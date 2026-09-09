using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Globalization;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed partial class AiAnalysisService
{
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromMinutes(5)
    };

    private const int NormalBatchSize = 30;
    private const int XHighBatchSize = 15;
    private const int MinBatchSize = 20;
    private const int MaxBatchSize = 50;
    private const int ConnectionTestTimeoutSeconds = 15;
    private const int ResponseOutputTokenBudget = 8_000;
    private const int ContextSafetyMarginTokens = 8_000;
    private const int MaxAgentInstructionChars = 32_000;
    private const int MaxEventDescriptionChars = 4_096;
    private const int MinEventDescriptionChars = 256;
    private const int StreamingIdleTimeoutSeconds = 90;
    private const int StreamingProgressIntervalSeconds = 5;

    // Known safe event IDs that can be skipped
    private static readonly HashSet<int> KnownSafeEventIds = new()
    {
        5156, // Windows Filtering Platform permitted connection (too common)
    };

    private readonly SettingsService _settingsService;
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly LruCache<string, CachedBatchAnalysis> _analysisCache = new(100);

    public AiAnalysisService(
        SettingsService settingsService,
        DiagnosticLogService diagnosticLogService)
    {
        _settingsService = settingsService;
        _diagnosticLogService = diagnosticLogService;
    }

    public async Task<(List<AuditIssue> Issues, int AnalyzedEventCount)> AnalyzeEventsAsync(
        List<SecurityEvent> events,
        IProgress<AuditProgressEventArgs>? progress = null,
        CancellationToken cancellationToken = default,
        Action<IReadOnlyList<string>>? modelsCompleted = null)
    {
        _settingsService.EnsureExtendedMode();
        cancellationToken.ThrowIfCancellationRequested();
        if (events.Count == 0)
        {
            return (new List<AuditIssue>(), 0);
        }

        progress?.Report(new(AuditStage.Route, AuditStepState.Active, "Selecting AI route..."));
        var routes = GetAnalysisRoutes();
        var mainTarget = routes.FirstOrDefault();
        if (mainTarget == null || string.IsNullOrWhiteSpace(mainTarget.BaseUrl))
        {
            throw new InvalidOperationException(AppText.Get("Configure the Main AI route before running an audit."));
        }

        progress?.Report(new(AuditStage.Route, AuditStepState.Done, "{0} / {1}", mainTarget.Name, mainTarget.Model));
        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Filtering events..."));

        // Apply smart filtering
        var filteredEvents = ApplySmartFiltering(events, out var filteredOut);
        _diagnosticLogService.Write($"Smart filtering: {events.Count} → {filteredEvents.Count} events ({filteredOut.Count} filtered)");

        if (filteredEvents.Count == 0)
        {
            progress?.Report(new(AuditStage.Analyze, AuditStepState.Skipped, "All events excluded by filtering."));
            return (new List<AuditIssue>(), 0);
        }

        // Calculate dynamic batch size
        int batchSize = CalculateDynamicBatchSize(filteredEvents, mainTarget.Effort ?? "medium",
            AiModelCatalog.ContextWindowTokens - ResponseOutputTokenBudget - ContextSafetyMarginTokens);

        int totalBatches = (int)Math.Ceiling(filteredEvents.Count / (double)batchSize);
        string systemPrompt = BuildSystemPrompt();
        int contextWindowTokens = GetContextWindowTokens(mainTarget.Model);
        int inputTokenBudget = Math.Max(
            1,
            contextWindowTokens - ResponseOutputTokenBudget - ContextSafetyMarginTokens);
        _diagnosticLogService.Write(
            $"AI analysis started: main={mainTarget.Name}, model={mainTarget.Model}, mode={mainTarget.Mode}, effort={mainTarget.Effort}, fallback={(routes.Count > 1 ? routes[1].Name : "empty")}, originalEvents={events.Count}, filteredEvents={filteredEvents.Count}, dynamicBatchSize={batchSize}, batches={totalBatches}, contextWindowTokens={contextWindowTokens}, inputTokenBudget={inputTokenBudget}");

        int maxParallel = Math.Clamp(_settingsService.Current.MaxConcurrentAnalysis, 1, 4);
        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "{0:N0} events / {1} parallel requests", filteredEvents.Count, maxParallel)
        { TotalBatches = totalBatches });
        var routeState = new AnalysisRouteState();
        if (maxParallel > 1)
        {
            var parallelIssues = await AnalyzeEventsParallelAsync(
                filteredEvents,
                routes,
                systemPrompt,
                inputTokenBudget,
                batchSize,
                maxParallel,
                routeState,
                progress,
                cancellationToken);
            var mergedParallelIssues = MergeDuplicateIssues(parallelIssues);
            _diagnosticLogService.Write(
                $"AI analysis completed: main={mainTarget.Name}, route={(routeState.UseFallback ? routes[^1].Name : mainTarget.Name)}, events={events.Count}, rawIssues={parallelIssues.Count}, issues={mergedParallelIssues.Count}");
            progress?.Report(new(AuditStage.Analyze, AuditStepState.Done, "{0} findings / English + Simplified Chinese", mergedParallelIssues.Count)
            { CompletedBatches = totalBatches, TotalBatches = totalBatches });
            modelsCompleted?.Invoke(routeState.Models.Keys.OrderBy(model => model, StringComparer.Ordinal).ToArray());
            return (mergedParallelIssues, filteredEvents.Count);
        }

        // Sequential processing (original)
        var allIssues = new List<AuditIssue>();
        for (int i = 0; i < filteredEvents.Count; i += batchSize)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var batch = filteredEvents.Skip(i).Take(batchSize).ToList();
            int currentBatch = (i / batchSize) + 1;
            progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Analyzing ({0}/{1}): connecting to AI endpoint...", currentBatch, totalBatches)
            { CompletedBatches = currentBatch - 1, TotalBatches = totalBatches });

            var stopwatch = Stopwatch.StartNew();
            try
            {
                var localIssues = await AnalyzeBatchWithCacheAsync(
                    routes,
                    batch,
                    systemPrompt,
                    inputTokenBudget,
                    routeState,
                    new AuditProgressReporter(value => progress?.Report(new(value.Stage, value.State, value.MessageKey, value.Arguments)
                    { BatchNumber = value.Stage == AuditStage.Analyze ? currentBatch : 0 })),
                    cancellationToken);
                var issues = RemapIssuesToIndexes(
                    localIssues,
                    Enumerable.Range(i, batch.Count).ToArray());
                allIssues.AddRange(issues);
                _diagnosticLogService.Write(
                    $"AI batch completed: batch={currentBatch}/{totalBatches}, events={batch.Count}, issues={issues.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Analyzing ({0}/{1}) complete: {2} issues found", currentBatch, totalBatches, issues.Count)
                { CompletedBatches = currentBatch, TotalBatches = totalBatches });
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException(
                    $"AI batch failed: batch={currentBatch}/{totalBatches}, events={batch.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}",
                    ex);
                throw;
            }
        }

        var mergedIssues = MergeDuplicateIssues(allIssues);
        _diagnosticLogService.Write(
            $"AI analysis completed: main={mainTarget.Name}, route={(routeState.UseFallback ? routes[^1].Name : mainTarget.Name)}, events={events.Count}, rawIssues={allIssues.Count}, issues={mergedIssues.Count}");
        progress?.Report(new(AuditStage.Analyze, AuditStepState.Done, "{0} findings / English + Simplified Chinese", mergedIssues.Count)
        { CompletedBatches = totalBatches, TotalBatches = totalBatches });
        modelsCompleted?.Invoke(routeState.Models.Keys.OrderBy(model => model, StringComparer.Ordinal).ToArray());
        return (mergedIssues, filteredEvents.Count);
    }

    public async Task<(bool Success, string Message)> TestConnectionAsync(AiTarget target)
    {
        _settingsService.EnsureExtendedMode();
        if (!Uri.TryCreate(target.BaseUrl?.Trim(), UriKind.Absolute, out var baseUri)
            || (baseUri.Scheme != Uri.UriSchemeHttps && baseUri.Scheme != Uri.UriSchemeHttp))
        {
            return (false, AppText.Get("Enter a valid HTTP or HTTPS endpoint."));
        }

        try
        {
            var stopwatch = Stopwatch.StartNew();
            _diagnosticLogService.Write(
                $"AI connection test started: target={target.Name}, host={baseUri.Host}");
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                BuildEndpoint(baseUri, "v1/models"));
            AddAuthorization(request, target.ApiKey);

            using var timeoutCts = new CancellationTokenSource(
                TimeSpan.FromSeconds(ConnectionTestTimeoutSeconds));
            using var response = await HttpClient.SendAsync(request, timeoutCts.Token);
            _diagnosticLogService.Write(
                $"AI connection test response: target={target.Name}, status={(int)response.StatusCode}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            if (response.IsSuccessStatusCode)
            {
                return (true, AppText.Format("Connection OK ({0}).", (int)response.StatusCode));
            }

            return (false, AppText.Format("API returned {0} ({1}).", (int)response.StatusCode, response.ReasonPhrase));
        }
        catch (HttpRequestException ex)
        {
            _diagnosticLogService.WriteException(
                $"AI connection test failed: target={target.Name}",
                ex);
            return (false, AppText.Format("Connection failed: {0}", FormatException(ex)));
        }
        catch (TaskCanceledException ex)
        {
            _diagnosticLogService.WriteException(
                $"AI connection test timed out: target={target.Name}",
                ex);
            return (false, AppText.Format("Connection timed out after {0} seconds: {1}", ConnectionTestTimeoutSeconds, FormatException(ex)));
        }
    }

    private async Task<List<AuditIssue>> AnalyzeBatchAsync(
        IReadOnlyList<AiTargetSettings> routes,
        List<SecurityEvent> events,
        string systemPrompt,
        int inputTokenBudget,
        AnalysisRouteState routeState,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        string eventSummary = BuildEventSummary(
            events,
            systemPrompt,
            inputTokenBudget,
            out int estimatedInputTokens,
            out int truncatedDescriptionCount,
            out int omittedEventCount);

        _diagnosticLogService.Write(
            $"AI request prepared: route={GetCurrentRouteName(routes, routeState)}, systemChars={systemPrompt.Length}, userChars={eventSummary.Length}, estimatedInputTokens={estimatedInputTokens}, truncatedDescriptions={truncatedDescriptionCount}, omittedEvents={omittedEventCount}");
        var response = await SendAnalysisRequestAsync(
            routes,
            systemPrompt,
            eventSummary,
            routeState,
            progress,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"The AI endpoint returned {(int)response.StatusCode} ({response.ReasonPhrase}).");
        }

        string messageContent = response.IsStreaming
            ? response.Text
            : ExtractMessageContent(response.Text, response.Mode);
        List<AuditIssue> issues;
        try
        {
            issues = ParseIssuesPayload(messageContent);
            if (issues.Any(issue => !issue.HasBilingualText))
            {
                throw new JsonException("Every finding must include complete English and Simplified Chinese analysis.");
            }
        }
        catch (JsonException ex)
        {
            _diagnosticLogService.WriteException(
                $"AI response did not match the findings contract: responseChars={messageContent.Length}",
                ex);
            throw new InvalidOperationException(AppText.Get("The AI response did not contain a valid findings result. Run the scan again."), ex);
        }

        routeState.Models.TryAdd(response.Model, 0);
        foreach (var issue in issues)
        {
            issue.AnalysisModel = response.Model;
            issue.OriginalAnalysisModel = response.Model;
        }
        return NormalizeIssues(issues, events);
    }

    private async Task<AnalysisResponsePayload> SendAnalysisRequestAsync(
        IReadOnlyList<AiTargetSettings> routes,
        string systemPrompt,
        string userPrompt,
        AnalysisRouteState routeState,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            bool usingFallback = routeState.UseFallback;
            var target = GetCurrentRoute(routes, routeState);

            try
            {
                var response = await SendAnalysisRequestToTargetAsync(
                    target,
                    systemPrompt,
                    userPrompt,
                    usingFallback ? 2 : routes.Count > 1 ? 1 : 2,
                    progress,
                    cancellationToken);
                if (response.IsSuccessStatusCode
                    || usingFallback
                    || routes.Count < 2
                    || !ShouldFailover(response.StatusCode))
                {
                    if (!usingFallback && routeState.UseFallback && !response.IsSuccessStatusCode)
                    {
                        continue;
                    }

                    return response;
                }

                SwitchToFallback(routes, routeState, target.Name,
                    $"API returned {response.StatusCode} ({response.ReasonPhrase})");
                progress?.Report(new(AuditStage.Route, AuditStepState.Done, "{0} unavailable; using {1}", target.Name, routes[1].Name));
            }
            catch (Exception ex) when (
                !cancellationToken.IsCancellationRequested
                && !usingFallback
                && routes.Count >= 2
                && IsFailoverException(ex))
            {
                SwitchToFallback(routes, routeState, target.Name, FormatException(ex));
                progress?.Report(new(AuditStage.Route, AuditStepState.Done, "{0} unavailable; using {1}", target.Name, routes[1].Name));
            }
        }
    }

    private async Task<AnalysisResponsePayload> SendAnalysisRequestToTargetAsync(
        AiTargetSettings target,
        string systemPrompt,
        string userPrompt,
        int maxRetries,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(target.BaseUrl?.Trim(), UriKind.Absolute, out var baseUri)
            || (baseUri.Scheme != Uri.UriSchemeHttps && baseUri.Scheme != Uri.UriSchemeHttp))
        {
            throw new InvalidOperationException("AI target endpoint is not a valid HTTP or HTTPS URL.");
        }

        bool useResponses = string.Equals(target.Mode, "responses", StringComparison.OrdinalIgnoreCase);
        object requestBody = useResponses
            ? new
            {
                model = target.Model,
                instructions = systemPrompt,
                input = userPrompt,
                reasoning = new { effort = target.Effort },
                max_output_tokens = ResponseOutputTokenBudget,
                store = false,
                stream = true
            }
            : new
            {
                model = target.Model,
                messages = new[]
                {
                    new { role = "system", content = systemPrompt },
                    new { role = "user", content = userPrompt }
                },
                temperature = 0.3,
                max_tokens = ResponseOutputTokenBudget,
                stream = true
            };

        string endpoint = useResponses ? "v1/responses" : "v1/chat/completions";
        _diagnosticLogService.Write(
            $"AI request dispatching: route={target.Name}, method=POST, endpoint={endpoint}, model={target.Model}, effort={target.Effort}");
        int attempt = 0;
        return await RetryAsync(
            $"POST {endpoint}, model={target.Model}, effort={target.Effort}",
            async () =>
        {
            attempt++;
            progress?.Report(attempt == 1
                ? new(AuditStage.Analyze, AuditStepState.Active, "Connecting to {0}", target.Name)
                : new(AuditStage.Analyze, AuditStepState.Active, "Retrying {0} ({1}/{2})", target.Name, attempt, maxRetries));
            var stopwatch = Stopwatch.StartNew();
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                BuildEndpoint(baseUri, endpoint));
            AddAuthorization(request, target.ApiKey);
            request.Content = new StringContent(
                JsonSerializer.Serialize(requestBody),
                Encoding.UTF8,
                "application/json");
            request.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue("text/event-stream"));
            request.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));

            string requestId = "unknown";
            using var requestTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            requestTimeoutCts.CancelAfter(HttpClient.Timeout);
            try
            {
                var sendTask = HttpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    requestTimeoutCts.Token);
                while (!sendTask.IsCompleted)
                {
                    try
                    {
                        await sendTask.WaitAsync(TimeSpan.FromSeconds(StreamingProgressIntervalSeconds));
                    }
                    catch (TimeoutException) when (!sendTask.IsFaulted)
                    {
                        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active,
                            "Waiting for {0} headers ({1:0}s)", target.Name, stopwatch.Elapsed.TotalSeconds));
                    }
                }

                using var response = await sendTask;
                if (response.Headers.TryGetValues("x-request-id", out var requestIds))
                {
                    requestId = GetSafeResponseIdentifier(requestIds.FirstOrDefault(), "req_");
                }
                _diagnosticLogService.Write(
                    $"AI request headers received: route={target.Name}, endpoint={endpoint}, status={(int)response.StatusCode}, requestId={requestId}, httpVersion={response.Version}, contentType={response.Content.Headers.ContentType?.MediaType ?? "unknown"}, elapsedMs={stopwatch.ElapsedMilliseconds}");
                string errorDetails = response.IsSuccessStatusCode
                    ? string.Empty
                    : await ReadHttpErrorDetailsAsync(response, requestTimeoutCts.Token);
                if ((int)response.StatusCode >= 500)
                {
                    int statusCode = (int)response.StatusCode;
                    string reasonPhrase = response.StatusCode.ToString();
                    throw new HttpRequestException(
                        $"The AI endpoint returned {statusCode} ({reasonPhrase}).{errorDetails}");
                }

                if (!response.IsSuccessStatusCode)
                {
                    return new AnalysisResponsePayload(
                        string.Empty,
                        false,
                        0,
                        (int)response.StatusCode,
                        response.StatusCode + errorDetails,
                        target.Mode);
                }

                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "{0} connected", target.Name));

                var payload = await ReadAnalysisResponseAsync(
                    response,
                    target.Mode,
                    target.Name,
                    progress,
                    requestTimeoutCts.Token);
                _diagnosticLogService.Write(
                    $"AI request response: endpoint={endpoint}, status={(int)response.StatusCode}, requestId={requestId}, streaming={payload.IsStreaming}, streamEvents={payload.StreamEventCount}, responseChars={payload.Text.Length}, elapsedMs={stopwatch.ElapsedMilliseconds}");
                return payload with { Model = target.Model };
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException(
                    $"AI request failed: route={target.Name}, endpoint={endpoint}, requestId={requestId}, callerCanceled={cancellationToken.IsCancellationRequested}, requestTimedOut={requestTimeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested}, elapsedMs={stopwatch.ElapsedMilliseconds}",
                    ex);
                cancellationToken.ThrowIfCancellationRequested();
                if (requestTimeoutCts.IsCancellationRequested || ex is OperationCanceledException)
                {
                    throw new TimeoutException(AppText.Format(
                        "The AI request timed out after {0} seconds.", HttpClient.Timeout.TotalSeconds), ex);
                }
                throw;
            }
        }, cancellationToken, maxRetries, progress, target.Name);
    }

    private static async Task<AnalysisResponsePayload> ReadAnalysisResponseAsync(
        HttpResponseMessage response,
        string mode,
        string routeName,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        bool isStreaming = string.Equals(
            response.Content.Headers.ContentType?.MediaType,
            "text/event-stream",
            StringComparison.OrdinalIgnoreCase);
        if (!isStreaming)
        {
            string text = await response.Content.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(text);
            ThrowIfResponseFailed(document.RootElement);
            if (string.Equals(mode, "responses", StringComparison.OrdinalIgnoreCase))
            {
                ExtractCompletedResponseText(document.RootElement);
            }
            progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Validating {0} response", routeName));
            return new AnalysisResponsePayload(
                text,
                false,
                0,
                (int)response.StatusCode,
                response.ReasonPhrase,
                mode);
        }

        var output = new StringBuilder();
        int streamEventCount = 0;
        bool receivedTerminalEvent = false;
        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(responseStream, Encoding.UTF8);
        var dataLines = new List<string>();
        string eventName = string.Empty;
        var streamStopwatch = Stopwatch.StartNew();
        var lastProgressReport = TimeSpan.Zero;

        while (true)
        {
            using var lineCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            lineCts.CancelAfter(TimeSpan.FromSeconds(StreamingIdleTimeoutSeconds));
            Task<string?> lineTask = reader.ReadLineAsync(lineCts.Token).AsTask();
            string? line;
            while (true)
            {
                try
                {
                    line = await lineTask.WaitAsync(
                        TimeSpan.FromSeconds(StreamingProgressIntervalSeconds), cancellationToken);
                    break;
                }
                catch (TimeoutException) when (!lineTask.IsFaulted)
                {
                    lastProgressReport = streamStopwatch.Elapsed;
                    progress?.Report(output.Length == 0
                        ? new(AuditStage.Analyze, AuditStepState.Active, "Waiting for {0} ({1:0}s)", routeName, streamStopwatch.Elapsed.TotalSeconds)
                        : new(AuditStage.Analyze, AuditStepState.Active, "{0}: {1:N0} characters ({2:0}s)", routeName, output.Length, streamStopwatch.Elapsed.TotalSeconds));
                }
                catch (Exception ex) when (lineCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException(
                        $"The AI streaming response was idle for more than {StreamingIdleTimeoutSeconds} seconds.", ex);
                }
            }

            if (line == null)
            {
                break;
            }

            if (line.Length == 0)
            {
                if (ProcessServerSentEvent(
                    dataLines,
                    eventName,
                    mode,
                    output,
                    ref streamEventCount,
                    ref receivedTerminalEvent))
                {
                    break;
                }

                dataLines.Clear();
                eventName = string.Empty;
                continue;
            }

            if (line.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
            {
                eventName = line[6..].Trim();
                continue;
            }

            if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            {
                string data = line[5..];
                dataLines.Add(data.StartsWith(' ') ? data[1..] : data);
            }

            if (streamEventCount > 0 && streamStopwatch.Elapsed - lastProgressReport >= TimeSpan.FromSeconds(1))
            {
                lastProgressReport = streamStopwatch.Elapsed;
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active,
                    "{0}: {1:N0} characters ({2:0}s)", routeName, output.Length, streamStopwatch.Elapsed.TotalSeconds));
            }
        }

        if (dataLines.Count > 0)
        {
            ProcessServerSentEvent(
                dataLines,
                eventName,
                mode,
                output,
                ref streamEventCount,
                ref receivedTerminalEvent);
        }

        if (string.Equals(mode, "responses", StringComparison.OrdinalIgnoreCase) && !receivedTerminalEvent)
        {
            throw new HttpRequestException(AppText.Get("The AI stream ended before response.completed was received. No result was saved."));
        }

        if (!HasCompleteJsonOutput(output.ToString()))
        {
            throw new HttpRequestException(
                "The AI streaming response ended before a complete findings result was received.");
        }

        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Validating {0} response", routeName));

        return new AnalysisResponsePayload(
            output.Length == 0 ? "{}" : output.ToString(),
            true,
            streamEventCount,
            (int)response.StatusCode,
            response.ReasonPhrase,
            mode);
    }

    private static bool ProcessServerSentEvent(
        List<string> dataLines,
        string eventName,
        string mode,
        StringBuilder output,
        ref int streamEventCount,
        ref bool receivedTerminalEvent)
    {
        if (dataLines.Count == 0)
        {
            ThrowIfResponseFailed(default, eventName);
            return false;
        }

        string data = string.Join("\n", dataLines).Trim();
        dataLines.Clear();
        if (string.IsNullOrWhiteSpace(data))
        {
            return false;
        }

        if (string.Equals(data, "[DONE]", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(mode, "responses", StringComparison.OrdinalIgnoreCase))
            {
                throw new HttpRequestException(AppText.Get("The AI stream ended before response.completed was received. No result was saved."));
            }
            receivedTerminalEvent = true;
            return true;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(data);
        }
        catch (JsonException ex)
        {
            throw new HttpRequestException(
                "The AI streaming response contained invalid JSON.",
                ex);
        }

        using (document)
        {
            streamEventCount++;
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new HttpRequestException("The AI streaming response contained an invalid event object.");
            }
            string eventType = TryGetString(root, "type", out var type) ? type : eventName;

            ThrowIfResponseFailed(root, eventType);

            if (string.Equals(mode, "responses", StringComparison.OrdinalIgnoreCase))
            {
                if (eventType.Equals("response.output_text.delta", StringComparison.OrdinalIgnoreCase)
                    && TryGetString(root, "delta", out var delta))
                {
                    output.Append(delta);
                    return false;
                }

                if (eventType.Equals("response.completed", StringComparison.OrdinalIgnoreCase))
                {
                    if (!root.TryGetProperty("response", out var completedResponse))
                    {
                        throw new HttpRequestException(AppText.Get("The AI endpoint did not return a completed Responses API object."));
                    }

                    // Text/item done events are not response completion. Only the
                    // final response snapshot is authoritative, including all parts.
                    string completedText = ExtractCompletedResponseText(completedResponse);
                    output.Clear();
                    output.Append(completedText);
                    receivedTerminalEvent = true;
                    return true;
                }

                return false;
            }

            if (root.TryGetProperty("choices", out var choices)
                && choices.ValueKind == JsonValueKind.Array
                && choices.GetArrayLength() > 0)
            {
                var choice = choices[0];
                if (choice.TryGetProperty("delta", out var deltaElement))
                {
                    AppendChatText(deltaElement, output, "content");
                }
                else if (choice.TryGetProperty("message", out var messageElement))
                {
                    AppendChatText(messageElement, output, "content");
                }
                else if (output.Length == 0 && choice.TryGetProperty("text", out var textElement))
                {
                    AppendTextValue(textElement, output);
                }

                if (choice.TryGetProperty("finish_reason", out var finishReason)
                    && finishReason.ValueKind != JsonValueKind.Null)
                {
                    if (!string.Equals(finishReason.GetString(), "stop", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new AiResponseException(AppText.Get("The AI endpoint returned an incomplete analysis. The scan has stopped."), false);
                    }

                    receivedTerminalEvent = true;
                    return true;
                }
            }

            return false;
        }
    }

    private static void ThrowIfResponseFailed(JsonElement root, string eventType = "")
    {
        var response = root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("response", out var nested)
            && nested.ValueKind == JsonValueKind.Object ? nested : root;
        string status = TryGetString(response, "status", out var value) ? value : string.Empty;
        string errorDetails = GetSafeResponseErrorDetails(root);
        if (eventType.Equals("response.cancelled", StringComparison.OrdinalIgnoreCase)
            || eventType.Equals("response.canceled", StringComparison.OrdinalIgnoreCase)
            || status.Equals("cancelled", StringComparison.OrdinalIgnoreCase)
            || status.Equals("canceled", StringComparison.OrdinalIgnoreCase))
        {
            throw new AiResponseException(AppText.Get("The AI endpoint cancelled the analysis. The scan has stopped.") + errorDetails, false);
        }

        if (eventType.Equals("response.incomplete", StringComparison.OrdinalIgnoreCase)
            || status.Equals("incomplete", StringComparison.OrdinalIgnoreCase))
        {
            bool tokenLimit = response.ValueKind == JsonValueKind.Object
                && response.TryGetProperty("incomplete_details", out var details)
                && TryGetString(details, "reason", out var reason)
                && reason == "max_output_tokens";
            throw new AiResponseException(AppText.Get(tokenLimit
                ? "The AI analysis reached its output token limit. Try a lower reasoning effort."
                : "The AI endpoint returned an incomplete analysis. The scan has stopped.") + errorDetails, false);
        }

        if (eventType.Equals("error", StringComparison.OrdinalIgnoreCase)
            || eventType.Equals("response.failed", StringComparison.OrdinalIgnoreCase)
            || status.Equals("failed", StringComparison.OrdinalIgnoreCase)
            || (response.ValueKind == JsonValueKind.Object && response.TryGetProperty("error", out var responseError)
                && responseError.ValueKind != JsonValueKind.Null)
            || (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("error", out var error)
                && error.ValueKind != JsonValueKind.Null))
        {
            // Provider error bodies can echo credentials or event data. Keep them out
            // of exceptions, which are displayed in the sidebar and diagnostic log.
            throw new AiResponseException(AppText.Get("The AI endpoint reported an analysis failure.") + errorDetails, true);
        }
    }

    private static string ExtractCompletedResponseText(JsonElement response)
    {
        ThrowIfResponseFailed(response);
        if (!TryGetString(response, "object", out var objectType) || objectType != "response"
            || !TryGetString(response, "status", out var status) || status != "completed"
            || !response.TryGetProperty("output", out var items) || items.ValueKind != JsonValueKind.Array)
        {
            throw new HttpRequestException(AppText.Get("The AI endpoint did not return a completed Responses API object."));
        }

        var text = new StringBuilder();
        foreach (var item in items.EnumerateArray())
        {
            if (!TryGetString(item, "type", out var type) || type != "message") continue;
            if (!TryGetString(item, "role", out var role) || role != "assistant"
                || !TryGetString(item, "status", out var itemStatus) || itemStatus != "completed"
                || !item.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array)
            {
                throw new HttpRequestException(AppText.Get("The AI endpoint did not return a completed Responses API object."));
            }

            foreach (var part in content.EnumerateArray())
            {
                if (!TryGetString(part, "type", out var partType)) continue;
                if (partType == "refusal")
                {
                    throw new AiResponseException(AppText.Get("The AI endpoint refused the analysis. No result was saved."), false);
                }
                if (partType == "output_text" && TryGetString(part, "text", out var value)) text.Append(value);
            }
        }

        if (text.Length == 0)
        {
            throw new HttpRequestException(AppText.Get("The completed AI response did not contain analysis text."));
        }
        return text.ToString();
    }

    private static string GetSafeResponseIdentifier(string? value, string prefix)
    {
        if (string.IsNullOrWhiteSpace(value)) return "unknown";
        if (Guid.TryParse(value, out var guid)) return guid.ToString("D");
        return value.Length is >= 20 and <= 133
            && value.StartsWith(prefix, StringComparison.Ordinal)
            && value[prefix.Length..].All(Uri.IsHexDigit) ? value : "unknown";
    }

    private static string GetSafeResponseErrorDetails(JsonElement root)
    {
        var response = root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("response", out var nested) && nested.ValueKind == JsonValueKind.Object ? nested : root;
        var error = response.ValueKind == JsonValueKind.Object && response.TryGetProperty("error", out var errorValue)
            && errorValue.ValueKind == JsonValueKind.Object ? errorValue : root;
        TryGetString(error, "code", out var code);
        // Error bodies can echo credentials or event text. Log only known codes
        // and standard-shaped opaque IDs, never provider messages or parameters.
        string safeCode = code switch
        {
            "server_error" or "rate_limit_exceeded" or "invalid_prompt" or "invalid_request_error"
                or "invalid_api_key" or "insufficient_quota" or "model_not_found" or "context_length_exceeded"
                or "content_filter" or "unsupported_value" or "invalid_value" or "missing_required_parameter"
                or "max_output_tokens" => code,
            _ => "unknown"
        };
        TryGetString(response, "id", out var responseId);
        return $" [code={safeCode}, responseId={GetSafeResponseIdentifier(responseId, "resp_")}]";
    }

    private static async Task<string> ReadHttpErrorDetailsAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            return string.Empty;
        using var detailsCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        detailsCts.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(detailsCts.Token);
            var buffer = new byte[16_384];
            int count = await stream.ReadAtLeastAsync(buffer, buffer.Length, false, detailsCts.Token);
            using var document = JsonDocument.Parse(buffer.AsMemory(0, count));
            return GetSafeResponseErrorDetails(document.RootElement);
        }
        catch (JsonException) { return string.Empty; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return string.Empty; }
        catch (IOException) when (!cancellationToken.IsCancellationRequested) { return string.Empty; }
    }

    private static void AppendChatText(JsonElement element, StringBuilder output, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var content))
        {
            return;
        }

        AppendTextValue(content, output);
    }

    private static void AppendTextValue(JsonElement element, StringBuilder output)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            output.Append(element.GetString());
            return;
        }

        if (element.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in element.EnumerateArray())
        {
            if (item.TryGetProperty("text", out var text))
            {
                AppendTextValue(text, output);
            }
        }
    }

    private static bool TryGetString(JsonElement element, string propertyName, out string value)
    {
        if (element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.String)
        {
            value = property.GetString() ?? string.Empty;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool HasCompleteJsonOutput(string text)
    {
        try
        {
            ParseIssuesPayload(text);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string BuildEventSummary(
        List<SecurityEvent> events,
        string systemPrompt,
        int inputTokenBudget,
        out int estimatedInputTokens,
        out int truncatedDescriptionCount,
        out int omittedEventCount)
    {
        const string userIntro =
            "Please analyze the following Windows security log events and identify potential security issues:\n\n";
        const string inputPrefix = "System instructions:\n";
        const string inputSeparator = "\n\nUser data:\n";
        var summary = new StringBuilder(userIntro);
        truncatedDescriptionCount = 0;
        omittedEventCount = 0;
        string contextPrefix = inputPrefix + systemPrompt + inputSeparator;
        int descriptionLimit = Math.Min(MaxEventDescriptionChars, Math.Max(
            MinEventDescriptionChars,
            inputTokenBudget * 2 / Math.Max(events.Count, 1)));

        int eventIndex = 0;
        foreach (var evt in events)
        {
            string description = CompactText(evt.Description ?? string.Empty);
            int eventDescriptionLimit = descriptionLimit;
            string compactDescription = TruncateText(description, eventDescriptionLimit);
            if (!string.Equals(compactDescription, description, StringComparison.Ordinal))
            {
                truncatedDescriptionCount++;
            }

            string eventText = FormatEvent(evt, compactDescription, $"event-{eventIndex++}");
            while (EstimateTokenCount(contextPrefix + summary + eventText)
                > inputTokenBudget
                && eventDescriptionLimit > MinEventDescriptionChars)
            {
                eventDescriptionLimit = Math.Max(MinEventDescriptionChars, eventDescriptionLimit / 2);
                compactDescription = TruncateText(description, eventDescriptionLimit);
                eventText = FormatEvent(evt, compactDescription, $"event-{eventIndex - 1}");
            }

            if (EstimateTokenCount(contextPrefix + summary + eventText)
                > inputTokenBudget)
            {
                eventText = FormatEvent(evt, "[Description omitted because the context budget was reached]", $"event-{eventIndex - 1}");
            }

            if (EstimateTokenCount(contextPrefix + summary + eventText) <= inputTokenBudget)
            {
                summary.Append(eventText);
            }
            else
            {
                omittedEventCount++;
            }
        }

        if (omittedEventCount > 0)
        {
            string omittedNote = $"[{omittedEventCount} event(s) omitted after the context budget was reached]\n\n";
            if (EstimateTokenCount(contextPrefix + summary + omittedNote) <= inputTokenBudget)
            {
                summary.Append(omittedNote);
            }
        }

        estimatedInputTokens = EstimateTokenCount(contextPrefix + summary);
        return summary.ToString();
    }

    private static string FormatEvent(SecurityEvent evt, string description, string eventRef)
    {
        var eventText = new StringBuilder();
        eventText.Append("- eventRef=");
        eventText.Append(eventRef);
        eventText.Append(" | timestamp=");
        eventText.Append(evt.Timestamp.ToUniversalTime().ToString("O"));
        eventText.Append(" | log=");
        eventText.Append(TruncateText(CompactText(evt.LogName), 128));
        eventText.Append(" | source=");
        eventText.Append(TruncateText(CompactText(evt.Source), 128));
        eventText.Append(" | eventId=");
        eventText.Append(evt.EventId);
        eventText.Append(" | level=");
        eventText.Append(TruncateText(CompactText(evt.Severity), 64));
        if (!string.IsNullOrWhiteSpace(evt.UserName))
        {
            eventText.Append(" | user=");
            eventText.Append(TruncateText(CompactText(evt.UserName), 256));
        }

        if (!string.IsNullOrWhiteSpace(evt.IpAddress))
        {
            eventText.Append(" | ip=");
            eventText.Append(TruncateText(CompactText(evt.IpAddress), 128));
        }

        eventText.Append("\n  description=");
        eventText.Append(description);
        eventText.Append("\n\n");
        return eventText.ToString();
    }

    private static int GetContextWindowTokens(string model)
    {
        return AiModelCatalog.ContextWindowTokens;
    }

    private static int EstimateTokenCount(string value)
    {
        // A tokenizer dependency would add no value for budgeting here. Using
        // UTF-8 bytes / 2 is intentionally conservative for mixed Windows log
        // text and keeps a safety margin below the provider's context limit.
        return Math.Max(1, (Encoding.UTF8.GetByteCount(value) + 1) / 2);
    }

    private static string CompactText(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var compact = new StringBuilder(value.Length);
        bool previousWasWhitespace = false;
        foreach (char character in value.Trim())
        {
            if (char.IsWhiteSpace(character))
            {
                if (!previousWasWhitespace)
                {
                    compact.Append(' ');
                }

                previousWasWhitespace = true;
                continue;
            }

            compact.Append(character);
            previousWasWhitespace = false;
        }

        return compact.ToString();
    }

    private static string TruncateText(string value, int maxChars)
    {
        if (maxChars <= 0 || value.Length <= maxChars)
        {
            return maxChars <= 0 ? string.Empty : value;
        }

        const string marker = " ...[truncated]... ";
        if (maxChars <= marker.Length)
        {
            return value[..maxChars];
        }

        int remaining = maxChars - marker.Length;
        int headLength = Math.Max(1, remaining * 3 / 4);
        int tailLength = remaining - headLength;
        return value[..headLength] + marker + value[^tailLength..];
    }

    private static void AddAuthorization(HttpRequestMessage request, string? apiKey)
    {
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey.Trim());
        }
    }

    private static Uri BuildEndpoint(Uri baseUri, string relativePath)
    {
        string basePath = baseUri.AbsolutePath.TrimEnd('/');
        string path = relativePath.TrimStart('/');
        if (basePath.EndsWith("/v1", StringComparison.OrdinalIgnoreCase) && path.StartsWith("v1/", StringComparison.Ordinal))
            path = path[3..];
        return new UriBuilder(baseUri) { Path = $"{basePath}/{path}", Query = string.Empty, Fragment = string.Empty }.Uri;
    }

    private static string ExtractMessageContent(string responseJson, string mode)
    {
        using var document = JsonDocument.Parse(responseJson);
        var root = document.RootElement;
        ThrowIfResponseFailed(root);

        if (string.Equals(mode, "responses", StringComparison.OrdinalIgnoreCase))
        {
            return ExtractCompletedResponseText(root);
        }

        if (root.TryGetProperty("choices", out var choices)
            && choices.ValueKind == JsonValueKind.Array
            && choices.GetArrayLength() > 0)
        {
            var message = choices[0].GetProperty("message");
            if (message.TryGetProperty("content", out var content)
                && content.ValueKind == JsonValueKind.String)
            {
                return content.GetString() ?? "{}";
            }
        }

        return "{}";
    }

    private async Task<AnalysisResponsePayload> RetryAsync(
        string operation,
        Func<Task<AnalysisResponsePayload>> action,
        CancellationToken cancellationToken,
        int maxRetries,
        IProgress<AuditProgressEventArgs>? progress,
        string routeName)
    {
        Exception? lastError = null;

        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                _diagnosticLogService.Write(
                    $"AI request attempt started: attempt={attempt + 1}/{maxRetries}, operation={operation}");
                return await action();
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested
                && ex is HttpRequestException or IOException
                && ex is not AiResponseException)
            {
                lastError = ex;
                _diagnosticLogService.WriteException(
                    $"AI request attempt failed: attempt={attempt + 1}/{maxRetries}, operation={operation}",
                    ex);
                if (attempt >= maxRetries - 1)
                {
                    break;
                }

                double delaySeconds = Math.Pow(2, attempt);
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active,
                    "{0} interrupted; retry in {1:0}s ({2}/{3})", routeName, delaySeconds, attempt + 2, maxRetries));
                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        throw new HttpRequestException(
            $"The AI endpoint request failed after {maxRetries} attempts. Last error: {FormatException(lastError ?? new HttpRequestException("Unknown transport error."))}",
            lastError);
    }

    private int CalculateDynamicBatchSize(List<SecurityEvent> events, string effort, int inputTokenBudget)
    {
        if (events.Count == 0)
            return NormalBatchSize;

        // Calculate average event complexity from first 50 events
        int sampleSize = Math.Min(50, events.Count);
        int totalChars = events.Take(sampleSize).Sum(e =>
            (e.Description?.Length ?? 0) +
            (e.LogName?.Length ?? 0) +
            (e.Source?.Length ?? 0));
        int avgEventChars = totalChars / sampleSize;

        // Estimate events that fit in budget (rough: 1 token ≈ 2 chars)
        int estimatedEventsPerBatch = inputTokenBudget * 2 / Math.Max(avgEventChars, 100);

        // Apply effort-based multiplier
        double effortMultiplier = effort?.ToLowerInvariant() switch
        {
            "max" => 0.2,
            "xhigh" => 0.4,
            "high" => 0.6,
            "medium" => 1.0,
            _ => 1.0
        };

        int dynamicBatch = (int)(estimatedEventsPerBatch * effortMultiplier);

        // Clamp to reasonable bounds
        return Math.Clamp(dynamicBatch, MinBatchSize, MaxBatchSize);
    }

    private List<SecurityEvent> ApplySmartFiltering(List<SecurityEvent> events, out List<SecurityEvent> filteredOut)
    {
        filteredOut = new List<SecurityEvent>();

        if (!_settingsService.Current.EnableSmartFiltering)
        {
            return events;
        }

        var toAnalyze = new List<SecurityEvent>();

        // Filter out known safe events
        var safeEvents = events.Where(e => KnownSafeEventIds.Contains(e.EventId)
            && string.Equals(e.LogName, "Security", StringComparison.OrdinalIgnoreCase)).ToList();
        filteredOut.AddRange(safeEvents);
        var remaining = events.Except(safeEvents).ToList();

        // Group by severity
        var severityGroups = remaining
            .GroupBy(e => e.Severity?.ToLowerInvariant() ?? "unknown")
            .ToList();

        foreach (var group in severityGroups)
        {
            var severity = group.Key;
            var groupEvents = group.ToList();

            if (severity.Contains("critical") || severity.Contains("error"))
            {
                // Analyze ALL critical/error events
                toAnalyze.AddRange(groupEvents);
            }
            else if (severity.Contains("warning"))
            {
                toAnalyze.AddRange(SelectRepresentativeEvents(groupEvents, 3));
            }
            else if (severity.Contains("information"))
            {
                toAnalyze.AddRange(SelectRepresentativeEvents(groupEvents, 1));
            }
            else
            {
                toAnalyze.AddRange(groupEvents);
            }
        }

        filteredOut = events.Except(toAnalyze).ToList();
        return toAnalyze.OrderByDescending(evt => evt.Severity?.ToLowerInvariant() switch
        {
            "critical" => 3,
            "error" => 2,
            "warning" => 1,
            _ => 0
        }).ThenByDescending(evt => evt.Timestamp).ToList();
    }

    private static IEnumerable<SecurityEvent> SelectRepresentativeEvents(List<SecurityEvent> events, int samplesPerPattern)
    {
        // Only sample identical evidence. A rare event or a different account, address,
        // message or event field must not disappear because its severity is informational.
        return events
            .GroupBy(evt => (evt.EventId, evt.LogName, evt.Source, evt.UserName,
                evt.IpAddress, evt.Description, evt.AdditionalData))
            .SelectMany(group => group.OrderByDescending(evt => evt.Timestamp).Take(samplesPerPattern));
    }

    private string CalculateBatchCacheKey(
        IReadOnlyList<SecurityEvent> events,
        string systemPrompt,
        AiTargetSettings target)
    {
        // Cached findings contain exact timestamps, records and evidence, so key the
        // entire ordered batch rather than a sample of each event's description.
        byte[] signature = JsonSerializer.SerializeToUtf8Bytes(new
        {
            systemPrompt,
            target.BaseUrl,
            target.Model,
            target.Mode,
            target.Effort,
            events
        });

        return Convert.ToBase64String(SHA256.HashData(signature));
    }

    private IReadOnlyList<AiTargetSettings> GetAnalysisRoutes()
    {
        var configured = _settingsService.Current.AiTargets ?? new List<AiTargetSettings>();
        var main = configured.FirstOrDefault(target =>
            string.Equals(target.Name, AiTargetSettings.MainName, StringComparison.OrdinalIgnoreCase))
            ?? configured.FirstOrDefault();
        if (main == null)
        {
            return Array.Empty<AiTargetSettings>();
        }

        var routes = new List<AiTargetSettings> { main };
        var fallback = configured.FirstOrDefault(target =>
            !ReferenceEquals(target, main)
            && string.Equals(target.Name, AiTargetSettings.FallbackName, StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(target.BaseUrl));
        if (fallback != null)
        {
            routes.Add(fallback);
        }

        return routes;
    }

    private static AiTargetSettings GetCurrentRoute(
        IReadOnlyList<AiTargetSettings> routes,
        AnalysisRouteState routeState)
    {
        if (routes.Count == 0)
        {
            throw new InvalidOperationException(AppText.Get("Configure the Main AI route before running an audit."));
        }

        return routeState.UseFallback && routes.Count > 1 ? routes[1] : routes[0];
    }

    private static string GetCurrentRouteName(
        IReadOnlyList<AiTargetSettings> routes,
        AnalysisRouteState routeState) => GetCurrentRoute(routes, routeState).Name;

    private void SwitchToFallback(
        IReadOnlyList<AiTargetSettings> routes,
        AnalysisRouteState routeState,
        string failedRoute,
        string reason)
    {
        if (routes.Count < 2)
        {
            return;
        }

        routeState.EnableFallback();
        _diagnosticLogService.Write(
            $"AI route failover: from={failedRoute}, to={routes[1].Name}, reason={reason}");
    }

    private static bool ShouldFailover(int statusCode) => statusCode >= 500 || statusCode is 404 or 408 or 429;

    private static bool IsFailoverException(Exception exception) => exception is AiResponseException responseError
        ? responseError.AllowFailover
        : exception is HttpRequestException or IOException or TimeoutException or TaskCanceledException or OperationCanceledException or InvalidOperationException;

    private async Task<List<AuditIssue>> AnalyzeEventsParallelAsync(
        List<SecurityEvent> events,
        IReadOnlyList<AiTargetSettings> routes,
        string systemPrompt,
        int inputTokenBudget,
        int batchSize,
        int maxParallel,
        AnalysisRouteState routeState,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        var batches = new List<List<SecurityEvent>>();
        for (int i = 0; i < events.Count; i += batchSize)
        {
            batches.Add(events.Skip(i).Take(batchSize).ToList());
        }

        var allIssues = new ConcurrentBag<AuditIssue>();
        int completedBatches = 0;
        using var semaphore = new SemaphoreSlim(maxParallel);
        using var batchCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        ExceptionDispatchInfo? firstFailure = null;

        var tasks = batches.Select(async (batch, index) =>
        {
            await semaphore.WaitAsync(batchCts.Token);
            try
            {
                var localIssues = await AnalyzeBatchWithCacheAsync(
                    routes,
                    batch,
                    systemPrompt,
                    inputTokenBudget,
                    routeState,
                    new AuditProgressReporter(value => progress?.Report(new(value.Stage, value.State, value.MessageKey, value.Arguments)
                    { BatchNumber = value.Stage == AuditStage.Analyze ? index + 1 : 0 })),
                    batchCts.Token);
                var issues = RemapIssuesToIndexes(
                    localIssues,
                    Enumerable.Range(index * batchSize, batch.Count).ToArray());

                foreach (var issue in issues)
                {
                    allIssues.Add(issue);
                }

                int completed = Interlocked.Increment(ref completedBatches);
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Analyzing ({0}/{1})... {2} issues found", completed, batches.Count, allIssues.Count)
                { CompletedBatches = completed, TotalBatches = batches.Count });
            }
            catch (Exception ex) when (!batchCts.IsCancellationRequested)
            {
                Interlocked.CompareExchange(ref firstFailure, ExceptionDispatchInfo.Capture(ex), null);
                batchCts.Cancel();
                throw;
            }
            finally
            {
                semaphore.Release();
            }
        });

        try
        {
            await Task.WhenAll(tasks);
        }
        catch
        {
            cancellationToken.ThrowIfCancellationRequested();
            firstFailure?.Throw();
            throw;
        }
        return allIssues.ToList();
    }

    private async Task<List<AuditIssue>> AnalyzeBatchWithCacheAsync(
        IReadOnlyList<AiTargetSettings> routes,
        List<SecurityEvent> events,
        string systemPrompt,
        int inputTokenBudget,
        AnalysisRouteState routeState,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        if (!_settingsService.Current.EnableCaching)
        {
            return await AnalyzeBatchAsync(routes, events, systemPrompt, inputTokenBudget, routeState, progress, cancellationToken);
        }

        var currentTarget = GetCurrentRoute(routes, routeState);
        string cacheKey = CalculateBatchCacheKey(events, systemPrompt, currentTarget);

        if (_analysisCache.TryGet(cacheKey, out var cached))
        {
            routeState.Models.TryAdd(currentTarget.Model, 0);
            _diagnosticLogService.Write($"Cache hit: batch events={events.Count}, issues={cached.Issues.Count}");
            return cached.Issues.Select(CloneIssue).ToList();
        }

        var issues = await AnalyzeBatchAsync(
            routes,
            events,
            systemPrompt,
            inputTokenBudget,
            routeState,
            progress,
            cancellationToken);

        // Cache only primary-route results. A fallback response must not be silently reused
        // when the primary endpoint becomes healthy again.
        if (!routeState.UseFallback)
        {
            _analysisCache.Set(cacheKey, new CachedBatchAnalysis
            {
                Issues = issues.Select(CloneIssue).ToList()
            });
        }

        return issues;
    }

    public void ClearCache()
    {
        _analysisCache.Clear();
        _diagnosticLogService.Write("Analysis cache cleared");
    }

    private static List<AuditIssue> RemapIssuesToIndexes(
        IEnumerable<AuditIssue> issues,
        IReadOnlyList<int> originalIndexes)
    {
        return issues.Select(issue =>
        {
            var copy = CloneIssue(issue);
            copy.EventRef = RemapLocalEventRef(copy.EventRef, originalIndexes);
            copy.RelatedEventRefs = copy.RelatedEventRefs
                .Select(reference => RemapLocalEventRef(reference, originalIndexes))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return copy;
        }).ToList();
    }

    private static string RemapLocalEventRef(
        string reference,
        IReadOnlyList<int> originalIndexes)
    {
        if (!reference.StartsWith("event-", StringComparison.OrdinalIgnoreCase)
            || !int.TryParse(reference[6..], out int localIndex)
            || localIndex < 0
            || localIndex >= originalIndexes.Count)
        {
            return reference;
        }

        return $"event-{originalIndexes[localIndex]}";
    }

    private static AuditIssue CloneIssue(AuditIssue issue) => new()
    {
        Key = issue.Key,
        EventRef = issue.EventRef,
        EventId = issue.EventId,
        EventTimestamp = issue.EventTimestamp,
        Source = issue.Source,
        LogName = issue.LogName,
        EventRecordId = issue.EventRecordId,
        EventDescription = issue.EventDescription,
        EventAdditionalData = issue.EventAdditionalData,
        UserName = issue.UserName,
        IpAddress = issue.IpAddress,
        FirstSeenUtc = issue.FirstSeenUtc,
        LastSeenUtc = issue.LastSeenUtc,
        SupportingEventCount = issue.SupportingEventCount,
        EventTimes = new Dictionary<string, DateTime>(issue.EventTimes),
        Title = issue.Title,
        Description = issue.Description,
        Severity = issue.Severity,
        Confidence = issue.Confidence,
        Category = issue.Category,
        Affected = issue.Affected,
        RootCause = issue.RootCause,
        Recommendation = issue.Recommendation,
        TitleZh = issue.TitleZh,
        DescriptionZh = issue.DescriptionZh,
        RootCauseZh = issue.RootCauseZh,
        RecommendationZh = issue.RecommendationZh,
        AnalysisModel = issue.AnalysisModel,
        OriginalAnalysisModel = issue.OriginalAnalysisModel,
        OptimizedAtUtc = issue.OptimizedAtUtc,
        Occurrences = issue.Occurrences,
        RelatedEventRefs = issue.RelatedEventRefs.ToList(),
        DetectedAt = issue.DetectedAt
    };


    private static string FormatException(Exception exception)
    {
        var messages = new List<string>();
        for (var current = exception; current != null; current = current.InnerException)
        {
            if (!string.IsNullOrWhiteSpace(current.Message))
            {
                messages.Add(current.Message);
            }
        }

        return string.Join(" Inner: ", messages);
    }

    private sealed record AnalysisResponsePayload(
        string Text,
        bool IsStreaming,
        int StreamEventCount,
        int StatusCode,
        string? ReasonPhrase,
        string Mode)
    {
        public bool IsSuccessStatusCode => StatusCode is >= 200 and <= 299;
        public string Model { get; init; } = string.Empty;
    }

    private sealed class AiResponseException : HttpRequestException
    {
        public bool AllowFailover { get; }

        public AiResponseException(string message, bool allowFailover) : base(message)
        {
            AllowFailover = allowFailover;
        }
    }

    private sealed class AnalysisRouteState
    {
        private int _useFallback;
        public ConcurrentDictionary<string, byte> Models { get; } = new(StringComparer.OrdinalIgnoreCase);

        public bool UseFallback => Volatile.Read(ref _useFallback) == 1;

        public void EnableFallback() => Interlocked.Exchange(ref _useFallback, 1);
    }

    private sealed class CachedBatchAnalysis
    {
        public List<AuditIssue> Issues { get; init; } = new();
    }
}
