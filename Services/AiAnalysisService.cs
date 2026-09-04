using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed class AiAnalysisService
{
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromMinutes(5)
    };

    private const int NormalBatchSize = 30;
    private const int XHighBatchSize = 15;
    private const int MaxBatchSize = 5;
    private const int ConnectionTestTimeoutSeconds = 15;
    private const int LunaContextWindowTokens = 256_000;
    private const int ResponseOutputTokenBudget = 2_000;
    private const int ContextSafetyMarginTokens = 8_000;
    private const int MaxAgentInstructionChars = 32_000;
    private const int MaxEventDescriptionChars = 4_096;
    private const int MinEventDescriptionChars = 256;

    // Known safe event IDs that can be skipped
    private static readonly HashSet<int> KnownSafeEventIds = new()
    {
        5156, // Windows Filtering Platform permitted connection (too common)
    };

    private readonly SettingsService _settingsService;
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly LruCache<string, List<AuditIssue>> _analysisCache = new(500);

    public AiAnalysisService(
        SettingsService settingsService,
        DiagnosticLogService diagnosticLogService)
    {
        _settingsService = settingsService;
        _diagnosticLogService = diagnosticLogService;
    }

    public async Task<List<AuditIssue>> AnalyzeEventsAsync(
        List<SecurityEvent> events,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (events.Count == 0)
        {
            return new List<AuditIssue>();
        }

        var target = _settingsService.Current.AiTargets.FirstOrDefault(item => item.IsActive)
            ?? _settingsService.Current.AiTargets.FirstOrDefault();
        if (target == null || string.IsNullOrWhiteSpace(target.BaseUrl))
        {
            throw new InvalidOperationException("Configure an AI target before running an audit.");
        }

        progress?.Report("Filtering events...");

        // Apply smart filtering
        var filteredEvents = ApplySmartFiltering(events, out var filteredOut);
        _diagnosticLogService.Write($"Smart filtering: {events.Count} → {filteredEvents.Count} events ({filteredOut.Count} filtered)");

        progress?.Report("Connecting to AI endpoint...");

        // Calculate dynamic batch size
        int batchSize = CalculateDynamicBatchSize(filteredEvents, target.Effort ?? "medium",
            LunaContextWindowTokens - ResponseOutputTokenBudget - ContextSafetyMarginTokens);

        int totalBatches = (int)Math.Ceiling(filteredEvents.Count / (double)batchSize);
        string systemPrompt = BuildSystemPrompt();
        int contextWindowTokens = GetContextWindowTokens(target.Model);
        int inputTokenBudget = Math.Max(
            1,
            contextWindowTokens - ResponseOutputTokenBudget - ContextSafetyMarginTokens);
        _diagnosticLogService.Write(
            $"AI analysis started: target={target.Name}, model={target.Model}, mode={target.Mode}, effort={target.Effort}, originalEvents={events.Count}, filteredEvents={filteredEvents.Count}, dynamicBatchSize={batchSize}, batches={totalBatches}, contextWindowTokens={contextWindowTokens}, inputTokenBudget={inputTokenBudget}");

        // Check for parallel processing setting
        int maxParallel = _settingsService.Current.MaxConcurrentAnalysis;
        if (maxParallel > 1)
        {
            return await AnalyzeEventsParallelAsync(
                filteredEvents,
                target,
                systemPrompt,
                inputTokenBudget,
                batchSize,
                maxParallel,
                progress,
                cancellationToken);
        }

        // Sequential processing (original)
        var allIssues = new List<AuditIssue>();
        for (int i = 0; i < filteredEvents.Count; i += batchSize)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var batch = filteredEvents.Skip(i).Take(batchSize).ToList();
            int currentBatch = (i / batchSize) + 1;
            progress?.Report($"Analyzing ({currentBatch}/{totalBatches})...");

            var stopwatch = Stopwatch.StartNew();
            try
            {
                var issues = await AnalyzeBatchAsync(
                    target,
                    batch,
                    systemPrompt,
                    inputTokenBudget,
                    cancellationToken);
                allIssues.AddRange(issues);
                _diagnosticLogService.Write(
                    $"AI batch completed: batch={currentBatch}/{totalBatches}, events={batch.Count}, issues={issues.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException(
                    $"AI batch failed: batch={currentBatch}/{totalBatches}, events={batch.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}",
                    ex);
                throw;
            }
        }

        _diagnosticLogService.Write(
            $"AI analysis completed: target={target.Name}, events={events.Count}, issues={allIssues.Count}");
        progress?.Report("Complete");
        return allIssues;
    }

    public async Task<(bool Success, string Message)> TestConnectionAsync(AiTarget target)
    {
        if (!Uri.TryCreate(target.BaseUrl?.Trim(), UriKind.Absolute, out var baseUri)
            || (baseUri.Scheme != Uri.UriSchemeHttps && baseUri.Scheme != Uri.UriSchemeHttp))
        {
            return (false, "Enter a valid HTTP or HTTPS endpoint.");
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
                return (true, $"Connection OK ({(int)response.StatusCode}).");
            }

            return (false, $"API returned {(int)response.StatusCode} ({response.ReasonPhrase}).");
        }
        catch (HttpRequestException ex)
        {
            _diagnosticLogService.WriteException(
                $"AI connection test failed: target={target.Name}",
                ex);
            return (false, $"Connection failed: {FormatException(ex)}");
        }
        catch (TaskCanceledException ex)
        {
            _diagnosticLogService.WriteException(
                $"AI connection test timed out: target={target.Name}",
                ex);
            return (false, $"Connection timed out after {ConnectionTestTimeoutSeconds} seconds: {FormatException(ex)}");
        }
    }

    private async Task<List<AuditIssue>> AnalyzeBatchAsync(
        AiTargetSettings target,
        List<SecurityEvent> events,
        string systemPrompt,
        int inputTokenBudget,
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
            $"AI request prepared: target={target.Name}, systemChars={systemPrompt.Length}, userChars={eventSummary.Length}, estimatedInputTokens={estimatedInputTokens}, truncatedDescriptions={truncatedDescriptionCount}, omittedEvents={omittedEventCount}");
        var response = await SendAnalysisRequestAsync(
            target,
            systemPrompt,
            eventSummary,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"The AI endpoint returned {(int)response.StatusCode} ({response.ReasonPhrase}).");
        }

        string messageContent = response.IsStreaming
            ? response.Text
            : ExtractMessageContent(response.Text, target.Mode);
        IssuesResponse? issuesResponse;
        try
        {
            issuesResponse = JsonSerializer.Deserialize<IssuesResponse>(
                messageContent,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (JsonException ex)
        {
            throw new HttpRequestException(
                "The AI endpoint returned invalid JSON in the analysis response.",
                ex);
        }

        if (issuesResponse?.Issues == null)
        {
            return new List<AuditIssue>();
        }

        foreach (var issue in issuesResponse.Issues)
        {
            issue.DetectedAt = DateTime.UtcNow;
        }

        return issuesResponse.Issues;
    }

    private async Task<AnalysisResponsePayload> SendAnalysisRequestAsync(
        AiTargetSettings target,
        string systemPrompt,
        string userPrompt,
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
                input = $"System instructions:\n{systemPrompt}\n\nUser data:\n{userPrompt}",
                reasoning = new { effort = target.Effort },
                max_output_tokens = ResponseOutputTokenBudget,
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
            $"AI request dispatching: method=POST, endpoint={endpoint}, model={target.Model}, effort={target.Effort}");
        return await RetryAsync(
            $"POST {endpoint}, model={target.Model}, effort={target.Effort}",
            async () =>
        {
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

            try
            {
                using var requestTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                requestTimeoutCts.CancelAfter(HttpClient.Timeout);
                using var response = await HttpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    requestTimeoutCts.Token);
                _diagnosticLogService.Write(
                    $"AI request headers received: endpoint={endpoint}, status={(int)response.StatusCode}, contentType={response.Content.Headers.ContentType?.MediaType ?? "unknown"}, elapsedMs={stopwatch.ElapsedMilliseconds}");
                if ((int)response.StatusCode >= 500)
                {
                    int statusCode = (int)response.StatusCode;
                    string? reasonPhrase = response.ReasonPhrase;
                    throw new HttpRequestException(
                        $"The AI endpoint returned {statusCode} ({reasonPhrase}).");
                }

                if (!response.IsSuccessStatusCode)
                {
                    return new AnalysisResponsePayload(
                        string.Empty,
                        false,
                        0,
                        (int)response.StatusCode,
                        response.ReasonPhrase);
                }

                var payload = await ReadAnalysisResponseAsync(
                    response,
                    target.Mode,
                    requestTimeoutCts.Token);
                _diagnosticLogService.Write(
                    $"AI request response: endpoint={endpoint}, status={(int)response.StatusCode}, streaming={payload.IsStreaming}, streamEvents={payload.StreamEventCount}, responseChars={payload.Text.Length}, elapsedMs={stopwatch.ElapsedMilliseconds}");
                return payload;
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException(
                    $"AI request transport failed: endpoint={endpoint}, elapsedMs={stopwatch.ElapsedMilliseconds}",
                    ex);
                throw;
            }
        }, cancellationToken);
    }

    private static async Task<AnalysisResponsePayload> ReadAnalysisResponseAsync(
        HttpResponseMessage response,
        string mode,
        CancellationToken cancellationToken)
    {
        bool isStreaming = string.Equals(
            response.Content.Headers.ContentType?.MediaType,
            "text/event-stream",
            StringComparison.OrdinalIgnoreCase);
        if (!isStreaming)
        {
            return new AnalysisResponsePayload(
                await response.Content.ReadAsStringAsync(cancellationToken),
                false,
                0,
                (int)response.StatusCode,
                response.ReasonPhrase);
        }

        var output = new StringBuilder();
        int streamEventCount = 0;
        bool receivedTerminalEvent = false;
        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(responseStream, Encoding.UTF8);
        var dataLines = new List<string>();
        string eventName = string.Empty;

        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
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

        if (!receivedTerminalEvent)
        {
            throw new HttpRequestException(
                "The AI streaming response ended before a terminal event was received.");
        }

        return new AnalysisResponsePayload(
            output.Length == 0 ? "{}" : output.ToString(),
            true,
            streamEventCount,
            (int)response.StatusCode,
            response.ReasonPhrase);
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
            string eventType = root.TryGetProperty("type", out var type)
                && type.ValueKind == JsonValueKind.String
                ? type.GetString() ?? string.Empty
                : eventName;

            if (eventType.Equals("error", StringComparison.OrdinalIgnoreCase)
                || eventType.EndsWith(".failed", StringComparison.OrdinalIgnoreCase))
            {
                string errorMessage = root.TryGetProperty("error", out var error)
                    ? error.ToString()
                    : "The AI streaming response reported a failure.";
                throw new HttpRequestException(errorMessage);
            }

            if (string.Equals(mode, "responses", StringComparison.OrdinalIgnoreCase))
            {
                if (eventType.Equals("response.output_text.delta", StringComparison.OrdinalIgnoreCase)
                    && TryGetString(root, "delta", out var delta))
                {
                    output.Append(delta);
                    return false;
                }

                if (eventType.Equals("response.output_text.done", StringComparison.OrdinalIgnoreCase)
                    && output.Length == 0
                    && TryGetString(root, "text", out var completedText))
                {
                    output.Append(completedText);
                }

                if (output.Length == 0 && TryGetString(root, "output_text", out var outputText))
                {
                    output.Append(outputText);
                }

                if (eventType.Equals("response.completed", StringComparison.OrdinalIgnoreCase))
                {
                    if (output.Length == 0
                        && root.TryGetProperty("response", out var completedResponse))
                    {
                        string completedContent = ExtractMessageContent(
                            completedResponse.GetRawText(),
                            "responses");
                        if (!string.Equals(completedContent, "{}", StringComparison.Ordinal))
                        {
                            output.Append(completedContent);
                        }
                    }

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
                    receivedTerminalEvent = true;
                    return true;
                }
            }

            return false;
        }
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
        if (element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.String)
        {
            value = property.GetString() ?? string.Empty;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private string BuildSystemPrompt()
    {
        string agentInstructions = CompactText(_settingsService.Current.AgentInstructions ?? string.Empty);
        agentInstructions = TruncateText(agentInstructions, MaxAgentInstructionChars);

        return """
            You are a Windows security audit expert. Analyze the provided event logs and identify:
            1. Abnormal login patterns
            2. Privilege escalation risks
            3. Firewall anomalies
            4. System stability issues
            5. Application, process, or program issues
            6. Network activity and connectivity issues

            Additional audit policy supplied by the user:
            """ + agentInstructions + """

            Return only JSON in this shape:
            {
              "issues": [
                {
                  "description": "Brief description",
                  "severity": "High|Medium|Low",
                  "category": "Login|Privilege|Firewall|System|Application|Network|Other",
                  "rootCause": "Root cause analysis",
                  "recommendation": "Recommended solution"
                }
              ]
            }
            """;
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

        foreach (var evt in events)
        {
            string description = CompactText(evt.Description ?? string.Empty);
            int eventDescriptionLimit = descriptionLimit;
            string compactDescription = TruncateText(description, eventDescriptionLimit);
            if (!string.Equals(compactDescription, description, StringComparison.Ordinal))
            {
                truncatedDescriptionCount++;
            }

            string eventText = FormatEvent(evt, compactDescription);
            while (EstimateTokenCount(contextPrefix + summary + eventText)
                > inputTokenBudget
                && eventDescriptionLimit > MinEventDescriptionChars)
            {
                eventDescriptionLimit = Math.Max(MinEventDescriptionChars, eventDescriptionLimit / 2);
                compactDescription = TruncateText(description, eventDescriptionLimit);
                eventText = FormatEvent(evt, compactDescription);
            }

            if (EstimateTokenCount(contextPrefix + summary + eventText)
                > inputTokenBudget)
            {
                eventText = FormatEvent(evt, "[Description omitted because the context budget was reached]");
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

    private static string FormatEvent(SecurityEvent evt, string description)
    {
        var eventText = new StringBuilder();
        eventText.Append("- [");
        eventText.Append(evt.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
        eventText.Append("] ");
        eventText.Append(TruncateText(CompactText(evt.LogName), 128));
        eventText.Append(" | source=");
        eventText.Append(TruncateText(CompactText(evt.Source), 128));
        eventText.Append(" | eventId=");
        eventText.Append(evt.EventId);
        eventText.Append(" | severity=");
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
        return model.Contains("luna", StringComparison.OrdinalIgnoreCase)
            ? LunaContextWindowTokens
            : 128_000;
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
        return new Uri(baseUri, relativePath.TrimStart('/'));
    }

    private static string ExtractMessageContent(string responseJson, string mode)
    {
        using var document = JsonDocument.Parse(responseJson);
        var root = document.RootElement;

        if (string.Equals(mode, "responses", StringComparison.OrdinalIgnoreCase))
        {
            if (root.TryGetProperty("output_text", out var outputText)
                && outputText.ValueKind == JsonValueKind.String)
            {
                return outputText.GetString() ?? "{}";
            }

            if (root.TryGetProperty("output", out var output)
                && output.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in output.EnumerateArray())
                {
                    if (!item.TryGetProperty("content", out var content)
                        || content.ValueKind != JsonValueKind.Array)
                    {
                        continue;
                    }

                    foreach (var contentItem in content.EnumerateArray())
                    {
                        if (contentItem.TryGetProperty("text", out var text)
                            && text.ValueKind == JsonValueKind.String)
                        {
                            return text.GetString() ?? "{}";
                        }
                    }
                }
            }
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
        int maxRetries = 3)
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
            catch (HttpRequestException ex)
            {
                lastError = ex;
                _diagnosticLogService.WriteException(
                    $"AI request attempt failed: attempt={attempt + 1}/{maxRetries}, operation={operation}",
                    ex);
                if (attempt >= maxRetries - 1)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)), cancellationToken);
            }
            catch (IOException ex)
            {
                lastError = ex;
                _diagnosticLogService.WriteException(
                    $"AI request attempt failed: attempt={attempt + 1}/{maxRetries}, operation={operation}",
                    ex);
                if (attempt >= maxRetries - 1)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)), cancellationToken);
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
                _diagnosticLogService.WriteException(
                    $"AI request attempt timed out: attempt={attempt + 1}/{maxRetries}, operation={operation}",
                    ex);
                if (attempt >= maxRetries - 1)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)), cancellationToken);
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = ex;
                _diagnosticLogService.WriteException(
                    $"AI request attempt timed out: attempt={attempt + 1}/{maxRetries}, operation={operation}",
                    ex);
                if (attempt >= maxRetries - 1)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)), cancellationToken);
            }
        }

        if (lastError is OperationCanceledException)
        {
            throw new TimeoutException(
                $"The AI request timed out after {HttpClient.Timeout.TotalSeconds:0} seconds on each attempt. Last error: {FormatException(lastError)}",
                lastError);
        }

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
        return Math.Clamp(dynamicBatch, 5, 50);
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
        var safeEvents = events.Where(e => KnownSafeEventIds.Contains(e.EventId)).ToList();
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
                // Analyze 70% of warnings (clustered)
                var clustered = ClusterSimilarEvents(groupEvents);
                int take = (int)(clustered.Count * 0.7);
                toAnalyze.AddRange(clustered.Take(take));
                filteredOut.AddRange(clustered.Skip(take));
            }
            else if (severity.Contains("information"))
            {
                // Analyze 20% of info events (unique patterns only)
                var unique = FilterUniquePatterns(groupEvents);
                int take = (int)(unique.Count * 0.2);
                toAnalyze.AddRange(unique.Take(take));
                filteredOut.AddRange(groupEvents.Except(toAnalyze));
            }
            else
            {
                // Unknown severity: analyze 50%
                toAnalyze.AddRange(groupEvents.Take(groupEvents.Count / 2));
                filteredOut.AddRange(groupEvents.Skip(groupEvents.Count / 2));
            }
        }

        return toAnalyze;
    }

    private List<SecurityEvent> ClusterSimilarEvents(List<SecurityEvent> events)
    {
        // Group by EventId + Source, take representative samples
        return events
            .GroupBy(e => $"{e.EventId}|{e.Source}")
            .SelectMany(g => g.Take(3)) // Max 3 per cluster
            .ToList();
    }

    private List<SecurityEvent> FilterUniquePatterns(List<SecurityEvent> events)
    {
        var seen = new HashSet<string>();
        var unique = new List<SecurityEvent>();

        foreach (var evt in events)
        {
            string pattern = $"{evt.EventId}|{evt.Source}|{evt.UserName}";
            if (seen.Add(pattern))
            {
                unique.Add(evt);
            }
        }

        return unique;
    }

    private string CalculateEventFingerprint(SecurityEvent evt)
    {
        // Create signature from key attributes
        var signatureData = $"{evt.EventId}|{evt.Source}|{evt.Severity}|" +
                           $"{CompactText(evt.Description ?? "")[..Math.Min(200, (evt.Description?.Length ?? 0))]}";

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(signatureData));
        return Convert.ToBase64String(hash);
    }

    private async Task<List<AuditIssue>> AnalyzeEventsParallelAsync(
        List<SecurityEvent> events,
        AiTargetSettings target,
        string systemPrompt,
        int inputTokenBudget,
        int batchSize,
        int maxParallel,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var batches = new List<List<SecurityEvent>>();
        for (int i = 0; i < events.Count; i += batchSize)
        {
            batches.Add(events.Skip(i).Take(batchSize).ToList());
        }

        var allIssues = new ConcurrentBag<AuditIssue>();
        int completedBatches = 0;
        var semaphore = new SemaphoreSlim(maxParallel);

        var tasks = batches.Select(async (batch, index) =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var issues = await AnalyzeBatchWithCacheAsync(
                    target,
                    batch,
                    systemPrompt,
                    inputTokenBudget,
                    cancellationToken);

                foreach (var issue in issues)
                {
                    allIssues.Add(issue);
                }

                int completed = Interlocked.Increment(ref completedBatches);
                progress?.Report($"Analyzing ({completed}/{batches.Count})... {allIssues.Count} issues found");
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return allIssues.ToList();
    }

    private async Task<List<AuditIssue>> AnalyzeBatchWithCacheAsync(
        AiTargetSettings target,
        List<SecurityEvent> events,
        string systemPrompt,
        int inputTokenBudget,
        CancellationToken cancellationToken)
    {
        if (!_settingsService.Current.EnableCaching)
        {
            return await AnalyzeBatchAsync(target, events, systemPrompt, inputTokenBudget, cancellationToken);
        }

        // Check cache for individual events
        var uncachedEvents = new List<SecurityEvent>();
        var cachedIssues = new List<AuditIssue>();

        foreach (var evt in events)
        {
            string fingerprint = CalculateEventFingerprint(evt);
            if (_analysisCache.TryGet(fingerprint, out var issues))
            {
                cachedIssues.AddRange(issues);
            }
            else
            {
                uncachedEvents.Add(evt);
            }
        }

        if (uncachedEvents.Count == 0)
        {
            _diagnosticLogService.Write($"Cache hit: all {events.Count} events cached");
            return cachedIssues;
        }

        _diagnosticLogService.Write($"Cache: {cachedIssues.Count} hits, {uncachedEvents.Count} misses");

        // Analyze uncached events
        var newIssues = await AnalyzeBatchAsync(
            target,
            uncachedEvents,
            systemPrompt,
            inputTokenBudget,
            cancellationToken);

        // Update cache (group issues by event)
        foreach (var evt in uncachedEvents)
        {
            string fingerprint = CalculateEventFingerprint(evt);
            var eventIssues = newIssues.Where(i =>
                i.Description?.Contains(evt.EventId.ToString()) ?? false).ToList();
            _analysisCache.Set(fingerprint, eventIssues);
        }

        cachedIssues.AddRange(newIssues);
        return cachedIssues;
    }

    public void ClearCache()
    {
        _analysisCache.Clear();
        _diagnosticLogService.Write("Analysis cache cleared");
    }


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

    private sealed class IssuesResponse
    {
        public List<AuditIssue> Issues { get; set; } = new();
    }

    private sealed record AnalysisResponsePayload(
        string Text,
        bool IsStreaming,
        int StreamEventCount,
        int StatusCode,
        string? ReasonPhrase)
    {
        public bool IsSuccessStatusCode => StatusCode is >= 200 and <= 299;
    }
}
