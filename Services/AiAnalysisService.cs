using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Globalization;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed partial class AiAnalysisService
{
    private const int NormalBatchSize = 30;
    private const int XHighBatchSize = 15;
    private const int MinBatchSize = 20;
    private const int MaxBatchSize = 50;
    private const int ConnectionTestTimeoutSeconds = 90;
    private const int KernelRequestTimeoutSeconds = 600;
    private const int MaxKernelOutputChars = 8 * 1024 * 1024;
    private const int ResponseOutputTokenBudget = 8_000;
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
    private readonly KernelManagerService? _kernelManagerService;
    private readonly LruCache<string, CachedBatchAnalysis> _analysisCache = new(100);

    public AiAnalysisService(
        SettingsService settingsService,
        DiagnosticLogService diagnosticLogService)
        : this(settingsService, diagnosticLogService, null)
    {
    }

    public AiAnalysisService(
        SettingsService settingsService,
        DiagnosticLogService diagnosticLogService,
        KernelManagerService? kernelManagerService)
    {
        _settingsService = settingsService;
        _diagnosticLogService = diagnosticLogService;
        _kernelManagerService = kernelManagerService;
    }

    public async Task<(List<AuditIssue> Issues, int AnalyzedEventCount)> AnalyzeEventsAsync(
        List<SecurityEvent> events,
        IProgress<AuditProgressEventArgs>? progress = null,
        CancellationToken cancellationToken = default,
        Action<IReadOnlyList<string>>? modelsCompleted = null)
    {
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
                    {
                        BatchNumber = value.Stage == AuditStage.Analyze ? currentBatch : 0,
                        EstimatedInputTokens = value.EstimatedInputTokens,
                        RequestId = value.RequestId, HasTokenUsage = value.HasTokenUsage,
                        InputTokens = value.InputTokens, OutputTokens = value.OutputTokens
                    })),
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

    public async Task<(bool Success, string Message)> TestConnectionAsync(
        AiTarget target,
        string? kernel = null,
        IProgress<AuditProgressEventArgs>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string selectedKernel = AiKernelCatalog.Normalize(kernel ?? _settingsService.Current.AiKernel);
        try
        {
            if (_kernelManagerService == null)
                return (false, AppText.Get("The selected AI kernel is unavailable in this build."));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(ConnectionTestTimeoutSeconds));
            var settings = new AiTargetSettings
            {
                Name = target.Name,
                BaseUrl = target.BaseUrl,
                ApiKey = target.ApiKey,
                Mode = target.Mode,
                Model = target.Model,
                Effort = target.Effort
            };
            var response = await SendKernelRequestToTargetAsync(
                selectedKernel,
                settings,
                "Return exactly {\"issues\":[]}.",
                "Connection test. Do not analyze events.",
                progress,
                timeout.Token);
            using var document = JsonDocument.Parse(response.Text);
            if (!document.RootElement.TryGetProperty("issues", out var issues)
                || issues.ValueKind != JsonValueKind.Array || issues.GetArrayLength() != 0)
                throw new InvalidOperationException(AppText.Get("The kernel returned an invalid connection-test response."));
            return (true, AppText.Format("{0} kernel and endpoint are ready.", selectedKernel));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (false, AppText.Format("{0} connection test timed out after {1}s.", selectedKernel, ConnectionTestTimeoutSeconds));
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception or TimeoutException or JsonException or ArgumentException)
        {
            _diagnosticLogService.WriteException(
                $"AI connection test failed: kernel={selectedKernel}, target={target.Name}",
                ex);
            return (false, AppText.Format("{0} kernel test failed: {1}", selectedKernel, FormatException(ex)));
        }
    }

    private async Task<List<AuditIssue>> AnalyzeBatchAsync(
        IReadOnlyList<AiTargetSettings> routes,
        List<SecurityEvent> events,
        string systemPrompt,
        int inputTokenBudget,
        AnalysisRouteState routeState,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken,
        Action<string>? modelCompleted = null)
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
        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Prepared {0:N0} input tokens", estimatedInputTokens)
        { EstimatedInputTokens = estimatedInputTokens });
        var response = await SendAnalysisRequestAsync(
            routes,
            systemPrompt,
            eventSummary,
            routeState,
            progress,
            cancellationToken);
        string messageContent = response.Text;
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
        modelCompleted?.Invoke(response.Model);
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
        var target = GetCurrentRoute(routes, routeState);
        string kernel = AiKernelCatalog.Normalize(_settingsService.Current.AiKernel);
        try
        {
            return await SendKernelRequestToTargetAsync(kernel, target, systemPrompt, userPrompt, progress, cancellationToken);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested
            && !ReferenceEquals(target, routes.Last()) && IsFailoverException(ex))
        {
            SwitchToFallback(routes, routeState, target.Name, FormatException(ex));
            progress?.Report(new(AuditStage.Route, AuditStepState.Done, "{0} unavailable; using {1}", target.Name, routes[1].Name));
            return await SendKernelRequestToTargetAsync(kernel, routes[1], systemPrompt, userPrompt, progress, cancellationToken);
        }
    }

    private async Task<AnalysisResponsePayload> SendKernelRequestToTargetAsync(
        string kernel,
        AiTargetSettings target,
        string systemPrompt,
        string userPrompt,
        IProgress<AuditProgressEventArgs>? progress,
        CancellationToken cancellationToken)
    {
        if (_kernelManagerService == null)
        {
            throw new InvalidOperationException(AppText.Get("The selected AI kernel is unavailable in this build."));
        }

        if (!Uri.TryCreate(target.BaseUrl.Trim(), UriKind.Absolute, out var endpoint)
            || endpoint.Scheme is not ("http" or "https") || endpoint.UserInfo.Length > 0)
            throw new InvalidOperationException(AppText.Get("Enter a valid HTTP or HTTPS endpoint URL."));

        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Prepared {0:N0} input tokens", EstimateTokenCount(systemPrompt + userPrompt))
        { EstimatedInputTokens = EstimateTokenCount(systemPrompt + userPrompt) });
        string executable = _kernelManagerService.RequireExecutable(kernel);
        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Connecting to {0} kernel", kernel));
        _diagnosticLogService.Write($"AI kernel dispatching: kernel={kernel}, route={target.Name}, model={target.Model}");

        string temporaryRoot = Path.Combine(Path.GetTempPath(), $"lsa-kernel-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryRoot);
        string outputPath = Path.Combine(temporaryRoot, "last-message.txt");
        string userPromptPath = Path.Combine(temporaryRoot, "user-prompt.txt");
        string codexHome = Path.Combine(temporaryRoot, "codex-home");
        string piHome = Path.Combine(temporaryRoot, "pi-home");
        try
        {
            File.WriteAllText(userPromptPath, userPrompt, new UTF8Encoding(false));
            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = temporaryRoot
            };
            ConfigureKernelProcess(startInfo, kernel, target, systemPrompt, userPromptPath, outputPath, codexHome, piHome);
            if (kernel == AiKernelCatalog.Codex)
                await ConfigureCodexModelCatalogAsync(startInfo, codexHome, cancellationToken);

            using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            if (!process.Start())
            {
                throw new InvalidOperationException(AppText.Get("The selected AI kernel could not be started."));
            }

            using var requestCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            requestCts.CancelAfter(TimeSpan.FromSeconds(KernelRequestTimeoutSeconds));
            string requestId = Guid.NewGuid().ToString("N");
            var output = new KernelOutput();
            Task stdoutTask = ReadKernelOutputAsync(process.StandardOutput, kernel, requestId, output, target.ApiKey, progress, requestCts.Token);
            Task<string> stderrTask = ReadKernelErrorAsync(process.StandardError, requestCts.Token);
            try
            {
                if (kernel == AiKernelCatalog.Codex)
                {
                    // Codex loads this request's policy from the working directory's
                    // AGENTS.md through its standard instruction-discovery path.
                    await process.StandardInput.WriteAsync(userPrompt.AsMemory(), requestCts.Token);
                }
                process.StandardInput.Close();

                var elapsed = Stopwatch.StartNew();
                Task exitTask = process.WaitForExitAsync(requestCts.Token);
                while (!exitTask.IsCompleted)
                {
                    await Task.WhenAny(exitTask, Task.Delay(TimeSpan.FromSeconds(5), requestCts.Token));
                    requestCts.Token.ThrowIfCancellationRequested();
                    if (stdoutTask.IsFaulted) await stdoutTask;
                    if (!exitTask.IsCompleted)
                    {
                        string error = output.Error;
                        progress?.Report(error.Length == 0
                            ? new(AuditStage.Analyze, AuditStepState.Active, "Waiting for {0} kernel ({1:0}s)", kernel, elapsed.Elapsed.TotalSeconds)
                            : new(AuditStage.Analyze, AuditStepState.Active, "Waiting for {0} kernel ({1:0}s): {2}",
                                kernel, elapsed.Elapsed.TotalSeconds, KernelErrorDetail(error, target.ApiKey)));
                    }
                }
                await exitTask;
                await stdoutTask;
                string stderr = await stderrTask;
                if (process.ExitCode != 0 || output.Error.Length > 0)
                {
                    string detail = output.Error.Length > 0 ? output.Error : stderr.Trim();
                    throw new InvalidOperationException(AppText.Format("{0} kernel failed (exit {1}): {2}",
                        kernel, process.ExitCode, KernelErrorDetail(detail, target.ApiKey)));
                }
                if (kernel == AiKernelCatalog.Codex && File.Exists(outputPath))
                    output.Text = File.ReadAllText(outputPath).Trim();
                if (!output.Completed || string.IsNullOrWhiteSpace(output.Text))
                    throw new InvalidOperationException(AppText.Format("{0} kernel ended without a complete response.", kernel));

                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Validating {0} response", kernel));
                return new AnalysisResponsePayload(output.Text, output.Model.Length > 0 ? output.Model : target.Model);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(AppText.Format("{0} kernel timed out after {1}s.", kernel, KernelRequestTimeoutSeconds));
            }
            finally
            {
                // Cancellation can occur while writing stdin as well as while waiting for exit.
                if (!process.HasExited)
                {
                    try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                }
                requestCts.Cancel();
                try { await Task.WhenAll(stdoutTask, stderrTask); } catch (Exception) { }
            }
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException($"AI kernel request failed: kernel={kernel}, route={target.Name}", ex);
            throw;
        }
        finally
        {
            try { if (Directory.Exists(temporaryRoot)) Directory.Delete(temporaryRoot, true); } catch { }
        }
    }

    private static void ConfigureKernelProcess(
        ProcessStartInfo startInfo,
        string kernel,
        AiTargetSettings target,
        string systemPrompt,
        string userPromptPath,
        string outputPath,
        string codexHome,
        string piHome)
    {
        string instructionsPath = Path.Combine(Path.GetDirectoryName(userPromptPath)!, "AGENTS.md");
        File.WriteAllText(instructionsPath, systemPrompt, new UTF8Encoding(false));
        if (kernel == AiKernelCatalog.Codex)
        {
            Directory.CreateDirectory(codexHome);
            string baseUrl = target.BaseUrl.TrimEnd('/');
            if (!baseUrl.EndsWith("/v1", StringComparison.OrdinalIgnoreCase))
            {
                baseUrl += "/v1";
            }
            if (string.Equals(target.Mode, "chat", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(AppText.Get("Codex requires Responses API. Select Responses or use Pi for Chat Completions."));
            // The editable policy is limited in characters; Codex limits AGENTS.md
            // in bytes. Include the complete UTF-8 policy and mandatory output contract.
            int instructionsBytes = Math.Max(32768, Encoding.UTF8.GetByteCount(systemPrompt));
            string config = $"model = {TomlString(target.Model)}\nmodel_reasoning_effort = {TomlString(target.Effort)}\nmodel_provider = \"localsecurityaudit\"\nproject_doc_max_bytes = {instructionsBytes}\n\n[model_providers.localsecurityaudit]\nname = \"LocalSecurityAudit\"\nbase_url = {TomlString(baseUrl)}\nwire_api = \"responses\"\n";
            if (!string.IsNullOrWhiteSpace(target.ApiKey)) config += "env_key = \"LOCAL_SECURITY_AUDIT_API_KEY\"\n";
            File.WriteAllText(Path.Combine(codexHome, "config.toml"), config, new UTF8Encoding(false));
            startInfo.Environment["CODEX_HOME"] = codexHome;
            startInfo.Environment.Remove("OPENAI_API_KEY");
            startInfo.Environment.Remove("CODEX_API_KEY");
            startInfo.Environment["LOCAL_SECURITY_AUDIT_API_KEY"] = target.ApiKey?.Trim() ?? string.Empty;

            startInfo.ArgumentList.Add("exec");
            startInfo.ArgumentList.Add("--json");
            startInfo.ArgumentList.Add("--ephemeral");
            startInfo.ArgumentList.Add("--sandbox");
            startInfo.ArgumentList.Add("read-only");
            startInfo.ArgumentList.Add("--skip-git-repo-check");
            startInfo.ArgumentList.Add("--color");
            startInfo.ArgumentList.Add("never");
            startInfo.ArgumentList.Add("--output-last-message");
            startInfo.ArgumentList.Add(outputPath);
            startInfo.ArgumentList.Add("-");
            return;
        }

        Directory.CreateDirectory(piHome);
        string piBaseUrl = target.BaseUrl.TrimEnd('/');
        if (!piBaseUrl.EndsWith("/v1", StringComparison.OrdinalIgnoreCase)) piBaseUrl += "/v1";
        // Never reuse the user's encrypted Pi auth/session files. An isolated
        // directory also prevents stale host credentials from affecting retries.
        startInfo.Environment["PI_CODING_AGENT_DIR"] = piHome;
        startInfo.Environment["PI_CODING_AGENT_SESSION_DIR"] = piHome;
        startInfo.Environment["PI_OFFLINE"] = "1";
        startInfo.Environment["PI_SKIP_VERSION_CHECK"] = "1";
        startInfo.Environment["PI_TELEMETRY"] = "0";
        startInfo.Environment["OPENAI_API_KEY"] = target.ApiKey?.Trim() ?? string.Empty;
        startInfo.Environment["OPENAI_BASE_URL"] = piBaseUrl;
        var piConfig = new
        {
            providers = new Dictionary<string, object>
            {
                ["localsecurityaudit"] = new
                {
                    baseUrl = piBaseUrl,
                    api = string.Equals(target.Mode, "chat", StringComparison.OrdinalIgnoreCase)
                        ? "openai-completions" : "openai-responses",
                    apiKey = "$OPENAI_API_KEY",
                    authHeader = true,
                    models = new[]
                    {
                        new
                        {
                            id = target.Model,
                            name = target.Model,
                            reasoning = true,
                            input = new[] { "text" },
                            contextWindow = 256000,
                            maxTokens = 8000
                        }
                    }
                }
            }
        };
        File.WriteAllText(Path.Combine(piHome, "models.json"), JsonSerializer.Serialize(piConfig), new UTF8Encoding(false));
        startInfo.ArgumentList.Add("--mode");
        startInfo.ArgumentList.Add("json");
        startInfo.ArgumentList.Add("--print");
        startInfo.ArgumentList.Add("--no-session");
        startInfo.ArgumentList.Add("--no-tools");
        startInfo.ArgumentList.Add("--no-context-files");
        startInfo.ArgumentList.Add("--provider");
        startInfo.ArgumentList.Add("localsecurityaudit");
        startInfo.ArgumentList.Add("--model");
        startInfo.ArgumentList.Add(target.Model);
        startInfo.ArgumentList.Add("--thinking");
        startInfo.ArgumentList.Add(target.Effort);
        startInfo.ArgumentList.Add("--system-prompt");
        startInfo.ArgumentList.Add("Follow the supplied task instructions. Return only the requested JSON.");
        // Pi's explicit file option also avoids the Windows command-line size limit.
        startInfo.ArgumentList.Add("--append-system-prompt");
        startInfo.ArgumentList.Add(instructionsPath);
        startInfo.ArgumentList.Add("--");
        startInfo.ArgumentList.Add("@" + userPromptPath);
    }

    private static string TomlString(string value) => JsonSerializer.Serialize(value);

    private static async Task ConfigureCodexModelCatalogAsync(
        ProcessStartInfo requestInfo, string codexHome, CancellationToken cancellationToken)
    {
        // Keep the installed kernel's model instructions and capabilities. Only disable
        // its internal Lite protocol, which public Responses gateways may not forward.
        var startInfo = new ProcessStartInfo
        {
            FileName = requestInfo.FileName,
            WorkingDirectory = requestInfo.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var variable in requestInfo.Environment) startInfo.Environment[variable.Key] = variable.Value;
        startInfo.ArgumentList.Add("debug");
        startInfo.ArgumentList.Add("models");
        startInfo.ArgumentList.Add("--bundled");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var process = new Process { StartInfo = startInfo };
        if (!process.Start()) throw new InvalidOperationException(AppText.Get("The selected AI kernel could not be started."));
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
        Task<string> stderr = ReadKernelErrorAsync(process.StandardError, timeout.Token);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            string catalogText = await stdout;
            await stderr;
            if (process.ExitCode != 0 || catalogText.Length > MaxKernelOutputChars
                || JsonNode.Parse(catalogText) is not JsonObject catalog || catalog["models"] is not JsonArray models)
                throw new InvalidOperationException(AppText.Get("Codex could not load its bundled model catalog. Update the kernel and retry."));
            foreach (var model in models.OfType<JsonObject>()) model["use_responses_lite"] = false;
            string catalogPath = Path.Combine(codexHome, "models.json");
            await File.WriteAllTextAsync(catalogPath, catalog.ToJsonString(), new UTF8Encoding(false), timeout.Token);
            string configPath = Path.Combine(codexHome, "config.toml");
            string config = await File.ReadAllTextAsync(configPath, timeout.Token);
            await File.WriteAllTextAsync(configPath, $"model_catalog_json = {TomlString(catalogPath)}\n" + config,
                new UTF8Encoding(false), timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(AppText.Get("Codex model catalog loading timed out."));
        }
        finally
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            }
            timeout.Cancel();
            try { await Task.WhenAll(stdout, stderr); } catch (Exception) { }
        }
    }

    private static string KernelErrorDetail(string detail, string? apiKey)
    {
        if (!string.IsNullOrWhiteSpace(apiKey))
            detail = detail.Replace(apiKey.Trim(), "[redacted]", StringComparison.Ordinal);
        return TruncateText(detail, 600);
    }

    private sealed class KernelOutput
    {
        public string Text = string.Empty;
        public string Model = string.Empty;
        public string Error = string.Empty;
        public bool Started;
        public bool Completed;
        public bool HasTokenUsage;
        public long InputTokens;
        public long OutputTokens;
    }

    private static async Task ReadKernelOutputAsync(
        StreamReader reader, string kernel, string requestId, KernelOutput output, string? apiKey,
        IProgress<AuditProgressEventArgs>? progress, CancellationToken cancellationToken)
    {
        int characters = 0;
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            characters += line.Length;
            if (characters > MaxKernelOutputChars) throw new InvalidDataException("Kernel output exceeded the response limit.");
            string previousError = output.Error;
            string previousText = output.Text;
            bool wasStarted = output.Started;
            ProcessKernelEvent(kernel, line, output);
            if (!wasStarted && output.Started)
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "{0} kernel is processing the request", kernel));
            if (output.Error.Length > 0 && output.Error != previousError)
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "{0} kernel: {1}", kernel, KernelErrorDetail(output.Error, apiKey)));
            else if (output.Text != previousText && !output.HasTokenUsage)
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Receiving {0} response", kernel));
            if (output.HasTokenUsage)
                progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Receiving {0} response", kernel)
                {
                    RequestId = requestId, HasTokenUsage = true,
                    InputTokens = output.InputTokens, OutputTokens = output.OutputTokens
                });
        }
    }

    private static async Task<string> ReadKernelErrorAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        // Drain stderr continuously so the child cannot block on a full pipe.
        var tail = new StringBuilder();
        var buffer = new char[1024];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            tail.Append(buffer, 0, count);
            if (tail.Length > 2048) tail.Remove(0, tail.Length - 2048);
        }
        return tail.ToString();
    }

    private static string ExtractKernelOutput(string kernel, string outputPath, string stdout)
    {
        var output = new KernelOutput();
        foreach (string line in stdout.Split('\n')) ProcessKernelEvent(kernel, line, output);
        if (output.Error.Length > 0) throw new InvalidOperationException("Kernel reported a failed response.");
        if (kernel == AiKernelCatalog.Codex && File.Exists(outputPath))
            return File.ReadAllText(outputPath).Trim();
        return output.Text;
    }

    private static void ProcessKernelEvent(string kernel, string line, KernelOutput output)
    {
        if (string.IsNullOrWhiteSpace(line) || !line.TrimStart().StartsWith('{')) return;
        JsonDocument document;
        try { document = JsonDocument.Parse(line); }
        catch (JsonException) { return; }
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return;
            string type = KernelString(root, "type");
            if (type is "turn.started" or "agent_start") output.Started = true;
            if (type is "error" or "turn.failed")
            {
                output.Error = root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object
                    ? KernelString(error, "message") : KernelString(root, "message");
                if (output.Error.Length == 0) output.Error = "Kernel reported a failed response.";
                return;
            }
            if (kernel == AiKernelCatalog.Codex)
            {
                if (type == "item.completed" && root.TryGetProperty("item", out var item)
                    && item.ValueKind == JsonValueKind.Object && KernelString(item, "type") == "agent_message")
                    output.Text = KernelString(item, "text");
                if (type == "turn.completed")
                {
                    output.Completed = true;
                    output.Error = string.Empty;
                    output.Model = KernelString(root, "model");
                    if (root.TryGetProperty("usage", out var usage) && usage.ValueKind == JsonValueKind.Object)
                    {
                        output.HasTokenUsage = true;
                        output.InputTokens = KernelTokenCount(usage, "input_tokens");
                        output.OutputTokens = KernelTokenCount(usage, "output_tokens");
                    }
                }
                return;
            }
            if (type == "message_end" && root.TryGetProperty("message", out var message))
                ReadPiMessage(message, output);
            if (type == "agent_end" && root.TryGetProperty("messages", out var messages) && messages.ValueKind == JsonValueKind.Array)
                foreach (var completed in messages.EnumerateArray()) ReadPiMessage(completed, output);
        }
    }

    private static void ReadPiMessage(JsonElement message, KernelOutput output)
    {
        if (message.ValueKind != JsonValueKind.Object || KernelString(message, "role") != "assistant") return;
        output.Model = KernelString(message, "model");
        if (message.TryGetProperty("usage", out var usage) && usage.ValueKind == JsonValueKind.Object)
        {
            output.HasTokenUsage = true;
            output.InputTokens = KernelTokenCount(usage, "input") + KernelTokenCount(usage, "cacheRead") + KernelTokenCount(usage, "cacheWrite");
            output.OutputTokens = KernelTokenCount(usage, "output");
        }
        string stopReason = KernelString(message, "stopReason");
        if (stopReason is "error" or "aborted" or "length" or "toolUse")
        {
            output.Error = KernelString(message, "errorMessage");
            if (output.Error.Length == 0) output.Error = $"Pi response was incomplete ({stopReason}).";
            return;
        }
        if (message.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.Array)
        {
            output.Text = string.Concat(content.EnumerateArray()
                .Where(part => part.ValueKind == JsonValueKind.Object && KernelString(part, "type") == "text")
                .Select(part => KernelString(part, "text")));
            output.Completed = true;
            output.Error = string.Empty;
        }
    }

    private static string KernelString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;

    private static long KernelTokenCount(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long count) ? Math.Max(0, count) : 0;

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
            Kernel = AiKernelCatalog.Normalize(_settingsService.Current.AiKernel),
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

    private static bool IsFailoverException(Exception exception) =>
        exception is IOException or TimeoutException or InvalidOperationException or Win32Exception;

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
                    {
                        BatchNumber = value.Stage == AuditStage.Analyze ? index + 1 : 0,
                        EstimatedInputTokens = value.EstimatedInputTokens,
                        RequestId = value.RequestId, HasTokenUsage = value.HasTokenUsage,
                        InputTokens = value.InputTokens, OutputTokens = value.OutputTokens
                    })),
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
            routeState.Models.TryAdd(cached.Model, 0);
            _diagnosticLogService.Write($"Cache hit: batch events={events.Count}, issues={cached.Issues.Count}");
            return cached.Issues.Select(CloneIssue).ToList();
        }

        string completedModel = string.Empty;
        var issues = await AnalyzeBatchAsync(
            routes,
            events,
            systemPrompt,
            inputTokenBudget,
            routeState,
            progress,
            cancellationToken,
            model => completedModel = model);

        // Cache only primary-route results. A fallback response must not be silently reused
        // when the primary endpoint becomes healthy again.
        if (!routeState.UseFallback)
        {
            _analysisCache.Set(cacheKey, new CachedBatchAnalysis
            {
                Issues = issues.Select(CloneIssue).ToList(),
                Model = completedModel
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

    private sealed record AnalysisResponsePayload(string Text, string Model);

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
        public string Model { get; init; } = string.Empty;
    }
}
