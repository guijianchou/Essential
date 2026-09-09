using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public class AuditSchedulerService : IHostedService, IDisposable
{
    private readonly EventLogService _eventLogService;
    private readonly AiAnalysisService _aiAnalysisService;
    private readonly DataStorageService _storageService;
    private readonly SettingsService _settingsService;
    private readonly DiagnosticLogService _diagnosticLogService;
    private Task? _runningTask;
    private Task? _initialTask;
    private Task? _historyTask;
    private Task? _watchTask;
    private CancellationTokenSource? _historyCts;
    private CancellationTokenSource? _cts;
    private CancellationTokenSource? _loopCts;
    private readonly object _lifecycleLock = new();
    private readonly SemaphoreSlim _auditGate = new(1, 1);
    private readonly List<RetiredLoop> _retiredLoops = new();
    private DateTime _lastScanTime = DateTime.MinValue;
    private bool _isStopping;
    private int _scheduledIntervalHours;
    private AuditStage _currentStage;
    public bool IsScanning { get; private set; }
    public bool IsAssistantMode => _settingsService.IsAssistantMode;
    public string ActiveMode => _settingsService.ActiveMode;

    public event EventHandler<AuditCompletedEventArgs>? AuditCompleted;
    public event EventHandler<AuditFailedEventArgs>? AuditFailed;
    public event EventHandler<AuditProgressEventArgs>? AuditProgress;
    public event EventHandler? HistoryUpdated;

    public AuditSchedulerService(
        EventLogService eventLogService,
        AiAnalysisService aiAnalysisService,
        DataStorageService storageService,
        SettingsService settingsService,
        DiagnosticLogService diagnosticLogService)
    {
        _eventLogService = eventLogService;
        _aiAnalysisService = aiAnalysisService;
        _storageService = storageService;
        _settingsService = settingsService;
        _diagnosticLogService = diagnosticLogService;
        _scheduledIntervalHours = settingsService.Current.ScanIntervalHours;
        _settingsService.SettingsChanged += OnSettingsChanged;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        CancellationTokenSource startCts;

        lock (_lifecycleLock)
        {
            if (_cts != null)
            {
                return Task.CompletedTask;
            }

            _isStopping = false;
            startCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _cts = startCts;
            _watchTask = Task.Run(() => WatchAssistantResultsAsync(startCts.Token), startCts.Token);

            if (IsAssistantMode)
            {
                return Task.CompletedTask;
            }

            StartScheduleLoopCore();

            _initialTask = Task.Run(async () =>
            {
                if (!_settingsService.Current.AutoScanEnabled)
                {
                    return;
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), startCts.Token);
                    if (!startCts.IsCancellationRequested && _settingsService.Current.AutoScanEnabled)
                    {
                        await ExecuteAuditAsync(cancellationToken: startCts.Token);
                    }
                }
                catch (OperationCanceledException) when (startCts.IsCancellationRequested)
                {
                    // Expected when the application stops before the initial audit.
                }
            }, startCts.Token);
        }

        return Task.CompletedTask;
    }

    private void StartScheduleLoop()
    {
        RetiredLoop? retiredLoop = null;

        lock (_lifecycleLock)
        {
            if (_cts == null || _isStopping)
            {
                return;
            }

            if (_runningTask != null && _loopCts != null)
            {
                _loopCts.Cancel();
                retiredLoop = new RetiredLoop(_runningTask, _loopCts);
                _retiredLoops.Add(retiredLoop);
            }

            var nextCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            var nextTask = RunAuditLoopAsync(nextCts.Token);
            _loopCts = nextCts;
            _runningTask = nextTask;
        }

        if (retiredLoop != null)
        {
            _ = ObserveRetiredLoopAsync(retiredLoop);
        }
    }

    private void StartScheduleLoopCore()
    {
        if (_cts == null || _isStopping)
        {
            return;
        }

        if (_runningTask != null && _loopCts != null)
        {
            _loopCts.Cancel();
            var retiredLoop = new RetiredLoop(_runningTask, _loopCts);
            _retiredLoops.Add(retiredLoop);
            _ = ObserveRetiredLoopAsync(retiredLoop);
        }

        var nextCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        _loopCts = nextCts;
        _runningTask = RunAuditLoopAsync(nextCts.Token);
    }

    private async Task ObserveRetiredLoopAsync(RetiredLoop retiredLoop)
    {
        try
        {
            await retiredLoop.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected when the interval changes or the application stops.
        }
        catch
        {
            // The loop must not become an unobserved task. Individual audits
            // already report their failures through AuditFailed.
        }
        finally
        {
            bool shouldDispose;
            lock (_lifecycleLock)
            {
                shouldDispose = _retiredLoops.Remove(retiredLoop);
            }

            if (shouldDispose)
            {
                retiredLoop.CancellationTokenSource.Dispose();
            }
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Task? initialTask;
        Task? runningTask;
        Task? historyTask;
        CancellationTokenSource? loopCts;
        CancellationTokenSource? cts;
        List<RetiredLoop> retiredLoops;

        lock (_lifecycleLock)
        {
            _isStopping = true;
            initialTask = _initialTask;
            runningTask = _runningTask;
            historyTask = _historyTask;
            loopCts = _loopCts;
            cts = _cts;

            loopCts?.Cancel();
            cts?.Cancel();
            _historyCts?.Cancel();
            retiredLoops = _retiredLoops.ToList();
            foreach (var retiredLoop in retiredLoops)
            {
                retiredLoop.CancellationTokenSource.Cancel();
            }

            _retiredLoops.Clear();
            _initialTask = null;
            _runningTask = null;
            _loopCts = null;
            _cts = null;
        }

        var tasks = new List<Task>();
        if (initialTask != null) tasks.Add(ObserveTaskAsync(initialTask));
        if (runningTask != null) tasks.Add(ObserveTaskAsync(runningTask));
        if (historyTask != null) tasks.Add(ObserveTaskAsync(historyTask));
        if (_watchTask != null) tasks.Add(ObserveTaskAsync(_watchTask));
        tasks.AddRange(retiredLoops.Select(loop => ObserveTaskAsync(loop.Task)));

        var completion = Task.WhenAll(tasks);
        try
        {
            await completion.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _ = DisposeAfterCompletionAsync(completion, GetCancellationSources(loopCts, cts, retiredLoops));
            return;
        }

        DisposeCancellationSources(loopCts, cts, retiredLoops);
    }

    private async Task RunAuditLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(_settingsService.Current.ScanIntervalHours));

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                if (_settingsService.Current.AutoScanEnabled)
                {
                    await ExecuteAuditAsync(cancellationToken: cancellationToken);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected when settings change or the application stops.
        }
    }

    private void RestartScheduleLoop()
    {
        RetiredLoop? retiredLoop = null;

        lock (_lifecycleLock)
        {
            if (_cts == null || _isStopping)
            {
                return;
            }

            if (_runningTask != null && _loopCts != null)
            {
                _loopCts.Cancel();
                retiredLoop = new RetiredLoop(_runningTask, _loopCts);
                _retiredLoops.Add(retiredLoop);
            }

            var nextCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            _loopCts = nextCts;
            _runningTask = RunAuditLoopAsync(nextCts.Token);
        }

        if (retiredLoop != null)
        {
            _ = ObserveRetiredLoopAsync(retiredLoop);
        }
    }

    private void OnSettingsChanged(object? sender, EventArgs e)
    {
        if (IsAssistantMode) return;
        if (_scheduledIntervalHours == _settingsService.Current.ScanIntervalHours) return;
        _scheduledIntervalHours = _settingsService.Current.ScanIntervalHours;
        RestartScheduleLoop();
    }

    public async Task<bool> ExecuteAuditAsync(
        bool fastScan = true,
        CancellationToken cancellationToken = default,
        int fullScanDays = 1)
    {
        _settingsService.EnsureExtendedMode();
        if (!fastScan && fullScanDays is not (1 or 2 or 7)) throw new ArgumentOutOfRangeException(nameof(fullScanDays));
        await _auditGate.WaitAsync(cancellationToken);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await PauseHistoryTranslationAsync();
            cancellationToken.ThrowIfCancellationRequested();
            IsScanning = true;
            DateTime endTime = DateTime.UtcNow;
            var checkpoint = await _storageService.GetScanCheckpointAsync(ActiveMode);
            string requestedModel = _settingsService.Current.AiTargets.FirstOrDefault(target => target.Name == AiTargetSettings.MainName)?.Model
                ?? _settingsService.Current.AiTargets.FirstOrDefault()?.Model ?? string.Empty;
            bool modelUpgrade = checkpoint.BestModelRank >= 0 && AiModelCatalog.Rank(requestedModel) > checkpoint.BestModelRank;
            _lastScanTime = checkpoint.Cursor;
            DateTime startTime = GetScanStart(fastScan, endTime, _lastScanTime, _settingsService.Current, fullScanDays, modelUpgrade);
            string scanReason = modelUpgrade ? "model_upgrade" : _lastScanTime == default ? "initial" : "incremental";

            _diagnosticLogService.Write(
                $"Audit started: type={(fastScan ? "fast" : "full")}, reason={scanReason}, model={requestedModel}, from={startTime:O}, to={endTime:O}");
            ReportProgress(new(AuditStage.Collect, AuditStepState.Active, fastScan
                ? "Fast scan: reading Windows event logs..."
                : "Full scan: reading Windows event logs...") { StartsScan = true });
            var collection = await _eventLogService.ReadAllEventsAsync(startTime, endTime, cancellationToken, new AuditProgressReporter(ReportProgress));
            var events = collection.Events;
            _diagnosticLogService.Write(
                $"Event log read completed: type={(fastScan ? "fast" : "full")}, events={events.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            ReportProgress(new(AuditStage.Collect, AuditStepState.Done, "{0:N0} events collected", events.Count)
            { CompletedUnits = 5, TotalUnits = 5 });

            // Analyze with AI when there is data. An empty event window is still
            // a completed audit and must be persisted so the dashboard gives
            // the user a visible result instead of appearing to do nothing.
            cancellationToken.ThrowIfCancellationRequested();
            List<AuditIssue> issues;
            int analyzedEventCount = 0;
            IReadOnlyList<string> analysisModels = Array.Empty<string>();
            if (events.Count == 0)
            {
                ReportProgress(new(AuditStage.Route, AuditStepState.Skipped, "No events to analyze."));
                ReportProgress(new(AuditStage.Analyze, AuditStepState.Skipped, "No events to analyze."));
                issues = new List<AuditIssue>();
            }
            else
            {
                _diagnosticLogService.Write(
                    $"Audit sending events to AI: type={(fastScan ? "fast" : "full")}, events={events.Count}");
                (issues, analyzedEventCount) = await _aiAnalysisService.AnalyzeEventsAsync(
                    events,
                    new AuditProgressReporter(ReportProgress),
                    cancellationToken,
                    models => analysisModels = models);
            }

            // Calculate health score
            cancellationToken.ThrowIfCancellationRequested();
            int healthScore = CalculateHealthScore(issues);

            // Save to database
            var result = new AuditResult
            {
                Timestamp = DateTime.UtcNow,
                HealthScore = healthScore,
                Findings = issues,
                Metadata = new()
                {
                    { "SchemaVersion", JsonSerializer.SerializeToElement(2) },
                    { "Mode", JsonSerializer.SerializeToElement(ActiveMode) },
                    { "AnalysisModels", JsonSerializer.SerializeToElement(analysisModels) },
                    { "RequestedModel", JsonSerializer.SerializeToElement(requestedModel) },
                    { "AnalysisCompleted", JsonSerializer.SerializeToElement(true) },
                    { "ScanReason", JsonSerializer.SerializeToElement(scanReason) },
                    { "CoverageStatus", JsonSerializer.SerializeToElement(collection.CoverageStatus) },
                    { "CoverageNotes", JsonSerializer.SerializeToElement(collection.CoverageNotes) },
                    { "Channels", JsonSerializer.SerializeToElement(collection.Channels) },
                    { "EventCount", JsonSerializer.SerializeToElement(events.Count) },
                    { "AnalyzedEventCount", JsonSerializer.SerializeToElement(analyzedEventCount) },
                    { "FilteredEventCount", JsonSerializer.SerializeToElement(events.Count - analyzedEventCount) },
                    { "DurationMs", JsonSerializer.SerializeToElement(stopwatch.ElapsedMilliseconds) },
                    { "TimeRange", JsonSerializer.SerializeToElement($"{startTime:yyyy-MM-dd HH:mm} - {endTime:yyyy-MM-dd HH:mm}") },
                    { "ScanType", JsonSerializer.SerializeToElement(fastScan ? "Fast Scan" : "Full Scan") },
                    { "ScanStart", JsonSerializer.SerializeToElement(startTime.ToUniversalTime().ToString("O")) },
                    { "ScanEnd", JsonSerializer.SerializeToElement(endTime.ToUniversalTime().ToString("O")) }
                }
            };

            ReportProgress(new(AuditStage.Save, AuditStepState.Active, "Saving audit result..."));
            await _storageService.SaveAuditResultAsync(result);
            _diagnosticLogService.Write(
                $"Audit result saved: type={(fastScan ? "fast" : "full")}, events={events.Count}, issues={issues.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            // Update last scan time
            if (collection.CoverageStatus != "partial") _lastScanTime = endTime;

            // Notify UI
            IsScanning = false;
            ReportProgress(new(AuditStage.Save, AuditStepState.Done, "Saved at {0:t}", result.Timestamp.ToLocalTime()));
            AuditCompleted?.Invoke(this, new AuditCompletedEventArgs(result));
            if (analyzedEventCount > 0)
            {
                StartHistoryTranslation();
            }
            else
            {
                ReportProgress(new(AuditStage.Translate, AuditStepState.Skipped, "No new analysis to translate."));
                ReportProgress(new(AuditStage.Complete, AuditStepState.Done, "Scan saved / not assessed"));
            }
            try { await _storageService.CleanupOldDataAsync(_settingsService.Current.RetentionDays); }
            catch (Exception ex) { _diagnosticLogService.WriteException("Retention cleanup failed; the audit is saved", ex); }
            _diagnosticLogService.Write(
                $"Audit completed: type={(fastScan ? "fast" : "full")}, events={events.Count}, issues={issues.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _diagnosticLogService.Write(
                $"Audit canceled: type={(fastScan ? "fast" : "full")}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            IsScanning = false;
            ReportProgress(new(_currentStage, AuditStepState.Failed, "Scan canceled."));
            throw;
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException(
                $"Audit failed: type={(fastScan ? "fast" : "full")}, elapsedMs={stopwatch.ElapsedMilliseconds}",
                ex);
            IsScanning = false;
            ReportProgress(new(_currentStage, AuditStepState.Failed, "Scan failed: {0}", ex.Message));
            AuditFailed?.Invoke(this, new AuditFailedEventArgs(ex.Message));
            return false;
        }
        finally
        {
            IsScanning = false;
            _auditGate.Release();
        }
    }

    internal static DateTime GetScanStart(bool fastScan, DateTime endTime, DateTime lastScanTime, AppSettings settings, int fullScanDays = 1, bool modelUpgrade = false)
    {
        if (fullScanDays is not (1 or 2 or 7)) throw new ArgumentOutOfRangeException(nameof(fullScanDays));
        if (lastScanTime > DateTime.MinValue && lastScanTime < endTime && !modelUpgrade) return lastScanTime;
        if (!fastScan || modelUpgrade)
        {
            var baseline = endTime.AddDays(-fullScanDays);
            return lastScanTime > DateTime.MinValue && lastScanTime < baseline ? lastScanTime : baseline;
        }
        return settings.FastScanRangeHours > 0 ? endTime.AddHours(-settings.FastScanRangeHours)
            : endTime.AddHours(-settings.ScanIntervalHours);
    }

    internal static DateTime GetStoredScanEnd(AuditResult? result, DateTime now)
    {
        if (result?.Metadata?.TryGetValue("CoverageStatus", out var coverage) == true
            && (coverage.ValueKind != JsonValueKind.String || coverage.GetString() is not ("complete" or "limited")))
            return DateTime.MinValue;
        if (result?.Metadata?.TryGetValue("ScanEnd", out var value) == true
            && value.ValueKind == JsonValueKind.String
            && DateTime.TryParse(value.GetString(), System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind, out var end)
            && end.ToUniversalTime() <= now && end > DateTime.MinValue)
            return end.ToUniversalTime();
        return DateTime.MinValue;
    }

    public async Task<int> OptimizeHistoryAsync(string model, IProgress<AuditProgressEventArgs>? progress = null,
        CancellationToken cancellationToken = default)
    {
        _settingsService.EnsureExtendedMode();
        if (AiModelCatalog.Rank(model) < 0) throw new InvalidOperationException(AppText.Get("Select an explicit optimization model."));
        await _auditGate.WaitAsync(cancellationToken);
        Task<int> task;
        try
        {
            await PauseHistoryTranslationAsync();
            cancellationToken.ThrowIfCancellationRequested();
            lock (_lifecycleLock)
            {
                if (_isStopping) throw new OperationCanceledException();
                var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts?.Token ?? CancellationToken.None);
                _historyCts = source;
                // Share the historical-work lifetime: a new scan or app shutdown
                // cancels optimization and waits for its current save to finish.
                task = Task.Run(async () =>
                {
                    try { return await RunOptimizationAsync(model, progress, source.Token).ConfigureAwait(false); }
                    finally
                    {
                        lock (_lifecycleLock)
                        {
                            if (ReferenceEquals(_historyCts, source)) _historyCts = null;
                            source.Dispose();
                        }
                    }
                });
                _historyTask = task;
            }
        }
        finally { _auditGate.Release(); }
        return await task;
    }

    private async Task<int> RunOptimizationAsync(string model, IProgress<AuditProgressEventArgs>? progress, CancellationToken cancellationToken)
    {
        var records = await _storageService.GetOptimizationRecordsAsync(cancellationToken);
        int total = records.Sum(record => record.Findings.Count(issue => AiModelCatalog.CanOptimize(issue.AnalysisModel, model)));
        int completed = 0;
        progress?.Report(new(AuditStage.Analyze, AuditStepState.Active, "Optimizing {0} findings with {1}", total, model) { TotalUnits = total });
        foreach (var record in records)
        {
            string json = record.OriginalJson;
            var indexes = Enumerable.Range(0, record.Findings.Count)
                .Where(index => AiModelCatalog.CanOptimize(record.Findings[index].AnalysisModel, model)).Chunk(8);
            foreach (var batch in indexes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var reviewed = await _aiAnalysisService.OptimizeFindingsAsync(batch.Select(index => record.Findings[index]).ToList(), model,
                    new AuditProgressReporter(value => progress?.Report(new(value.Stage, value.State, value.MessageKey, value.Arguments)
                    { CompletedUnits = completed, TotalUnits = total })), cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                var updates = batch.Select((index, offset) => (index, finding: reviewed[offset])).ToDictionary(pair => pair.index, pair => pair.finding);
                json = await _storageService.UpdateOptimizedFindingsAsync(record.Id, json, updates, model, cancellationToken)
                    ?? throw new InvalidOperationException(AppText.Get("History changed during optimization. Reload before continuing."));
                completed += batch.Length;
                HistoryUpdated?.Invoke(this, EventArgs.Empty);
                progress?.Report(new(AuditStage.Save, AuditStepState.Active, "Saved {0}/{1} optimized findings", completed, total)
                { CompletedUnits = completed, TotalUnits = total });
            }
        }
        return completed;
    }

    private void ReportProgress(AuditProgressEventArgs progress)
    {
        if (progress.State == AuditStepState.Active && progress.Stage != AuditStage.Translate)
            _currentStage = progress.Stage;
        AuditProgress?.Invoke(this, progress);
    }

    private async Task PauseHistoryTranslationAsync()
    {
        Task? historyTask;
        lock (_lifecycleLock)
        {
            _historyCts?.Cancel();
            historyTask = _historyTask;
        }
        if (historyTask != null) await ObserveTaskAsync(historyTask).ConfigureAwait(false);
    }

    private void StartHistoryTranslation()
    {
        if (IsAssistantMode) return;
        lock (_lifecycleLock)
        {
            if (_isStopping || _historyTask is { IsCompleted: false }) return;
            var source = CancellationTokenSource.CreateLinkedTokenSource(_cts?.Token ?? CancellationToken.None);
            _historyCts = source;
            _historyTask = Task.Run(async () =>
            {
                try { await UpgradeLegacyFindingsAsync(source.Token).ConfigureAwait(false); }
                finally
                {
                    lock (_lifecycleLock)
                    {
                        if (ReferenceEquals(_historyCts, source)) _historyCts = null;
                        source.Dispose();
                    }
                }
            });
        }
    }

    private async Task UpgradeLegacyFindingsAsync(CancellationToken cancellationToken)
    {
        _settingsService.EnsureExtendedMode();
        string status = "English + Simplified Chinese saved";
        var state = AuditStepState.Done;
        try
        {
            var records = await _storageService.GetLegacyFindingsAsync();
            if (records.Count == 0) return;
            try
            {
                await _aiAnalysisService.TranslateLegacyFindingsAsync(
                    records.SelectMany(record => record.Findings).ToList(),
                    new AuditProgressReporter(ReportProgress), cancellationToken);
                status = "Historical findings are now available in both languages.";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                status = "Historical translation paused for the next scan.";
                state = AuditStepState.Skipped;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _diagnosticLogService.WriteException("Historical translation deferred until the next scan", ex);
                status = "Historical translation failed. It will retry after the next scan.";
                state = AuditStepState.Failed;
            }

            bool updated = false;
            // Persist finished batches even when translation was interrupted by a new scan.
            foreach (var record in records)
            {
                if (!record.Findings.Any(issue => issue.HasBilingualText)) continue;
                bool saved = await _storageService.UpdateTranslatedFindingsAsync(record.Id, record.OriginalJson, record.Findings);
                updated |= saved;
                if (!saved)
                {
                    state = AuditStepState.Failed;
                    status = "Historical translation could not be saved. It will retry after the next scan.";
                }
            }
            if (updated) HistoryUpdated?.Invoke(this, EventArgs.Empty);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException("Historical translation could not be saved; the audit remains valid", ex);
            status = "Historical translation failed. It will retry after the next scan.";
            state = AuditStepState.Failed;
        }
        finally
        {
            ReportProgress(new(AuditStage.Translate, state, status));
            ReportProgress(new(AuditStage.Complete, AuditStepState.Done,
                state == AuditStepState.Done ? "Scan complete" : "Scan saved / translation pending"));
        }
    }

    public void Dispose()
    {
        _settingsService.SettingsChanged -= OnSettingsChanged;
        _auditGate.Dispose();
    }

    private async Task WatchAssistantResultsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await _storageService.WatchForChangesAsync(() => HistoryUpdated?.Invoke(this, EventArgs.Empty), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException("Assistant result refresh deferred", ex);
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            }
        }
    }

    private static int CalculateHealthScore(List<AuditIssue> issues)
    {
        return HealthScoreCalculator.Calculate(issues).Score;
    }

    private static async Task ObserveTaskAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch
        {
            // Shutdown should observe, not rethrow, background loop failures.
        }
    }

    private static CancellationTokenSource[] GetCancellationSources(
        CancellationTokenSource? loopCts,
        CancellationTokenSource? cts,
        IEnumerable<RetiredLoop> retiredLoops)
    {
        return new[] { loopCts, cts }
            .Where(source => source != null)
            .Cast<CancellationTokenSource>()
            .Concat(retiredLoops.Select(loop => loop.CancellationTokenSource))
            .Distinct()
            .ToArray();
    }

    private static void DisposeCancellationSources(
        CancellationTokenSource? loopCts,
        CancellationTokenSource? cts,
        IEnumerable<RetiredLoop> retiredLoops)
    {
        foreach (var source in GetCancellationSources(loopCts, cts, retiredLoops))
        {
            source.Dispose();
        }
    }

    private static async Task DisposeAfterCompletionAsync(
        Task completion,
        IEnumerable<CancellationTokenSource> sources)
    {
        await completion.ConfigureAwait(false);
        foreach (var source in sources)
        {
            source.Dispose();
        }
    }

    private sealed class RetiredLoop
    {
        public RetiredLoop(Task task, CancellationTokenSource cancellationTokenSource)
        {
            Task = task;
            CancellationTokenSource = cancellationTokenSource;
        }

        public Task Task { get; }
        public CancellationTokenSource CancellationTokenSource { get; }
    }
}
