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
    private CancellationTokenSource? _cts;
    private CancellationTokenSource? _loopCts;
    private readonly object _lifecycleLock = new();
    private readonly SemaphoreSlim _auditGate = new(1, 1);
    private readonly List<RetiredLoop> _retiredLoops = new();
    private DateTime _lastScanTime = DateTime.MinValue;
    private bool _isStopping;

    public event EventHandler<AuditCompletedEventArgs>? AuditCompleted;
    public event EventHandler<AuditFailedEventArgs>? AuditFailed;
    public event EventHandler<AuditProgressEventArgs>? AuditProgress;

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
        CancellationTokenSource? loopCts;
        CancellationTokenSource? cts;
        List<RetiredLoop> retiredLoops;

        lock (_lifecycleLock)
        {
            _isStopping = true;
            initialTask = _initialTask;
            runningTask = _runningTask;
            loopCts = _loopCts;
            cts = _cts;

            loopCts?.Cancel();
            cts?.Cancel();
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
        RestartScheduleLoop();
    }

    public async Task<bool> ExecuteAuditAsync(
        bool fastScan = true,
        CancellationToken cancellationToken = default)
    {
        await _auditGate.WaitAsync(cancellationToken);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            DateTime endTime = DateTime.UtcNow;
            DateTime startTime;

            if (fastScan)
            {
                // Fast Scan: incremental scan, only scan new data since last scan
                int rangeHours = _settingsService.Current.FastScanRangeHours;
                startTime = rangeHours > 0
                    ? endTime.AddHours(-rangeHours)
                    : _lastScanTime == DateTime.MinValue
                        ? endTime.AddHours(-_settingsService.Current.ScanIntervalHours)
                    : _lastScanTime;
            }
            else
            {
                // Full Scan: complete scan, scan all data from past 24 hours
                startTime = endTime.AddHours(-24);
            }

            _diagnosticLogService.Write(
                $"Audit started: type={(fastScan ? "fast" : "full")}, from={startTime:O}, to={endTime:O}");
            ReportProgress(fastScan
                ? "Fast scan: reading Windows event logs..."
                : "Full scan: reading Windows event logs...");
            var events = await _eventLogService.ReadAllEventsAsync(startTime, endTime, cancellationToken);
            _diagnosticLogService.Write(
                $"Event log read completed: type={(fastScan ? "fast" : "full")}, events={events.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");

            // Analyze with AI when there is data. An empty event window is still
            // a completed audit and must be persisted so the dashboard gives
            // the user a visible result instead of appearing to do nothing.
            cancellationToken.ThrowIfCancellationRequested();
            List<AuditIssue> issues;
            if (events.Count == 0)
            {
                ReportProgress("No matching events found. Saving an empty audit result...");
                issues = new List<AuditIssue>();
            }
            else
            {
                ReportProgress($"Collected {events.Count:N0} events. Sending to AI...");
                _diagnosticLogService.Write(
                    $"Audit sending events to AI: type={(fastScan ? "fast" : "full")}, events={events.Count}");
                issues = await _aiAnalysisService.AnalyzeEventsAsync(
                    events,
                    new Progress<string>(ReportProgress),
                    cancellationToken);
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
                    { "EventCount", JsonSerializer.SerializeToElement(events.Count) },
                    { "TimeRange", JsonSerializer.SerializeToElement($"{startTime:yyyy-MM-dd HH:mm} - {endTime:yyyy-MM-dd HH:mm}") },
                    { "ScanType", JsonSerializer.SerializeToElement(fastScan ? "Fast Scan" : "Full Scan") }
                }
            };

            ReportProgress("Saving audit result...");
            await _storageService.SaveAuditResultAsync(result);
            _diagnosticLogService.Write(
                $"Audit result saved: type={(fastScan ? "fast" : "full")}, events={events.Count}, issues={issues.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            cancellationToken.ThrowIfCancellationRequested();
            await _storageService.CleanupOldDataAsync(_settingsService.Current.RetentionDays);

            // Update last scan time
            _lastScanTime = endTime;

            // Notify UI
            AuditCompleted?.Invoke(this, new AuditCompletedEventArgs(result));
            ReportProgress($"{(fastScan ? "Fast" : "Full")} scan completed.");
            _diagnosticLogService.Write(
                $"Audit completed: type={(fastScan ? "fast" : "full")}, events={events.Count}, issues={issues.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _diagnosticLogService.Write(
                $"Audit canceled: type={(fastScan ? "fast" : "full")}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            throw;
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException(
                $"Audit failed: type={(fastScan ? "fast" : "full")}, elapsedMs={stopwatch.ElapsedMilliseconds}",
                ex);
            AuditFailed?.Invoke(this, new AuditFailedEventArgs(ex.Message));
            return false;
        }
        finally
        {
            _auditGate.Release();
        }
    }

    private void ReportProgress(string message)
    {
        AuditProgress?.Invoke(this, new AuditProgressEventArgs(message));
    }

    public void Dispose()
    {
        _settingsService.SettingsChanged -= OnSettingsChanged;
        _auditGate.Dispose();
    }

    private int CalculateHealthScore(System.Collections.Generic.List<AuditIssue> issues)
    {
        if (issues.Count == 0)
        {
            return 100;
        }

        // Calculate score based on issue count and severity
        int highCount = issues.Count(i => i.Severity == "High");
        int mediumCount = issues.Count(i => i.Severity == "Medium");
        int lowCount = issues.Count(i => i.Severity == "Low");

        // Deduct points: High=-20, Medium=-10, Low=-5
        int deduction = (highCount * 20) + (mediumCount * 10) + (lowCount * 5);

        int score = Math.Max(0, 100 - deduction);

        return score;
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
