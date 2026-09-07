using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Dispatching;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

[Microsoft.UI.Xaml.Data.Bindable]
public sealed partial class ScanStep : ObservableObject
{
    public AuditStage Stage { get; }
    private AuditProgressEventArgs _progress;
    private int _completed;
    private int _total;

    [ObservableProperty]
    private bool showText = true;

    public ScanStep(AuditStage stage)
    {
        Stage = stage;
        _progress = new(stage, AuditStepState.Pending, "Pending");
    }

    public string Title => AppText.Get(Stage switch
    {
        AuditStage.Collect => "Read event logs",
        AuditStage.Route => "AI router",
        AuditStage.Analyze => "Bilingual analysis",
        AuditStage.Save => "Save results",
        AuditStage.Translate => "Historical translation",
        _ => "Complete"
    });
    public AuditStepState State => _progress.State;
    public bool IsActive => State == AuditStepState.Active;
    public bool IsDone => State == AuditStepState.Done;
    public bool IsFailed => State == AuditStepState.Failed;
    public bool IsInactive => State is AuditStepState.Pending or AuditStepState.Skipped;
    public string InactiveGlyph => State == AuditStepState.Skipped ? "\uE738" : "\uEA3A";
    public bool HasConnector => Stage != AuditStage.Complete;
    public string Detail => _progress.Message;
    public string Tooltip => $"{Title}: {Detail}";
    public bool HasBatchProgress => ShowText && _total > 0;
    public double Percent => _total == 0 ? 0 : 100d * _completed / _total;
    public string BatchText => AppText.Format("{0}/{1} batches", _completed, _total);

    public void Update(AuditProgressEventArgs progress)
    {
        // Concurrent requests can finish in a different order from their progress reports.
        if (progress.TotalBatches > 0 && progress.CompletedBatches < _completed) return;
        _progress = progress;
        _completed = Math.Max(_completed, progress.CompletedBatches);
        _total = Math.Max(_total, progress.TotalBatches);
        Refresh();
    }

    public void Reset()
    {
        _completed = _total = 0;
        _progress = new(Stage, AuditStepState.Pending, "Pending");
        Refresh();
    }

    partial void OnShowTextChanged(bool value) => OnPropertyChanged(nameof(HasBatchProgress));
    public void Refresh() => OnPropertyChanged(string.Empty);
}

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly AuditSchedulerService _scheduler;
    private readonly DispatcherQueue? _dispatcher = DispatcherQueue.GetForCurrentThread();
    private bool _hasRun;
    private DateTime? _savedAt;

    public IReadOnlyList<ScanStep> Steps { get; } = Enum.GetValues<AuditStage>().Select(stage => new ScanStep(stage)).ToList();

    [ObservableProperty]
    private bool isPaneOpen = true;

    [ObservableProperty]
    private string workflowTitle = AppText.Get("Ready to scan");

    public string SavedText => _savedAt.HasValue ? AppText.Format("Saved at {0:t}", _savedAt.Value) : string.Empty;
    public bool HasSavedResult => _savedAt.HasValue;
    public string PaneToggleText => AppText.Get(IsPaneOpen ? "Collapse sidebar" : "Expand sidebar");
    public string PaneToggleGlyph => IsPaneOpen ? "\uE76B" : "\uE76C";

    public MainViewModel(AuditSchedulerService scheduler)
    {
        _scheduler = scheduler;
        _scheduler.AuditProgress += OnProgress;
        AppText.Current.LanguageChanged += OnLanguageChanged;
    }

    public async Task LoadSavedTimeAsync(DataStorageService storage)
    {
        try
        {
            var latest = await storage.GetLatestResultAsync();
            if (!_hasRun && latest != null)
            {
                _savedAt = latest.Timestamp.ToLocalTime();
                Refresh();
            }
        }
        catch { /* The dashboard reports storage errors. */ }
    }

    private void OnProgress(object? sender, AuditProgressEventArgs progress)
    {
        if (_dispatcher is { HasThreadAccess: false })
            _dispatcher.TryEnqueue(() => ApplyProgress(progress));
        else ApplyProgress(progress);
    }

    internal void ApplyProgress(AuditProgressEventArgs progress)
    {
        if (progress.Stage == AuditStage.Collect && progress.State == AuditStepState.Active)
        {
            _hasRun = true;
            _savedAt = null;
            foreach (var step in Steps) step.Reset();
        }
        Steps[(int)progress.Stage].Update(progress);
        if (progress.Stage == AuditStage.Save && progress.State == AuditStepState.Done)
            _savedAt = progress.Arguments.FirstOrDefault() is DateTime savedAt ? savedAt : DateTime.Now;
        Refresh();
    }

    partial void OnIsPaneOpenChanged(bool value)
    {
        foreach (var step in Steps) step.ShowText = value;
        OnPropertyChanged(nameof(PaneToggleText));
        OnPropertyChanged(nameof(PaneToggleGlyph));
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        if (_dispatcher is { HasThreadAccess: false }) _dispatcher.TryEnqueue(Refresh);
        else Refresh();
    }

    private void Refresh()
    {
        WorkflowTitle = AppText.Get(!_hasRun ? "Ready to scan"
            : Steps.Take(4).Any(step => step.IsFailed) ? "Scan failed"
            : Steps[(int)AuditStage.Translate].IsFailed ? "Translation pending"
            : _savedAt.HasValue ? "Scan saved" : "Scanning");
        foreach (var step in Steps) step.Refresh();
        OnPropertyChanged(nameof(SavedText));
        OnPropertyChanged(nameof(HasSavedResult));
        OnPropertyChanged(nameof(PaneToggleText));
    }

    public void Dispose()
    {
        _scheduler.AuditProgress -= OnProgress;
        AppText.Current.LanguageChanged -= OnLanguageChanged;
    }
}
