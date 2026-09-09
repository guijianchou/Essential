using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
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
        _ => "Finish"
    });
    public AuditStepState State => _progress.State;
    public bool IsActive => State == AuditStepState.Active;
    public bool IsDone => State == AuditStepState.Done;
    public bool IsFailed => State == AuditStepState.Failed;
    public bool IsInactive => State is AuditStepState.Pending or AuditStepState.Skipped;
    public string InactiveGlyph => State == AuditStepState.Skipped ? "\uE738" : "\uEA3A";
    public bool HasConnector => Stage != AuditStage.Complete;
    public bool HasCompletedConnector => HasConnector && IsDone;
    public string Detail => _progress.BatchNumber > 0
        ? AppText.Format("Step {0}: {1}", _progress.BatchNumber, _progress.Message) : _progress.Message;
    public string Tooltip => $"{Title} {PercentText}: {Detail}";
    public bool HasBatchProgress => ShowText && _total > 0;
    public string StatusText => State switch
    {
        AuditStepState.Done => AppText.Get("Done"),
        AuditStepState.Failed => AppText.Get("Failed"),
        AuditStepState.Skipped => AppText.Get("Skipped"),
        AuditStepState.Active => _total > 0 ? PercentText : AppText.Get("Active"),
        _ => AppText.Get("Pending")
    };
    public double Percent => IsDone ? 100 : _total == 0 ? 0 : Math.Clamp(100d * _completed / _total, 0, 100);
    public string PercentText => IsDone || _total > 0 ? AppText.Format("{0:0}%", Math.Floor(Percent)) : "--";
    public double CompletionFraction => State == AuditStepState.Skipped && (Stage != AuditStage.Translate || _total == 0) ? 1 : Percent / 100;
    public string BatchText => AppText.Format(Stage == AuditStage.Collect ? "{0}/{1} groups" : "{0}/{1} steps", _completed, _total);
    public double RowHeight => 36;

    public bool Update(AuditProgressEventArgs progress)
    {
        if ((State is AuditStepState.Done or AuditStepState.Failed or AuditStepState.Skipped)
            && progress.State == AuditStepState.Active) return false;
        int total = progress.TotalBatches > 0 ? progress.TotalBatches : progress.TotalUnits;
        int completed = progress.TotalBatches > 0 ? progress.CompletedBatches : progress.CompletedUnits;
        // Concurrent requests can finish in a different order from their progress reports.
        if (progress.State == AuditStepState.Active && total > 0 && completed < _completed) return false;
        if (progress.State == AuditStepState.Active && State == progress.State && total == 0
            && progress.MessageKey == _progress.MessageKey && progress.BatchNumber == _progress.BatchNumber
            && progress.Arguments.SequenceEqual(_progress.Arguments)) return false;
        _progress = progress;
        _total = Math.Max(_total, total);
        _completed = IsDone ? _total : Math.Clamp(Math.Max(_completed, completed), 0, _total);
        Refresh();
        return true;
    }

    public void Reset()
    {
        _completed = _total = 0;
        _progress = new(Stage, AuditStepState.Pending, "Pending");
        Refresh();
    }

    partial void OnShowTextChanged(bool value)
    {
        OnPropertyChanged(nameof(HasBatchProgress));
        OnPropertyChanged(nameof(RowHeight));
    }
    public void Refresh() => OnPropertyChanged(string.Empty);
}

[Microsoft.UI.Xaml.Data.Bindable]
public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly AuditSchedulerService _scheduler;
    private readonly DispatcherQueue? _dispatcher = DispatcherQueue.GetForCurrentThread();
    private bool _hasRun;
    private DateTime? _savedAt;
    private int _scanVersion;
    private bool _isDisposed;

    public IReadOnlyList<ScanStep> Steps { get; } = Enum.GetValues<AuditStage>().Select(stage => new ScanStep(stage)).ToList();

    [ObservableProperty]
    private bool isPaneOpen = true;

    [ObservableProperty]
    private string workflowTitle = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(WorkflowTooltip))]
    private ScanStep? selectedStep;

    public bool IsWorkflowVisible => _hasRun;
    public string SavedText => _savedAt.HasValue ? AppText.Format("Saved at {0:t}", _savedAt.Value) : string.Empty;
    public bool HasSavedResult => _savedAt.HasValue;
    public string PaneToggleText => AppText.Get(IsPaneOpen ? "Collapse sidebar" : "Expand sidebar");
    public string PaneToggleGlyph => "\uE700";
    public bool IsWorkflowFailed => Steps.Take(4).Any(step => step.IsFailed);
    public bool IsTranslationPending => Steps[(int)AuditStage.Translate].IsFailed
        || Steps[(int)AuditStage.Translate].State == AuditStepState.Skipped
            && Steps[(int)AuditStage.Translate].CompletionFraction < 1;
    public string WorkflowGlyph => IsWorkflowFailed ? "\uEA39" : IsTranslationPending ? "\uE7BA"
        : Steps.Any(step => step.IsActive) ? "\uE895" : _savedAt.HasValue ? "\uE73E" : "\uEA3A";
    public string WorkflowTooltip => $"{WorkflowTitle} {WorkflowPercentText}\n{SelectedStep?.Tooltip}\n{SavedText}".Trim();
    public double WorkflowPercent => !_hasRun ? 0 : Math.Min(Steps.Any(step => step.IsFailed) ? 99 : 100,
        Math.Floor(100 * Steps.Sum(step => step.CompletionFraction) / Steps.Count));
    public string WorkflowPercentText => AppText.Format("{0:0}%", WorkflowPercent);
    public string WorkflowCountText => AppText.Format("{0}/{1} stages", Steps.Count(step => step.IsDone
        || step.State == AuditStepState.Skipped && step.CompletionFraction == 1), Steps.Count);
    public string WorkflowProgressLabel => AppText.Get("Stage completion");
    public string ModeText => AppText.Get(LocalSecurityAudit.Models.AppMode.Label(_scheduler.ActiveMode));
    public string WindowTitle => $"{AppText.Get("Local Security Audit")} · {ModeText}";

    public MainViewModel(AuditSchedulerService scheduler)
    {
        _scheduler = scheduler;
        _scheduler.AuditProgress += OnProgress;
        AppText.Current.LanguageChanged += OnLanguageChanged;
    }

    private void OnProgress(object? sender, AuditProgressEventArgs progress)
    {
        int version = progress.StartsScan && progress.Stage == AuditStage.Collect && progress.State == AuditStepState.Active
            ? Interlocked.Increment(ref _scanVersion) : Volatile.Read(ref _scanVersion);
        if (_dispatcher is { HasThreadAccess: false })
            _dispatcher.TryEnqueue(() => ApplyCurrentProgress(progress, version));
        else ApplyCurrentProgress(progress, version);
    }

    private void ApplyCurrentProgress(AuditProgressEventArgs progress, int version)
    {
        // A new scan can start before the previous scan's UI callbacks have drained.
        if (!_isDisposed && version == Volatile.Read(ref _scanVersion)) ApplyProgress(progress);
    }

    internal void ApplyProgress(AuditProgressEventArgs progress)
    {
        if (progress.StartsScan && progress.Stage == AuditStage.Collect && progress.State == AuditStepState.Active)
        {
            _hasRun = true;
            _savedAt = null;
            foreach (var scanStep in Steps) scanStep.Reset();
            OnPropertyChanged(nameof(IsWorkflowVisible));
        }
        else if (IsWorkflowFailed) return;
        var step = Steps[(int)progress.Stage];
        bool enteringStage = step.State == AuditStepState.Pending && progress.State == AuditStepState.Active;
        if (!step.Update(progress)) return;
        if (SelectedStep == null || progress.StartsScan || enteringStage || progress.State == AuditStepState.Failed
            || progress.Stage == AuditStage.Complete && progress.State == AuditStepState.Done)
            SelectedStep = step;
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
        void RefreshLanguage()
        {
            foreach (var step in Steps) step.Refresh();
            Refresh();
        }
        if (_dispatcher is { HasThreadAccess: false }) _dispatcher.TryEnqueue(RefreshLanguage);
        else RefreshLanguage();
    }

    private void Refresh()
    {
        OnPropertyChanged(nameof(WindowTitle));
        OnPropertyChanged(nameof(ModeText));
        WorkflowTitle = AppText.Get(!_hasRun ? string.Empty
            : IsWorkflowFailed ? "Scan failed"
            : IsTranslationPending ? "Translation pending"
            : Steps[(int)AuditStage.Complete].IsDone ? "Scan complete"
            : _savedAt.HasValue ? "Scan saved" : "Scanning");
        OnPropertyChanged(nameof(IsWorkflowFailed));
        OnPropertyChanged(nameof(IsTranslationPending));
        OnPropertyChanged(nameof(WorkflowGlyph));
        OnPropertyChanged(nameof(WorkflowTooltip));
        OnPropertyChanged(nameof(SavedText));
        OnPropertyChanged(nameof(HasSavedResult));
        OnPropertyChanged(nameof(PaneToggleText));
        OnPropertyChanged(nameof(WorkflowPercent));
        OnPropertyChanged(nameof(WorkflowPercentText));
        OnPropertyChanged(nameof(WorkflowCountText));
        OnPropertyChanged(nameof(WorkflowProgressLabel));
    }

    public void Dispose()
    {
        _isDisposed = true;
        _scheduler.AuditProgress -= OnProgress;
        AppText.Current.LanguageChanged -= OnLanguageChanged;
    }
}
