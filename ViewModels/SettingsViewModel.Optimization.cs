using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

public partial class SettingsViewModel
{
    private int _optimizationPreviewVersion;
    private int _optimizationRunVersion;
    public IReadOnlyList<string> OptimizationModels => AiModelCatalog.OptimizationModels;
    [ObservableProperty] private string optimizationModel = AiModelCatalog.Astra;
    [ObservableProperty] private string optimizationPreviewText = string.Empty;
    [ObservableProperty] private string optimizationLegacyText = string.Empty;
    [ObservableProperty] private string optimizationStatus = string.Empty;
    [ObservableProperty] private double optimizationPercent;
    [ObservableProperty] private bool showOptimizationProgress;
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OptimizeHistoryCommand))]
    private bool isOptimizing;
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OptimizeHistoryCommand))]
    private int eligibleOptimizationCount;

    partial void OnOptimizationModelChanged(string value) => _ = RefreshOptimizationPreviewAsync();
    private bool CanOptimizeHistory() => IsExtendedMode && !IsOptimizing && EligibleOptimizationCount > 0;

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task RefreshOptimizationPreviewAsync()
    {
        if (IsAssistantMode) return;
        int version = ++_optimizationPreviewVersion;
        string model = OptimizationModel;
        EligibleOptimizationCount = 0;
        try
        {
            var records = await Task.Run(() => _storageService.GetOptimizationRecordsAsync());
            if (version != _optimizationPreviewVersion) return;
            var findings = records.SelectMany(record => record.Findings).ToList();
            EligibleOptimizationCount = findings.Count(issue => AiModelCatalog.CanOptimize(issue.AnalysisModel, model));
            OptimizationPreviewText = AppText.Format("{0} eligible / {1} protected findings", EligibleOptimizationCount, findings.Count - EligibleOptimizationCount);
            OptimizationLegacyText = AppText.Format("Unlabelled or gateway-alias findings: {0}. Astra only.",
                findings.Count(issue => string.IsNullOrWhiteSpace(issue.AnalysisModel) || issue.AnalysisModel == AiModelCatalog.GatewayAlias));
        }
        catch (Exception ex)
        {
            if (version == _optimizationPreviewVersion) OptimizationPreviewText = AppText.Format("Load failed: {0}", ex.Message);
        }
    }

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanOptimizeHistory))]
    private async Task OptimizeHistoryAsync(CancellationToken cancellationToken)
    {
        if (IsAssistantMode || IsOptimizing) return;
        IsOptimizing = true;
        ShowOptimizationProgress = true;
        OptimizationPercent = 0;
        int version = ++_optimizationRunVersion;
        OptimizationStatus = AppText.Get("Preparing history optimization...");
        try
        {
            int count = await _schedulerService.OptimizeHistoryAsync(OptimizationModel,
                new AuditProgressReporter(value => ApplyOptimizationProgress(value, version)), cancellationToken);
            OptimizationPercent = 100;
            OptimizationStatus = AppText.Format("Saved {0} optimized findings", count);
        }
        catch (OperationCanceledException)
        {
            OptimizationStatus = AppText.Get("Optimization stopped. Completed updates were saved.");
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException("History optimization failed", ex);
            OptimizationStatus = AppText.Format("Optimization failed: {0}", ex.Message);
        }
        finally
        {
            ++_optimizationRunVersion;
            IsOptimizing = false;
            await RefreshOptimizationPreviewAsync();
        }
    }

    private void ApplyOptimizationProgress(AuditProgressEventArgs value, int version)
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
        {
            _dispatcherQueue.TryEnqueue(() => ApplyOptimizationProgress(value, version));
            return;
        }
        if (version != _optimizationRunVersion || !IsOptimizing) return;
        OptimizationStatus = value.Message;
        if (value.TotalUnits > 0) OptimizationPercent = Math.Clamp(100d * value.CompletedUnits / value.TotalUnits, 0, 100);
    }
}
