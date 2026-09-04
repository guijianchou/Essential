using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Dispatching;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly DataStorageService _storageService;
    private readonly SettingsService _settingsService;
    private readonly AiAnalysisService _aiAnalysisService;
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly DispatcherQueue? _dispatcherQueue;

    [ObservableProperty]
    private bool showOperationStatus;

    [ObservableProperty]
    private InfoBarSeverity operationSeverity = InfoBarSeverity.Informational;

    [ObservableProperty]
    private string operationMessage = "";

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private bool autoScanEnabled;

    [ObservableProperty]
    private bool minimizeToTray;

    [ObservableProperty]
    private int themeIndex;

    [ObservableProperty]
    private int scanIntervalIndex;

    [ObservableProperty]
    private int fastScanRangeIndex;

    [ObservableProperty]
    private int retentionDaysIndex;

    [ObservableProperty]
    private string databaseSize = "Calculating...";

    [ObservableProperty]
    private int auditRecordCount;

    [ObservableProperty]
    private bool highSeverityNotification;

    [ObservableProperty]
    private bool scanCompleteNotification;

    [ObservableProperty]
    private bool diagnosticLoggingEnabled;

    [ObservableProperty]
    private string agentInstructions = "";

    [ObservableProperty]
    private ObservableCollection<AiTarget> aiTargets = new();

    public string AgentInstructionsPath => _settingsService.AgentInstructionsPath;
    public string DiagnosticLogPath => _diagnosticLogService.LogPath;

    public SettingsViewModel(
        DataStorageService storageService,
        SettingsService settingsService,
        AiAnalysisService aiAnalysisService,
        DiagnosticLogService diagnosticLogService)
    {
        _storageService = storageService;
        _settingsService = settingsService;
        _aiAnalysisService = aiAnalysisService;
        _diagnosticLogService = diagnosticLogService;
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();

        LoadFromSettings(_settingsService.Current);
        _ = UpdateDatabaseStatsAsync();
    }

    [RelayCommand]
    private async Task SaveSettingsAsync()
    {
        if (IsBusy)
        {
            return;
        }

        try
        {
            IsBusy = true;
            _settingsService.Save(ToSettings());
            ShowStatus(InfoBarSeverity.Success, "Settings saved");
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, $"Save failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void ResetSettings()
    {
        LoadFromSettings(_settingsService.CreateDefaultSettings());
        ShowStatus(InfoBarSeverity.Informational, "Defaults restored. Save to apply them.");
    }

    [RelayCommand]
    private void ResetAppearanceSettings()
    {
        var defaults = _settingsService.CreateDefaultSettings();
        ThemeIndex = defaults.Theme switch
        {
            "light" => 1,
            "dark" => 2,
            _ => 0
        };
        MinimizeToTray = defaults.MinimizeToTray;
        ShowStatus(InfoBarSeverity.Informational, "Appearance defaults restored. Save to apply them.");
    }

    [RelayCommand]
    private void ResetAiSettings()
    {
        var defaults = _settingsService.CreateDefaultSettings();
        AgentInstructions = defaults.AgentInstructions;
        LoadTargets(defaults.AiTargets);
        ShowStatus(InfoBarSeverity.Informational, "AI defaults restored. Save to apply them.");
    }

    [RelayCommand]
    private void ResetScanningSettings()
    {
        var defaults = _settingsService.CreateDefaultSettings();
        AutoScanEnabled = defaults.AutoScanEnabled;
        ScanIntervalIndex = defaults.ScanIntervalHours switch
        {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            24 => 4,
            _ => 2
        };
        FastScanRangeIndex = defaults.FastScanRangeHours switch
        {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => 3
        };
        HighSeverityNotification = defaults.HighSeverityNotification;
        ScanCompleteNotification = defaults.ScanCompleteNotification;
        DiagnosticLoggingEnabled = defaults.DiagnosticLoggingEnabled;
        ShowStatus(InfoBarSeverity.Informational, "Scanning defaults restored. Save to apply them.");
    }

    [RelayCommand]
    private void ResetAgentInstructions()
    {
        AgentInstructions = SettingsService.DefaultAgentInstructions;
        ShowStatus(InfoBarSeverity.Informational, "Default AGENTS.md policy restored. Save to apply it.");
    }

    [RelayCommand]
    private async Task TestApiConnectionAsync(AiTarget? target)
    {
        if (target == null || IsBusy)
        {
            return;
        }

        try
        {
            IsBusy = true;
            var result = await _aiAnalysisService.TestConnectionAsync(target);
            ShowStatus(
                result.Success ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
                result.Message);
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, $"Connection test failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task CleanupDataAsync()
    {
        if (IsBusy)
        {
            return;
        }

        try
        {
            IsBusy = true;
            await _storageService.CleanupOldDataAsync(GetRetentionDays());
            await UpdateDatabaseStatsAsync();
            ShowStatus(InfoBarSeverity.Success, "Old data cleaned");
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, $"Cleanup failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task VacuumDatabaseAsync()
    {
        if (IsBusy)
        {
            return;
        }

        try
        {
            IsBusy = true;
            await _storageService.VacuumDatabaseAsync();
            await UpdateDatabaseStatsAsync();
            ShowStatus(InfoBarSeverity.Success, "Database optimized");
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, $"Optimization failed: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void AddTarget()
    {
        AiTargets.Add(new AiTarget
        {
            Name = $"Target {AiTargets.Count + 1}",
            IsActive = !AiTargets.Any(target => target.IsActive),
            BaseUrl = "",
            ApiKey = "",
            Mode = "responses",
            Model = "gpt-5.6-sol",
            Effort = "medium",
            IsExpanded = true
        });
    }

    [RelayCommand]
    private void RemoveTarget(AiTarget? target)
    {
        if (target == null)
        {
            return;
        }

        if (AiTargets.Count > 1)
        {
            AiTargets.Remove(target);
            if (!AiTargets.Any(candidate => candidate.IsActive))
            {
                AiTargets[0].IsActive = true;
            }
            return;
        }

        ShowStatus(InfoBarSeverity.Warning, "At least one AI target is required");
    }

    [RelayCommand]
    private void SetActiveTarget(AiTarget? target)
    {
        if (target == null)
        {
            return;
        }

        foreach (var candidate in AiTargets)
        {
            candidate.IsActive = ReferenceEquals(candidate, target);
        }
    }

    private void LoadFromSettings(AppSettings settings)
    {
        AutoScanEnabled = settings.AutoScanEnabled;
        MinimizeToTray = settings.MinimizeToTray;
        ThemeIndex = settings.Theme switch
        {
            "light" => 1,
            "dark" => 2,
            _ => 0
        };
        ScanIntervalIndex = settings.ScanIntervalHours switch
        {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            24 => 4,
            _ => 2
        };
        FastScanRangeIndex = settings.FastScanRangeHours switch
        {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => 3
        };
        RetentionDaysIndex = settings.RetentionDays switch
        {
            3 => 0,
            7 => 1,
            14 => 2,
            30 => 3,
            _ => 1
        };
        HighSeverityNotification = settings.HighSeverityNotification;
        ScanCompleteNotification = settings.ScanCompleteNotification;
        DiagnosticLoggingEnabled = settings.DiagnosticLoggingEnabled;
        AgentInstructions = settings.AgentInstructions;

        LoadTargets(settings.AiTargets);
    }

    private void LoadTargets(System.Collections.Generic.IEnumerable<AiTargetSettings> targets)
    {
        AiTargets.Clear();
        foreach (var target in targets)
        {
            AiTargets.Add(new AiTarget
            {
                Name = target.Name,
                IsActive = target.IsActive,
                BaseUrl = target.BaseUrl,
                ApiKey = target.ApiKey,
                Mode = target.Mode,
                Model = target.Model,
                Effort = target.Effort,
                IsExpanded = false
            });
        }
    }

    private AppSettings ToSettings()
    {
        return new AppSettings
        {
            Theme = ThemeIndex switch
            {
                1 => "light",
                2 => "dark",
                _ => "system"
            },
            MinimizeToTray = MinimizeToTray,
            AutoScanEnabled = AutoScanEnabled,
            ScanIntervalHours = new[] { 1, 2, 4, 8, 24 }.ElementAtOrDefault(ScanIntervalIndex) is var scanHours and > 0
                ? scanHours
                : 4,
            FastScanRangeHours = FastScanRangeIndex switch
            {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 0
            },
            RetentionDays = GetRetentionDays(),
            HighSeverityNotification = HighSeverityNotification,
            ScanCompleteNotification = ScanCompleteNotification,
            DiagnosticLoggingEnabled = DiagnosticLoggingEnabled,
            AgentInstructions = AgentInstructions,
            AiTargets = AiTargets.Select(target => new AiTargetSettings
            {
                Name = target.Name,
                IsActive = target.IsActive,
                BaseUrl = target.BaseUrl,
                ApiKey = target.ApiKey,
                Mode = target.Mode,
                Model = target.Model,
                Effort = target.Effort
            }).ToList()
        };
    }

    private int GetRetentionDays()
    {
        return RetentionDaysIndex switch
        {
            0 => 3,
            2 => 14,
            3 => 30,
            _ => 7
        };
    }

    private void ShowStatus(InfoBarSeverity severity, string message)
    {
        OperationSeverity = severity;
        OperationMessage = message;
        ShowOperationStatus = true;
    }

    private async Task UpdateDatabaseStatsAsync()
    {
        try
        {
            var dbPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LocalSecurityAudit",
                "audit_data.db");

            string databaseSize = File.Exists(dbPath)
                ? $"{new FileInfo(dbPath).Length / (1024.0 * 1024.0):F2} MB"
                : "0 MB";
            int auditRecordCount = await _storageService.GetAuditRecordCountAsync();
            UpdateDatabaseStats(databaseSize, auditRecordCount);
        }
        catch
        {
            UpdateDatabaseStats("Unknown", 0);
        }
    }

    private void UpdateDatabaseStats(string databaseSize, int auditRecordCount)
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
        {
            _dispatcherQueue.TryEnqueue(() => UpdateDatabaseStats(databaseSize, auditRecordCount));
            return;
        }

        DatabaseSize = databaseSize;
        AuditRecordCount = auditRecordCount;
    }
}
