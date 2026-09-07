using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
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
    private int languageIndex;

    [ObservableProperty]
    private int scanIntervalIndex;

    [ObservableProperty]
    private int fastScanRangeIndex;

    [ObservableProperty]
    private int retentionDaysIndex;

    [ObservableProperty]
    private string databaseSize = AppText.Get("Calculating...");

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
    private string policyStatusText = AppText.Get("Built-in policy");

    [ObservableProperty]
    private ObservableCollection<AiTarget> aiTargets = new();

    // Request pipeline summary, derived from the active target and the scan settings.
    [ObservableProperty]
    private string pipelineCollectText = "";

    [ObservableProperty]
    private string pipelineBatchText = "";

    [ObservableProperty]
    private string pipelineAnalyzeText = "";

    [ObservableProperty]
    private string pipelineParseText = "";

    [ObservableProperty]
    private string pipelineStoreText = "";

    [ObservableProperty]
    private string activeTargetSummary = "";

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

        AiTargets.CollectionChanged += OnTargetsCollectionChanged;
        AppText.Current.LanguageChanged += (_, _) =>
        {
            UpdatePipelineSummary();
            UpdatePolicyStatus(AgentInstructions);
        };
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
            ShowStatus(InfoBarSeverity.Success, AppText.Get("Settings saved. They apply to the next audit."));
            UpdatePipelineSummary();
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Save failed: {0}", ex.Message));
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
        ShowStatus(InfoBarSeverity.Informational, AppText.Get("Defaults restored. Save to apply them."));
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
        LanguageIndex = defaults.Language == "zh-CN" ? 1 : 0;
        ShowStatus(InfoBarSeverity.Informational, AppText.Get("Appearance defaults restored. Save to apply them."));
    }

    [RelayCommand]
    private void ResetAiSettings()
    {
        var defaults = _settingsService.CreateDefaultSettings();
        AgentInstructions = defaults.AgentInstructions;
        LoadTargets(defaults.AiTargets);
        ShowStatus(InfoBarSeverity.Informational, AppText.Get("AI defaults restored. Save to apply them."));
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
        ShowStatus(InfoBarSeverity.Informational, AppText.Get("Scanning defaults restored. Save to apply them."));
    }

    [RelayCommand]
    private void ResetAgentInstructions()
    {
        AgentInstructions = SettingsService.DefaultAgentInstructions;
        ShowStatus(InfoBarSeverity.Informational, AppText.Get("Built-in audit policy restored. Save to apply it."));
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
                $"{target.Name}: {result.Message}");
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Connection test failed: {0}", ex.Message));
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
            ShowStatus(InfoBarSeverity.Success, AppText.Get("Old data cleaned"));
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Cleanup failed: {0}", ex.Message));
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
            ShowStatus(InfoBarSeverity.Success, AppText.Get("Database optimized"));
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Optimization failed: {0}", ex.Message));
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void AddTarget()
    {
        if (AiTargets.Count >= 2)
        {
            ShowStatus(InfoBarSeverity.Informational, AppText.Get("AI Hub keeps only Main and the optional Fallback route."));
            return;
        }

        AiTargets.Add(new AiTarget
        {
            Name = AiTargetSettings.FallbackName,
            IsActive = false,
            BaseUrl = "",
            ApiKey = "",
            Mode = "responses",
            Model = AiTargetSettings.LunaModel,
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

        if (string.Equals(target.Name, AiTargetSettings.FallbackName, StringComparison.OrdinalIgnoreCase))
        {
            target.BaseUrl = string.Empty;
            target.ApiKey = string.Empty;
            target.Mode = "responses";
            target.Model = AiTargetSettings.LunaModel;
            target.Effort = "medium";
            ShowStatus(InfoBarSeverity.Informational, AppText.Get("Fallback route cleared. Main remains the only active route."));
            return;
        }

        ShowStatus(InfoBarSeverity.Warning, AppText.Get("Main is required. Clear its URL only if you intend to stop audits."));
    }

    [RelayCommand]
    private void SetActiveTarget(AiTarget? target)
    {
        if (target == null || string.Equals(target.Name, AiTargetSettings.FallbackName, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        target.IsActive = true;

        UpdatePipelineSummary();
    }

    partial void OnAgentInstructionsChanged(string value)
    {
        UpdatePolicyStatus(value);
    }

    partial void OnFastScanRangeIndexChanged(int value)
    {
        UpdatePipelineSummary();
    }

    private void UpdatePolicyStatus(string value)
    {
        string normalized = (value ?? string.Empty).Replace("\r\n", "\n").Trim();
        string builtIn = SettingsService.DefaultAgentInstructions.Replace("\r\n", "\n").Trim();
        if (normalized == builtIn)
        {
            PolicyStatusText = AppText.Get("Built-in policy");
        }
        else if (SettingsService.IsLegacyDefaultPolicy(value))
        {
            PolicyStatusText = AppText.Get("Older built-in policy. Reset to get the current contract.");
        }
        else
        {
            PolicyStatusText = AppText.Format("Custom policy, {0:N0} characters", normalized.Length);
        }
    }

    private void OnTargetsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.OldItems != null)
        {
            foreach (AiTarget target in e.OldItems)
            {
                target.PropertyChanged -= OnTargetPropertyChanged;
            }
        }

        if (e.NewItems != null)
        {
            foreach (AiTarget target in e.NewItems)
            {
                target.PropertyChanged += OnTargetPropertyChanged;
            }
        }

        UpdatePipelineSummary();
    }

    private void OnTargetPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(AiTarget.IsExpanded) or nameof(AiTarget.ApiKey))
        {
            return;
        }

        UpdatePipelineSummary();
    }

    /// <summary>Describes the request chain from event logs to dashboard using the active endpoint.</summary>
    private void UpdatePipelineSummary()
    {
        var target = AiTargets.FirstOrDefault(candidate => candidate.IsActive) ?? AiTargets.FirstOrDefault();
        var settings = _settingsService.Current;

        string window = FastScanRangeIndex switch
        {
            0 => AppText.Get("the past hour"),
            1 => AppText.Get("the past 2 hours"),
            2 => AppText.Get("the past 4 hours"),
            _ => AppText.Get("everything since the last scan")
        };
        PipelineCollectText = AppText.Format("Security, System, Application and Firewall logs. Fast scans cover {0}; full scans cover 24 hours.", window);

        string parallel = settings.MaxConcurrentAnalysis > 1
            ? AppText.Format("up to {0} requests in parallel", settings.MaxConcurrentAnalysis)
            : AppText.Get("one request at a time");
        string filtering = settings.EnableSmartFiltering
            ? AppText.Get("Routine events are filtered out, then")
            : AppText.Get("All events are kept, then");
        PipelineBatchText = AppText.Format("{0} sent in batches of 20 to 50 events, {1}; cache is checked before each request.", filtering, parallel);

        if (target == null || string.IsNullOrWhiteSpace(target.BaseUrl))
        {
            ActiveTargetSummary = AppText.Get("No endpoint configured");
            PipelineAnalyzeText = AppText.Get("Add an endpoint below to enable analysis.");
        }
        else
        {
            string host = Uri.TryCreate(target.BaseUrl.Trim(), UriKind.Absolute, out var uri) ? uri.Host : target.BaseUrl.Trim();
            string route = string.Equals(target.Mode, "chat", StringComparison.OrdinalIgnoreCase)
                ? "POST /v1/chat/completions"
                : "POST /v1/responses";
            string key = string.IsNullOrWhiteSpace(target.ApiKey) ? AppText.Get("no API key") : AppText.Get("API key set");
            var fallback = AiTargets.FirstOrDefault(candidate =>
                string.Equals(candidate.Name, AiTargetSettings.FallbackName, StringComparison.OrdinalIgnoreCase));
            string fallbackSummary = fallback == null || string.IsNullOrWhiteSpace(fallback.BaseUrl)
                ? AppText.Get("fallback empty")
                : AppText.Format("fallback {0}", fallback.BaseUrl);
            ActiveTargetSummary = $"{target.Name}: {host}, {key}; {fallbackSummary}";
            PipelineAnalyzeText = AppText.Format("Luna ({0}) at {1} via streaming {2}, reasoning effort {3}, 256k context; failover uses the optional fallback route.", target.Model, host, route, target.Effort);
        }

        PipelineParseText = AppText.Get("English and Chinese analysis are validated together. Categories and severities are normalized, repeated patterns are merged.");
        PipelineStoreText = AppText.Get("Findings and the health score are saved to the local SQLite database and shown on the dashboard and trends.");
    }

    private void LoadFromSettings(AppSettings settings)
    {
        LanguageIndex = settings.Language == "zh-CN" ? 1 : 0;
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
        UpdatePolicyStatus(AgentInstructions);

        LoadTargets(settings.AiTargets);
    }

    private void LoadTargets(IEnumerable<AiTargetSettings> targets)
    {
        AiTargets.Clear();
        foreach (var target in targets.Take(2))
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

        while (AiTargets.Count < 2)
        {
            AiTargets.Add(new AiTarget
            {
                Name = AiTargets.Count == 0 ? AiTargetSettings.MainName : AiTargetSettings.FallbackName,
                IsActive = AiTargets.Count == 0,
                BaseUrl = AiTargets.Count == 0 ? "" : "",
                ApiKey = "",
                Mode = "responses",
                Model = AiTargetSettings.LunaModel,
                Effort = "medium",
                IsExpanded = false
            });
        }

        UpdatePipelineSummary();
    }

    private AppSettings ToSettings()
    {
        return new AppSettings
        {
            Language = LanguageIndex == 1 ? "zh-CN" : "en",
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
            MaxConcurrentAnalysis = _settingsService.Current.MaxConcurrentAnalysis,
            EnableSmartFiltering = _settingsService.Current.EnableSmartFiltering,
            EnableCaching = _settingsService.Current.EnableCaching,
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
