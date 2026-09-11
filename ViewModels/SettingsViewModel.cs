using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Dispatching;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;
using Windows.ApplicationModel.DataTransfer;

namespace LocalSecurityAudit.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    public string VersionText => AppText.Format("Version {0}", typeof(App).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);

    private readonly DataStorageService _storageService;
    private readonly SettingsService _settingsService;
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly KernelManagerService _kernelManagerService;
    private readonly AuditSchedulerService _schedulerService;
    private readonly DispatcherQueue? _dispatcherQueue;

    [ObservableProperty]
    private int modeIndex;

    public string ActiveModeText => AppText.Get(AppMode.Label(_settingsService.ActiveMode));
    public string DatabasePath => _storageService.DatabasePath;
    public bool IsModeChangePending => _settingsService.Current.Mode != _settingsService.ActiveMode;

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
    private int tokenUsagePeriodIndex;

    [ObservableProperty]
    private int kernelIndex;

    [ObservableProperty]
    private string kernelStatusText = "";

    [ObservableProperty]
    private string kernelPathText = "";

    [ObservableProperty]
    private string kernelLatestText = "";

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
    private string securityAuditInstructions = "";

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

    public string SecurityAuditTaskId => HubTaskCatalog.SecurityAuditId;
    public string SecurityAuditTaskTitle => AppText.Get(HubTaskCatalog.Get(SecurityAuditTaskId).Title);
    public string SecurityAuditTaskGlyph => HubTaskCatalog.Get(SecurityAuditTaskId).Glyph;
    public string SecurityAuditInstructionsPath => _settingsService.GetTaskInstructionsPath(SecurityAuditTaskId);
    public string DiagnosticLogPath => _diagnosticLogService.LogPath;

    public SettingsViewModel(
        DataStorageService storageService,
        SettingsService settingsService,
        DiagnosticLogService diagnosticLogService,
        AuditSchedulerService schedulerService,
        KernelManagerService kernelManagerService)
    {
        _storageService = storageService;
        _settingsService = settingsService;
        _diagnosticLogService = diagnosticLogService;
        _schedulerService = schedulerService;
        _kernelManagerService = kernelManagerService;
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();

        AiTargets.CollectionChanged += OnTargetsCollectionChanged;
        AppText.Current.LanguageChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(VersionText));
            OnPropertyChanged(nameof(ActiveModeText));
            OnPropertyChanged(nameof(SecurityAuditTaskTitle));
            UpdatePipelineSummary();
            UpdateKernelStatus();
            UpdatePolicyStatus(SecurityAuditInstructions);
        };
        LoadFromSettings(_settingsService.Current);
        _schedulerService.HistoryUpdated += (_, _) => _ = UpdateDatabaseStatsAsync();
        _ = UpdateDatabaseStatsAsync();
        UpdateKernelStatus();
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
            OnPropertyChanged(nameof(IsModeChangePending));
            ShowStatus(InfoBarSeverity.Success, AppText.Get(IsModeChangePending
                ? "Mode saved. Fully exit and reopen the app normally from File Explorer to apply it."
                : "Settings saved."));
            UpdatePipelineSummary();
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException("Settings save failed", ex);
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Save failed: {0}", ex.Message));
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task SaveModeAndExitAsync()
    {
        if (IsBusy || _schedulerService.IsScanning)
        {
            ShowStatus(InfoBarSeverity.Warning, AppText.Get("Wait for the current operation to finish before switching modes."));
            return;
        }
        try
        {
            IsBusy = true;
            _settingsService.Save(ToSettings());
            OnPropertyChanged(nameof(IsModeChangePending));
            await App.Current.ExitForModeChangeAsync();
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Save failed: {0}", ex.Message));
        }
        finally { IsBusy = false; }
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
        TokenUsagePeriodIndex = 0;
        ShowStatus(InfoBarSeverity.Informational, AppText.Get("Appearance defaults restored. Save to apply them."));
    }

    [RelayCommand]
    private void ResetAiSettings()
    {
        var defaults = _settingsService.CreateDefaultSettings();
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
    private void ResetSecurityAuditInstructions()
    {
        SecurityAuditInstructions = SettingsService.DefaultSecurityAuditInstructions;
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
            ShowStatus(InfoBarSeverity.Informational, AppText.Format("Testing {0} connection...", SelectedKernel));
            var result = await _schedulerService.TestConnectionAsync(target, SelectedKernel);
            ShowStatus(
                result.Success ? InfoBarSeverity.Success : InfoBarSeverity.Error,
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
    private async Task DownloadKernelAsync()
    {
        if (IsBusy)
        {
            return;
        }
        if (_schedulerService.IsScanning)
        {
            ShowStatus(InfoBarSeverity.Warning, AppText.Get("Wait for the current operation to finish before updating a kernel."));
            return;
        }

        string kernel = SelectedKernel;
        try
        {
            IsBusy = true;
            ShowStatus(InfoBarSeverity.Informational, AppText.Format("Checking {0} versions before downloading...", kernel));
            var result = await _kernelManagerService.DownloadOrUpdateAsync(kernel);
            UpdateKernelStatus();
            KernelLatestText = result.UsedBundledArchive
                ? AppText.Get("Installed from the bundled archive; latest release was not verified.")
                : AppText.Format("Latest official release: {0}", result.LatestVersion);
            string message = result.UsedBundledArchive ? "{0} kernel {1} installed from the bundled archive."
                : result.Changed ? "{0} kernel updated to {1}."
                : KernelManagerService.CompareVersions(result.Status.Version, result.LatestVersion) > 0
                    ? "{0} kernel {1} is newer than the latest official release. No download needed."
                    : "{0} kernel {1} is up to date. No download needed.";
            ShowStatus(InfoBarSeverity.Success, AppText.Format(message, kernel, result.Status.Version));
            _diagnosticLogService.Write($"Kernel update checked: kernel={kernel}, local={result.Status.Version}, latest={result.LatestVersion}, changed={result.Changed}, bundled={result.UsedBundledArchive}");
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException($"Kernel download failed: {kernel}", ex);
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Kernel download failed: {0}", ex.Message));
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task CheckKernelUpdatesAsync()
    {
        if (IsBusy)
        {
            return;
        }

        string kernel = SelectedKernel;
        try
        {
            IsBusy = true;
            await _kernelManagerService.GetStatusAsync(kernel);
            UpdateKernelStatus();
            string latest = await _kernelManagerService.CheckLatestVersionAsync(kernel);
            KernelLatestText = AppText.Format("Latest official release: {0}", latest);
        }
        catch (Exception ex)
        {
            KernelLatestText = AppText.Format("Latest release check failed: {0}", ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RefreshKernelStatusAsync()
    {
        if (IsBusy) return;
        try
        {
            IsBusy = true;
            await _kernelManagerService.GetStatusAsync(SelectedKernel);
            UpdateKernelStatus();
        }
        catch (Exception ex)
        {
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Kernel version check failed: {0}", ex.Message));
        }
        finally { IsBusy = false; }
    }

    public IReadOnlyList<string> KernelOptions => AiKernelCatalog.Kernels;

    private string SelectedKernel => KernelIndex switch
    {
        1 => AiKernelCatalog.Pi,
        _ => AiKernelCatalog.Codex
    };

    partial void OnKernelIndexChanged(int value)
    {
        KernelLatestText = AppText.Get("Latest release not checked.");
        UpdateKernelStatus();
        UpdatePipelineSummary();
    }

    private void UpdateKernelStatus()
    {
        var status = _kernelManagerService.GetStatus(SelectedKernel);
        KernelStatusText = status.Installed
                ? AppText.Format("Installed · {0}", string.IsNullOrEmpty(status.Version) ? AppText.Get("Version not checked") : status.Version)
                : AppText.Get("Not installed · download required");
        KernelPathText = status.Path;
        if (string.IsNullOrEmpty(KernelLatestText)) KernelLatestText = AppText.Get("Latest release not checked.");
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
            ShowStatus(InfoBarSeverity.Error, AppText.Format("Database vacuum failed: {0}", ex.Message));
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

    partial void OnSecurityAuditInstructionsChanged(string value)
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
        string builtIn = SettingsService.DefaultSecurityAuditInstructions.Replace("\r\n", "\n").Trim();
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
        PipelineCollectText = AppText.Format(_settingsService.IsFullMode
            ? "All five Windows log channels, including Security. Incremental progress is shared across modes; higher models reanalyze the selected range. Initial fast range: {0}."
            : "Application, Setup, System and Forwarded Events; Security skipped. Shared incremental progress; higher models reanalyze the selected range. Initial fast range: {0}.", window);

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
            string key = string.IsNullOrWhiteSpace(target.ApiKey) ? AppText.Get("no API key") : AppText.Get("API key set");
            var fallback = AiTargets.FirstOrDefault(candidate =>
                string.Equals(candidate.Name, AiTargetSettings.FallbackName, StringComparison.OrdinalIgnoreCase));
            string fallbackSummary = fallback == null || string.IsNullOrWhiteSpace(fallback.BaseUrl)
                ? AppText.Get("fallback empty")
                : AppText.Format("fallback {0}", fallback.BaseUrl);
            ActiveTargetSummary = $"{target.Name}: {host}, {key}; {fallbackSummary}";
            PipelineAnalyzeText = AppText.Format("{0} via {1} at {2}, reasoning effort {3}; failover uses the optional fallback route.", target.Model, SelectedKernel, host, target.Effort);
        }

        PipelineParseText = AppText.Get("English and Chinese analysis are validated together. Categories and severities are normalized, repeated patterns are merged.");
        PipelineStoreText = AppText.Get("Findings and the health score are saved to the local SQLite database and shown on the dashboard and trends.");
    }

    private void LoadFromSettings(AppSettings settings)
    {
        ModeIndex = settings.Mode == AppMode.Full ? 1 : 0;
        LanguageIndex = settings.Language == "zh-CN" ? 1 : 0;
        TokenUsagePeriodIndex = settings.TokenUsagePeriod switch { "week" => 1, "month" => 2, _ => 0 };
        KernelIndex = AiKernelCatalog.Normalize(settings.AiKernel) switch
        {
            AiKernelCatalog.Pi => 1,
            _ => 0
        };
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
            _ => 3
        };
        HighSeverityNotification = settings.HighSeverityNotification;
        ScanCompleteNotification = settings.ScanCompleteNotification;
        DiagnosticLoggingEnabled = settings.DiagnosticLoggingEnabled;
        SecurityAuditInstructions = settings.SecurityAuditInstructions;
        UpdatePolicyStatus(SecurityAuditInstructions);

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
            Mode = ModeIndex == 1 ? AppMode.Full : AppMode.Extended,
            Language = LanguageIndex == 1 ? "zh-CN" : "en",
            TokenUsagePeriod = TokenUsagePeriodIndex switch { 1 => "week", 2 => "month", _ => "day" },
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
            RetentionPolicyVersion = _settingsService.Current.RetentionPolicyVersion,
            HighSeverityNotification = HighSeverityNotification,
            ScanCompleteNotification = ScanCompleteNotification,
            DiagnosticLoggingEnabled = DiagnosticLoggingEnabled,
            SecurityAuditInstructions = SecurityAuditInstructions,
            AiKernel = SelectedKernel,
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
            1 => 7,
            2 => 14,
            _ => 30
        };
    }

    private void ShowStatus(InfoBarSeverity severity, string message)
    {
        OperationSeverity = severity;
        OperationMessage = message;
        ShowOperationStatus = true;
    }

    [RelayCommand]
    private async Task UpdateDatabaseStatsAsync()
    {
        try
        {
            long bytes = new[] { DatabasePath, DatabasePath + "-wal" }
                .Where(File.Exists).Sum(path => new FileInfo(path).Length);
            string databaseSize = $"{bytes / (1024.0 * 1024.0):F2} MB";
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
