using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

/// <summary>One dashboard category section: its findings plus the counts shown in the header.</summary>
public sealed partial class FindingSection : ObservableObject
{
    private const double BarWidth = 96;
    private const double MinSegmentWidth = 6;

    [ObservableProperty]
    private bool isExpanded;

    public FindingSection(string name, IReadOnlyList<AuditIssueEnhanced> issues, bool isExpanded)
    {
        Name = name;
        Issues = new ObservableCollection<AuditIssueEnhanced>(issues);
        HighCount = issues.Count(issue => issue.IsHigh);
        MediumCount = issues.Count(issue => issue.IsMedium);
        LowCount = issues.Count - HighCount - MediumCount;
        this.isExpanded = isExpanded;

        int total = Math.Max(1, issues.Count);
        HighBarWidth = SegmentWidth(HighCount, total);
        MediumBarWidth = SegmentWidth(MediumCount, total);
        LowBarWidth = SegmentWidth(LowCount, total);

        var parts = new List<string>();
        if (HighCount > 0) parts.Add(AppText.Format("{0} high", HighCount));
        if (MediumCount > 0) parts.Add(AppText.Format("{0} medium", MediumCount));
        if (LowCount > 0) parts.Add(AppText.Format("{0} low", LowCount));
        SeveritySummary = string.Join(", ", parts);
    }

    public string Name { get; }
    public ObservableCollection<AuditIssueEnhanced> Issues { get; }
    public int Count => Issues.Count;
    public int HighCount { get; }
    public int MediumCount { get; }
    public int LowCount { get; }
    public bool HasHigh => HighCount > 0;
    public bool HasMedium => MediumCount > 0;
    public bool HasLow => LowCount > 0;
    public double HighBarWidth { get; }
    public double MediumBarWidth { get; }
    public double LowBarWidth { get; }
    public string SeveritySummary { get; }
    public string CountLabel => Count == 1 ? AppText.Get("1 finding") : AppText.Format("{0} findings", Count);

    private static double SegmentWidth(int count, int total)
    {
        if (count == 0)
        {
            return 0;
        }

        return Math.Max(MinSegmentWidth, Math.Round(BarWidth * count / total));
    }
}

public partial class DashboardViewModel : ObservableObject, IDisposable
{
    public const string FilterAll = "All";
    public const string FilterHigh = "High";
    public const string FilterMedium = "Medium";
    public const string FilterLow = "Low";

    private readonly DataStorageService _storageService;
    private readonly AuditSchedulerService _schedulerService;
    private readonly DispatcherQueue? _dispatcherQueue;
    private readonly List<AuditIssueEnhanced> _allIssues = new();
    private bool _isRunningScan;
    private AuditResult? _displayedResult;
    private int _loadVersion;
    private bool _isLoadingData;

    [ObservableProperty]
    private List<AuditIssueEnhanced> priorityFindings = new();

    [ObservableProperty]
    private int eventCount;

    [ObservableProperty]
    private string coverageState = AppText.Get("No audit");

    [ObservableProperty]
    private string coverageText = AppText.Get("Run a scan to establish the evidence coverage.");

    [ObservableProperty]
    private bool hasAuditData;

    [ObservableProperty]
    private bool hasAssessment;

    [ObservableProperty]
    private int healthScore;

    [ObservableProperty]
    private HealthBand healthBand = HealthBand.Good;

    [ObservableProperty]
    private string healthScoreText = "–";

    [ObservableProperty]
    private string healthVerdict = AppText.Get("No audit yet");

    [ObservableProperty]
    private string healthSummaryText = AppText.Get("Run a scan to see your posture.");

    [ObservableProperty]
    private string healthDeductionText = string.Empty;

    [ObservableProperty]
    private string lastAuditHeadline = AppText.Get("No audit has completed yet");

    [ObservableProperty]
    private string scanTypeText = "–";

    [ObservableProperty]
    private string finishedText = "–";

    [ObservableProperty]
    private string windowText = "–";

    [ObservableProperty]
    private string eventCountText = "–";

    [ObservableProperty]
    private string scanCountText = "0";

    [ObservableProperty]
    private int totalFindings;

    [ObservableProperty]
    private int highCount;

    [ObservableProperty]
    private int mediumCount;

    [ObservableProperty]
    private int lowCount;

    [ObservableProperty]
    private string findingsSummaryText = AppText.Get("No findings");

    [ObservableProperty]
    private string severityFilter = FilterAll;

    [ObservableProperty]
    private ObservableCollection<FindingSection> findingSections = new();

    [ObservableProperty]
    private bool showEmptyIssues;

    [ObservableProperty]
    private bool showNoAudit = true;

    [ObservableProperty]
    private bool showNoFilterMatches;

    [ObservableProperty]
    private bool isLoading;

    [ObservableProperty]
    private bool isStatusVisible;

    [ObservableProperty]
    private string statusMessage = AppText.Get("Ready");

    [ObservableProperty]
    private InfoBarSeverity statusSeverity = InfoBarSeverity.Informational;

    public bool IsFilterAll => SeverityFilter == FilterAll;
    public bool IsFilterHigh => SeverityFilter == FilterHigh;
    public bool IsFilterMedium => SeverityFilter == FilterMedium;
    public bool IsFilterLow => SeverityFilter == FilterLow;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSourceAll), nameof(IsSourceApplication), nameof(IsSourceSecurity), nameof(IsSourceSetup), nameof(IsSourceSystem))]
    private string sourceFilter = FilterAll;

    public bool IsSourceAll => SourceFilter == FilterAll;
    public bool IsSourceApplication => SourceFilter == "Application";
    public bool IsSourceSecurity => SourceFilter == "Security";
    public bool IsSourceSetup => SourceFilter == "Setup";
    public bool IsSourceSystem => SourceFilter == "System";
    public string OverviewLabel => AppText.Format("Overview {0}", _allIssues.Count);
    public string ApplicationLabel => SourceLabel("Application");
    public string SecurityLabel => SourceLabel("Security");
    public string SetupLabel => SourceLabel("Setup");
    public string SystemLabel => SourceLabel("System");

    private string SourceLabel(string log) => $"{AppText.Get(log)} {_allIssues.Count(issue => string.Equals(issue.LogName, log, StringComparison.OrdinalIgnoreCase))}";

    [RelayCommand]
    private void SetSourceFilter(string? log) => SourceFilter = log is "Application" or "Security" or "Setup" or "System" ? log : FilterAll;

    partial void OnSourceFilterChanged(string value) => RebuildSections();

    public DashboardViewModel(
        DataStorageService storageService,
        AuditSchedulerService schedulerService)
    {
        _storageService = storageService;
        _schedulerService = schedulerService;
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
        _schedulerService.AuditCompleted += OnAuditCompleted;
        _schedulerService.AuditFailed += OnAuditFailed;
        _schedulerService.AuditProgress += OnAuditProgress;
        _schedulerService.HistoryUpdated += OnHistoryUpdated;
        AppText.Current.LanguageChanged += OnLanguageChanged;
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        EnqueueOnUi(() =>
        {
            if (_displayedResult != null) ApplyResult(_displayedResult);
            else ApplyNoData();
        });
    }

    private void OnAuditCompleted(object? sender, AuditCompletedEventArgs e)
    {
        EnqueueOnUi(async () =>
        {
            ApplyResult(e.Result);
            try
            {
                await LoadDataCommand.ExecuteAsync(null);
            }
            catch (Exception ex)
            {
                ShowStatus(InfoBarSeverity.Error, AppText.Format("Failed to load audit results: {0}", ex.Message));
            }
        });
    }

    private void OnHistoryUpdated(object? sender, EventArgs e)
    {
        EnqueueOnUi(() => _ = LoadDataCommand.ExecuteAsync(null));
    }

    private void OnAuditFailed(object? sender, AuditFailedEventArgs e)
    {
        EnqueueOnUi(UpdateLoadingState);
    }

    private void OnAuditProgress(object? sender, AuditProgressEventArgs e)
    {
        EnqueueOnUi(UpdateLoadingState);
    }

    private void UpdateLoadingState() => IsLoading = _isLoadingData || _isRunningScan || _schedulerService.IsScanning;

    [RelayCommand]
    private void SetSeverityFilter(string? filter)
    {
        string next = filter switch
        {
            FilterHigh or FilterMedium or FilterLow => filter,
            _ => FilterAll
        };

        SeverityFilter = next;
        OnPropertyChanged(nameof(IsFilterAll));
        OnPropertyChanged(nameof(IsFilterHigh));
        OnPropertyChanged(nameof(IsFilterMedium));
        OnPropertyChanged(nameof(IsFilterLow));
        RebuildSections();
    }

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task LoadDataAsync()
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
        {
            _dispatcherQueue.TryEnqueue(() => _ = LoadDataCommand.ExecuteAsync(null));
            return;
        }

        int version = ++_loadVersion;
        _isLoadingData = true;
        UpdateLoadingState();

        try
        {
            var (result, scanCount) = await Task.Run(async () =>
                (await _storageService.GetLatestResultAsync(), await _storageService.GetAuditRecordCountAsync()));
            if (version != _loadVersion) return;
            ScanCountText = scanCount.ToString("N0", AppText.Culture);

            if (result == null)
            {
                ApplyNoData();
                if (!_isRunningScan)
                {
                    IsStatusVisible = false;
                }

                return;
            }

            ApplyResult(result);
            if (!_isRunningScan)
            {
                IsStatusVisible = false;
            }
        }
        catch (Exception ex)
        {
            if (version == _loadVersion)
                ShowStatus(InfoBarSeverity.Warning, _displayedResult == null
                    ? AppText.Format("Load failed: {0}", ex.Message)
                    : AppText.Get("The latest audit could not be loaded. Showing the last available result."));
        }
        finally
        {
            if (version == _loadVersion)
            {
                _isLoadingData = false;
                UpdateLoadingState();
            }
        }
    }

    [RelayCommand]
    private async Task RunFastScanAsync()
    {
        await RunScanAsync(true);
    }

    [RelayCommand]
    private async Task RunFullScanAsync()
    {
        await RunScanAsync(false);
    }

    private async Task RunScanAsync(bool fastScan)
    {
        if (_isRunningScan || IsLoading || _schedulerService.IsScanning)
        {
            return;
        }

        _isRunningScan = true;
        IsLoading = true;
        IsStatusVisible = false;

        try
        {
            bool succeeded = await _schedulerService.ExecuteAuditAsync(fastScan);
            if (succeeded)
            {
                await LoadDataCommand.ExecuteAsync(null);
            }
        }
        finally
        {
            _isRunningScan = false;
            UpdateLoadingState();
        }
    }

    private void ApplyNoData()
    {
        _displayedResult = null;
        HasAuditData = false;
        HasAssessment = false;
        _allIssues.Clear();
        HealthScore = 0;
        HealthBand = HealthBand.Good;
        HealthScoreText = "–";
        HealthVerdict = AppText.Get("No audit yet");
        HealthSummaryText = AppText.Get("Run a fast scan for the past few hours or a full scan for the past 24 hours.");
        HealthDeductionText = string.Empty;
        LastAuditHeadline = AppText.Get("No audit has completed yet");
        ScanTypeText = "–";
        FinishedText = "–";
        WindowText = "–";
        EventCountText = "–";
        EventCount = 0;
        CoverageState = AppText.Get("No audit");
        CoverageText = AppText.Get("Run a scan to establish the evidence coverage.");
        PriorityFindings = new List<AuditIssueEnhanced>();
        TotalFindings = 0;
        HighCount = 0;
        MediumCount = 0;
        LowCount = 0;
        FindingsSummaryText = AppText.Get("No findings yet");
        ShowNoAudit = true;
        ShowEmptyIssues = false;
        ShowNoFilterMatches = false;
        FindingSections.Clear();
    }

    private void ApplyResult(AuditResult result)
    {
        _displayedResult = result;
        HasAuditData = true;
        HasAssessment = result.HasAssessment;
        ShowNoAudit = false;

        _allIssues.Clear();
        foreach (var issue in result.Findings)
        {
            if (issue.DetectedAt == default)
            {
                issue.DetectedAt = result.Timestamp;
            }

            _allIssues.Add(IssueCategorizer.CategorizeIssue(issue));
        }

        var breakdown = HealthScoreCalculator.Calculate(result.Findings);
        HealthScore = result.HasAssessment ? breakdown.Score : 0;
        HealthBand = breakdown.Band;
        HealthScoreText = result.HasAssessment ? breakdown.Score.ToString(AppText.Culture) : "--";
        HealthVerdict = result.HasAssessment ? breakdown.Verdict : AppText.Get("Not assessed");
        HealthSummaryText = !result.HasAssessment ? AppText.Get("No events were analyzed by AI.") : breakdown.TotalFindings == 0
            ? AppText.Get("No findings in the latest audit")
            : AppText.Format("Based on {0} high, {1} medium and {2} low findings.", breakdown.HighCount, breakdown.MediumCount, breakdown.LowCount);
        HealthDeductionText = result.HasAssessment ? BuildDeductionText(breakdown) : string.Empty;

        TotalFindings = breakdown.TotalFindings;
        HighCount = breakdown.HighCount;
        MediumCount = breakdown.MediumCount;
        LowCount = breakdown.LowCount;

        ScanTypeText = ReadMetadataString(result, "ScanType").ToLowerInvariant() switch
        {
            "fast scan" => AppText.Get("Fast scan"),
            "full scan" => AppText.Get("Full scan"),
            "" => AppText.Get("Scan"),
            var other => char.ToUpper(other[0], AppText.Culture) + other[1..]
        };
        FinishedText = FormatDay(result.Timestamp, capitalize: true);
        LastAuditHeadline = AppText.Format("{0} finished {1}", ScanTypeText, FormatDay(result.Timestamp, capitalize: false));
        WindowText = FormatWindow(result);
        int eventCount = ReadMetadataInt(result, "EventCount");
        EventCount = eventCount;
        EventCountText = eventCount.ToString("N0", AppText.Culture);
        CoverageState = eventCount == 0
            ? AppText.Get("No events read")
            : !result.HasAssessment ? AppText.Get("Not assessed")
            : _allIssues.Count == 0 ? AppText.Get("Scanned · no findings") : AppText.Get("Evidence available");
        CoverageText = eventCount == 0
            ? AppText.Get("0 events were read in this window. No conclusion about system safety can be drawn.")
            : result.Metadata?.ContainsKey("AnalyzedEventCount") == true
                ? AppText.Format("{0:N0} events collected; {1:N0} analyzed by AI; {2:N0} excluded by filtering or sampling.",
                    eventCount, ReadMetadataInt(result, "AnalyzedEventCount"), ReadMetadataInt(result, "FilteredEventCount"))
                : AppText.Format("{0:N0} events collected. This older audit did not record how many were analyzed by AI.", eventCount);

        RebuildSections();
    }

    private void RebuildSections()
    {
        var previousState = FindingSections.ToDictionary(section => section.Name, section => section.IsExpanded);
        var sourceIssues = IsSourceAll ? _allIssues : _allIssues.Where(issue =>
            string.Equals(issue.LogName, SourceFilter, StringComparison.OrdinalIgnoreCase)).ToList();
        TotalFindings = sourceIssues.Count;
        HighCount = sourceIssues.Count(issue => issue.IsHigh);
        MediumCount = sourceIssues.Count(issue => issue.IsMedium);
        LowCount = sourceIssues.Count(issue => issue.IsLow);
        foreach (string property in new[] { nameof(OverviewLabel), nameof(ApplicationLabel), nameof(SecurityLabel), nameof(SetupLabel), nameof(SystemLabel) })
            OnPropertyChanged(property);
        var visibleIssues = SeverityFilter switch
        {
            FilterHigh => sourceIssues.Where(issue => issue.IsHigh).ToList(),
            FilterMedium => sourceIssues.Where(issue => issue.IsMedium).ToList(),
            FilterLow => sourceIssues.Where(issue => issue.IsLow).ToList(),
            _ => sourceIssues.ToList()
        };

        var groups = visibleIssues
            .GroupBy(issue => issue.CategoryLabel)
            .OrderByDescending(group => group.Max(issue => SeverityRank(issue.Severity)))
            .ThenByDescending(group => group.Max(issue => issue.Occurrences))
            .ThenBy(group => group.Min(issue => issue.CategoryOrder))
            .ToList();

        bool anyHigh = groups.Any(group => group.Any(issue => issue.IsHigh));
        bool filterActive = SeverityFilter != FilterAll;
        var sections = new List<FindingSection>();
        for (int index = 0; index < groups.Count; index++)
        {
            var group = groups[index];
            var issues = group
                .OrderByDescending(issue => issue.IsHigh)
                .ThenByDescending(issue => issue.IsMedium)
                .ThenByDescending(issue => issue.EventTimestamp == default ? issue.DetectedAt : issue.EventTimestamp)
                .ToList();

            bool expanded = previousState.TryGetValue(group.Key, out bool wasExpanded)
                ? wasExpanded
                : filterActive || (anyHigh ? issues.Any(issue => issue.IsHigh) : index == 0);
            sections.Add(new FindingSection(group.Key, issues, expanded));
        }

        FindingSections.Clear();
        foreach (var section in sections)
        {
            FindingSections.Add(section);
        }

        int shown = sections.Sum(section => section.Count);
        PriorityFindings = visibleIssues
            .OrderByDescending(issue => SeverityRank(issue.Severity))
            .ThenByDescending(issue => issue.Occurrences)
            .ThenByDescending(issue => issue.EventTimestamp == default ? issue.DetectedAt : issue.EventTimestamp)
            .Take(5)
            .ToList();

        ShowEmptyIssues = HasAuditData && _allIssues.Count == 0;
        ShowNoFilterMatches = HasAuditData && _allIssues.Count > 0 && shown == 0;

        if (!HasAuditData)
        {
            FindingsSummaryText = AppText.Get("No findings yet");
        }
        else if (sourceIssues.Count == 0 && !IsSourceAll)
        {
            FindingsSummaryText = AppText.Format("No findings from {0}", AppText.Get(SourceFilter));
        }
        else if (_allIssues.Count == 0)
        {
            FindingsSummaryText = AppText.Get("No findings in the latest audit");
        }
        else if (filterActive)
        {
            string severityWord = AppText.Get(SeverityFilter.ToLowerInvariant());
            FindingsSummaryText = shown == 0
                ? AppText.Format("No {0} findings", severityWord)
                : AppText.Format("{0} {1} findings in {2} categories", shown, severityWord, sections.Count);
        }
        else
        {
            FindingsSummaryText = AppText.Format("{0} findings in {1} categories", shown, sections.Count);
        }
    }

    private static int SeverityRank(IssueSeverity severity)
    {
        return severity switch
        {
            IssueSeverity.Critical => 4,
            IssueSeverity.High => 3,
            IssueSeverity.Medium => 2,
            _ => 1
        };
    }

    private static string BuildDeductionText(HealthScoreBreakdown breakdown)
    {
        var parts = new List<string>();
        if (breakdown.HighDeduction > 0) parts.Add(AppText.Format("high \u2212{0}", breakdown.HighDeduction));
        if (breakdown.MediumDeduction > 0) parts.Add(AppText.Format("medium \u2212{0}", breakdown.MediumDeduction));
        if (breakdown.LowDeduction > 0) parts.Add(AppText.Format("low \u2212{0}", breakdown.LowDeduction));
        return parts.Count == 0
            ? AppText.Get("No deductions. A score of 80 or more counts as healthy.")
            : AppText.Format("Deductions from 100: {0}. 80 or more counts as healthy.", string.Join(", ", parts));
    }

    private static string FormatDay(DateTime utc, bool capitalize)
    {
        var local = utc.ToLocalTime();
        var today = DateTime.Today;
        string day = local.Date == today
            ? AppText.Get("today")
            : local.Date == today.AddDays(-1)
                ? AppText.Get("yesterday")
                : local.ToString("MMM d", AppText.Culture);

        if (capitalize)
        {
            day = char.ToUpper(day[0], AppText.Culture) + day[1..];
            return $"{day}, {local:HH:mm}";
        }

        return AppText.Format("{0} at {1}", day, local.ToString("HH:mm", AppText.Culture));
    }

    private static string FormatWindow(AuditResult result)
    {
        string startText = ReadMetadataString(result, "ScanStart");
        string endText = ReadMetadataString(result, "ScanEnd");
        if (TryParseUtc(startText, "O", out var start) && TryParseUtc(endText, "O", out var end))
        {
            return FormatWindow(start, end);
        }

        // Older records only carry a "yyyy-MM-dd HH:mm - yyyy-MM-dd HH:mm" text whose time
        // zone changed between builds. The window ends shortly before the result was saved,
        // so pick the interpretation (local or UTC) whose end is closest to the timestamp.
        string legacy = ReadMetadataString(result, "TimeRange");
        var parts = legacy.Split(" - ", StringSplitOptions.TrimEntries);
        if (parts.Length == 2
            && DateTime.TryParseExact(parts[0], "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var rawStart)
            && DateTime.TryParseExact(parts[1], "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var rawEnd))
        {
            var asUtcEnd = DateTime.SpecifyKind(rawEnd, DateTimeKind.Utc);
            var asLocalEnd = DateTime.SpecifyKind(rawEnd, DateTimeKind.Local).ToUniversalTime();
            var saved = result.Timestamp.ToUniversalTime();
            double utcGap = Math.Abs((saved - asUtcEnd).TotalMinutes);
            double localGap = Math.Abs((saved - asLocalEnd).TotalMinutes);
            bool treatAsLocal = localGap < utcGap;
            var legacyStart = treatAsLocal
                ? DateTime.SpecifyKind(rawStart, DateTimeKind.Local).ToUniversalTime()
                : DateTime.SpecifyKind(rawStart, DateTimeKind.Utc);
            var legacyEnd = treatAsLocal ? asLocalEnd : asUtcEnd;
            return FormatWindow(legacyStart, legacyEnd);
        }

        return string.IsNullOrEmpty(legacy) ? "–" : legacy;
    }

    private static string FormatWindow(DateTime startUtc, DateTime endUtc)
    {
        var start = startUtc.ToLocalTime();
        var end = endUtc.ToLocalTime();
        if (start.Date == end.Date)
        {
            string day = end.Date == DateTime.Today ? AppText.Get("today") : end.ToString("MMM d", AppText.Culture);
            return AppText.Format("{0} to {1}, {2}", start.ToString("HH:mm", AppText.Culture), end.ToString("HH:mm", AppText.Culture), day);
        }

        return AppText.Format("{0} to {1}", start.ToString("MMM d, HH:mm", AppText.Culture), end.ToString("MMM d, HH:mm", AppText.Culture));
    }

    private static bool TryParseUtc(string value, string format, out DateTime utc)
    {
        return DateTime.TryParseExact(
            value,
            format,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out utc);
    }

    private static int ReadMetadataInt(AuditResult result, string key)
    {
        if (result.Metadata?.TryGetValue(key, out var value) != true)
        {
            return 0;
        }

        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
            ? number
            : 0;
    }

    private static string ReadMetadataString(AuditResult result, string key)
    {
        if (result.Metadata?.TryGetValue(key, out var value) != true)
        {
            return string.Empty;
        }

        return value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;
    }

    private void ShowStatus(InfoBarSeverity severity, string message)
    {
        StatusSeverity = severity;
        StatusMessage = message;
        IsStatusVisible = true;
    }

    private void EnqueueOnUi(Action action)
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
        {
            _dispatcherQueue.TryEnqueue(() => action());
            return;
        }

        action();
    }

    public void Dispose()
    {
        AppText.Current.LanguageChanged -= OnLanguageChanged;
        _schedulerService.AuditCompleted -= OnAuditCompleted;
        _schedulerService.AuditFailed -= OnAuditFailed;
        _schedulerService.AuditProgress -= OnAuditProgress;
        _schedulerService.HistoryUpdated -= OnHistoryUpdated;
    }
}
