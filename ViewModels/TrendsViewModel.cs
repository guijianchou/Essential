using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

/// <summary>A local hour or day, including all scans in that interval.</summary>
public sealed class TrendDay
{
    public DateTime Date { get; init; }
    public string Label { get; init; } = string.Empty;
    public bool HasData { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public int Total => High + Medium + Low;
    public double? Health { get; init; }
    public int Scans { get; init; }
}

public sealed class CategoryTotal
{
    public string Name { get; init; } = string.Empty;
    public int Count { get; init; }
}

public sealed class HistoryFinding
{
    public AuditIssueEnhanced Issue { get; init; } = new();
    public DateTime ScanTimestamp { get; init; }
    public string ScanText => AppText.Format("Scan {0}", ScanTimestamp.ToLocalTime().ToString("MMM d, HH:mm:ss", AppText.Culture));
}

public partial class TrendsViewModel : ObservableObject, IDisposable
{
    private const int PageSize = 20;
    private readonly DataStorageService _storageService;
    private readonly AuditSchedulerService _schedulerService;
    private readonly DispatcherQueue? _dispatcherQueue;
    private List<HistoryFinding> _findings = new();
    private int _loadVersion;
    private int _loadedWindow;
    private DateTime _loadedDate;
    private int _pageIndex;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsOneDay), nameof(IsSevenDays), nameof(IsThirtyDays))]
    private int windowDays = 7;

    public bool IsOneDay => WindowDays == 1;
    public bool IsSevenDays => WindowDays == 7;
    public bool IsThirtyDays => WindowDays == 30;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAssessment))]
    private List<TrendDay> trendDays = new();
    public bool HasAssessment => TrendDays.Any(day => day.Health.HasValue);
    [ObservableProperty] private List<CategoryTotal> categoryTotals = new();
    [ObservableProperty] private List<HistoryFinding> visibleFindings = new();
    [ObservableProperty] private bool hasData;
    [ObservableProperty] private bool hasFindings;
    [ObservableProperty] private string periodText = string.Empty;
    [ObservableProperty] private string findingsChartTitle = string.Empty;
    [ObservableProperty] private string healthChartTitle = string.Empty;
    [ObservableProperty] private string scansText = "0";
    [ObservableProperty] private string scansDetailText = string.Empty;
    [ObservableProperty] private string averageHealthText = "--";
    [ObservableProperty] private string averageHealthDetailText = string.Empty;
    [ObservableProperty] private string findingCountText = "0";
    [ObservableProperty] private string findingCountDetailText = string.Empty;
    [ObservableProperty] private string trendStatus = string.Empty;
    [ObservableProperty] private string trendDetailText = string.Empty;
    [ObservableProperty] private HealthBand trendBand = HealthBand.Good;
    [ObservableProperty] private double categoryChartHeight = 300;
    [ObservableProperty] private int severityFilterIndex;
    [ObservableProperty] private string pageText = string.Empty;
    [ObservableProperty] private bool canGoBack;
    [ObservableProperty] private bool canGoForward;
    [ObservableProperty] private bool isLoading;
    [ObservableProperty] private bool isStatusVisible;
    [ObservableProperty] private InfoBarSeverity statusSeverity = InfoBarSeverity.Informational;
    [ObservableProperty] private string statusMessage = string.Empty;

    public TrendsViewModel(DataStorageService storageService, AuditSchedulerService schedulerService)
    {
        _storageService = storageService;
        _schedulerService = schedulerService;
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
        AppText.Current.LanguageChanged += OnHistoryChanged;
        _schedulerService.AuditCompleted += OnAuditCompleted;
        _schedulerService.HistoryUpdated += OnHistoryChanged;
    }

    private void OnAuditCompleted(object? sender, AuditCompletedEventArgs e) => Reload();
    private void OnHistoryChanged(object? sender, EventArgs e) => Reload();

    private void Reload()
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
            _dispatcherQueue.TryEnqueue(() => _ = LoadDataCommand.ExecuteAsync(null));
        else _ = LoadDataCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private void SetWindow(string? value)
    {
        if (int.TryParse(value, out int days) && days is 1 or 7 or 30) WindowDays = days;
    }

    partial void OnWindowDaysChanged(int value) => Reload();

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task LoadDataAsync()
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
        {
            Reload();
            return;
        }

        int version = ++_loadVersion;
        int days = WindowDays;
        var today = DateTime.Today;
        bool changingPeriod = _loadedWindow != days || _loadedDate != today;
        IsLoading = true;
        try
        {
            var start = today.AddDays(1 - days).ToUniversalTime();
            var end = today.AddDays(1).ToUniversalTime();
            var results = await Task.Run(() => _storageService.GetResultsAsync(start, end));
            if (version != _loadVersion) return;
            ApplyResults(results, days, today);
            IsStatusVisible = false;
        }
        catch (Exception ex)
        {
            if (version != _loadVersion) return;
            if (changingPeriod) ApplyResults(new(), days, today);
            StatusMessage = HasData
                ? AppText.Get("History could not be updated. Showing the last available data for this period.")
                : AppText.Format("Load failed: {0}", ex.Message);
            StatusSeverity = InfoBarSeverity.Warning;
            IsStatusVisible = true;
        }
        finally
        {
            if (version == _loadVersion) IsLoading = false;
        }
    }

    private void ApplyResults(List<AuditResult> results, int days, DateTime today)
    {
        var start = today.AddDays(1 - days);
        var inWindow = results.Where(result => result.Timestamp.ToLocalTime() >= start
            && result.Timestamp.ToLocalTime() < today.AddDays(1)).OrderBy(result => result.Timestamp).ToList();
        var byBucket = inWindow.GroupBy(result => days == 1
            ? result.Timestamp.ToLocalTime().Hour
            : (result.Timestamp.ToLocalTime().Date - start).Days)
            .ToDictionary(group => group.Key, group => group.ToList());
        var buckets = new List<TrendDay>();
        for (int index = 0; index < (days == 1 ? 24 : days); index++)
        {
            var date = days == 1 ? start.AddHours(index) : start.AddDays(index);
            var scans = byBucket.GetValueOrDefault(index) ?? new();
            var findings = scans.SelectMany(scan => scan.Findings).ToList();
            var breakdown = HealthScoreCalculator.Calculate(findings);
            var assessed = scans.Where(scan => scan.HasAssessment).ToList();
            buckets.Add(new TrendDay
            {
                Date = date,
                Label = date.ToString(days == 1 ? "HH:mm" : "M/d", AppText.Culture),
                HasData = scans.Count > 0,
                High = breakdown.HighCount,
                Medium = breakdown.MediumCount,
                Low = breakdown.LowCount,
                Health = assessed.Count == 0 ? null : assessed.Average(scan => HealthScoreCalculator.Calculate(scan.Findings).Score),
                Scans = scans.Count
            });
        }

        _findings = inWindow.AsEnumerable().Reverse()
            .SelectMany(scan => scan.Findings.Select(issue => new HistoryFinding
            {
                ScanTimestamp = scan.Timestamp,
                Issue = IssueCategorizer.CategorizeIssue(issue)
            }).OrderBy(item => item.Issue.Severity)).ToList();
        CategoryTotals = _findings.GroupBy(finding => finding.Issue.CategoryLabel)
            .Select(group => new CategoryTotal { Name = group.Key, Count = group.Count() })
            .OrderByDescending(total => total.Count).ThenBy(total => total.Name).ToList();
        HasData = inWindow.Count > 0;
        PeriodText = days == 1
            ? AppText.Format("Today, {0:d} (local time)", today)
            : AppText.Format("{0:d} to {1:d} (local time)", start, today);
        FindingsChartTitle = AppText.Get(days == 1 ? "Finding reports by hour" : "Finding reports by day");
        HealthChartTitle = AppText.Get(days == 1 ? "Average health by hour" : "Average health by day");
        ScansText = inWindow.Count.ToString("N0", AppText.Culture);
        ScansDetailText = AppText.Format("{0} of {1} days with scans", inWindow.Select(scan => scan.Timestamp.ToLocalTime().Date).Distinct().Count(), days);
        var assessedScans = inWindow.Where(scan => scan.HasAssessment).ToList();
        AverageHealthText = assessedScans.Count == 0 ? "--"
            : Math.Round(assessedScans.Average(scan => HealthScoreCalculator.Calculate(scan.Findings).Score)).ToString(AppText.Culture);
        AverageHealthDetailText = AppText.Format("{0} assessed scans", assessedScans.Count);
        FindingCountText = _findings.Count.ToString("N0", AppText.Culture);
        FindingCountDetailText = AppText.Format("{0} high / {1} medium / {2} low",
            _findings.Count(finding => finding.Issue.IsHigh), _findings.Count(finding => finding.Issue.IsMedium),
            _findings.Count(finding => finding.Issue.IsLow));
        UpdateTrendStatus(assessedScans);
        if (_loadedWindow != days || _loadedDate != today) _pageIndex = 0;
        _loadedWindow = days;
        _loadedDate = today;
        RebuildFindingPage();
        // Publish chart data after all of its labels and categories are ready.
        TrendDays = buckets;
    }

    partial void OnSeverityFilterIndexChanged(int value)
    {
        _pageIndex = 0;
        RebuildFindingPage();
    }

    [RelayCommand]
    private void PreviousPage()
    {
        if (!CanGoBack) return;
        _pageIndex--;
        RebuildFindingPage();
    }

    [RelayCommand]
    private void NextPage()
    {
        if (!CanGoForward) return;
        _pageIndex++;
        RebuildFindingPage();
    }

    private void RebuildFindingPage()
    {
        var filtered = _findings.Where(finding => SeverityFilterIndex switch
        {
            1 => finding.Issue.IsHigh,
            2 => finding.Issue.IsMedium,
            3 => finding.Issue.IsLow,
            _ => true
        }).ToList();
        _pageIndex = Math.Clamp(_pageIndex, 0, Math.Max(0, (filtered.Count - 1) / PageSize));
        VisibleFindings = filtered.Skip(_pageIndex * PageSize).Take(PageSize).ToList();
        HasFindings = filtered.Count > 0;
        CanGoBack = _pageIndex > 0;
        CanGoForward = (_pageIndex + 1) * PageSize < filtered.Count;
        PageText = AppText.Format("{0}-{1} of {2} reports", HasFindings ? _pageIndex * PageSize + 1 : 0,
            _pageIndex * PageSize + VisibleFindings.Count, filtered.Count);
    }

    private void UpdateTrendStatus(List<AuditResult> assessed)
    {
        if (assessed.Count == 0)
        {
            TrendStatus = AppText.Get(HasData ? "Not assessed" : "No data");
            TrendDetailText = AppText.Get("No assessed scans in this period.");
            TrendBand = HealthBand.Good;
            return;
        }
        int first = HealthScoreCalculator.Calculate(assessed[0].Findings).Score;
        int last = HealthScoreCalculator.Calculate(assessed[^1].Findings).Score;
        int delta = last - first;
        TrendStatus = assessed.Count == 1 ? HealthScoreCalculator.GetVerdict(last)
            : AppText.Get(delta > 5 ? "Improving" : delta < -5 ? "Getting worse" : "Stable");
        TrendBand = delta > 5 ? HealthBand.Good : HealthScoreCalculator.GetBand(last);
        TrendDetailText = assessed.Count == 1 ? AppText.Get("1 assessed scan")
            : AppText.Format("First scan {0}, latest scan {1}.", first, last);
    }

    public void Dispose()
    {
        AppText.Current.LanguageChanged -= OnHistoryChanged;
        _schedulerService.AuditCompleted -= OnAuditCompleted;
        _schedulerService.HistoryUpdated -= OnHistoryChanged;
    }
}
