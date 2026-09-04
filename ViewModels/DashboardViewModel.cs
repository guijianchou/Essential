using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

public partial class DashboardViewModel : ObservableObject, IDisposable
{
    private readonly DataStorageService _storageService;
    private readonly AuditSchedulerService _schedulerService;
    private readonly DispatcherQueue? _dispatcherQueue;
    private bool _isRunningScan;

    [ObservableProperty]
    private int healthScore = 100;

    [ObservableProperty]
    private string healthScoreText = "—";

    [ObservableProperty]
    private bool hasAuditData;

    [ObservableProperty]
    private bool showEmptyIssues;

    [ObservableProperty]
    private ObservableCollection<AuditIssue> issues = new();

    [ObservableProperty]
    private ObservableCollection<IssueGroup> issueGroups = new();

    [ObservableProperty]
    private ISeries[] severityPieSeries = Array.Empty<ISeries>();

    [ObservableProperty]
    private bool isLoading;

    [ObservableProperty]
    private bool isStatusVisible;

    [ObservableProperty]
    private string statusMessage = "Ready";

    [ObservableProperty]
    private Microsoft.UI.Xaml.Controls.InfoBarSeverity statusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Informational;

    [ObservableProperty]
    private string lastUpdatedText = "No audit has completed";

    [ObservableProperty]
    private int highIssueCount;

    [ObservableProperty]
    private int mediumIssueCount;

    [ObservableProperty]
    private int lowIssueCount;

    [ObservableProperty]
    private int scanCount;

    [ObservableProperty]
    private int eventCount;

    [ObservableProperty]
    private string scanTypeText = "—";

    [ObservableProperty]
    private string timeRangeText = "—";

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
    }

    private void OnAuditCompleted(object? sender, AuditCompletedEventArgs e)
    {
        EnqueueOnUi(async () =>
        {
            try
            {
                await LoadDataCommand.ExecuteAsync(null);
            }
            catch (Exception ex)
            {
                StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Error;
                StatusMessage = $"Failed to load audit results: {ex.Message}";
                IsStatusVisible = true;
            }
        });
    }

    private void OnAuditFailed(object? sender, AuditFailedEventArgs e)
    {
        EnqueueOnUi(() =>
        {
            StatusMessage = $"Audit failed: {e.Message}";
            StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Error;
            IsStatusVisible = true;
            IsLoading = false;
        });
    }

    private void OnAuditProgress(object? sender, AuditProgressEventArgs e)
    {
        EnqueueOnUi(() =>
        {
            if (!_isRunningScan)
            {
                return;
            }

            StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Informational;
            StatusMessage = e.Message;
            IsStatusVisible = true;
        });
    }

    [RelayCommand]
    private async Task LoadDataAsync()
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
        {
            _dispatcherQueue.TryEnqueue(() => _ = LoadDataCommand.ExecuteAsync(null));
            return;
        }

        if (IsLoading && !_isRunningScan)
        {
            return;
        }

        IsLoading = true;
        IsStatusVisible = true;
        if (!_isRunningScan)
        {
            StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Informational;
            StatusMessage = "Loading latest audit...";
        }

        try
        {
            var result = await _storageService.GetTodayResultAsync();
            ScanCount = await _storageService.GetAuditRecordCountAsync();

            if (result == null)
            {
                HasAuditData = false;
                ShowEmptyIssues = false;
                HealthScoreText = "—";
                HealthScore = 100;
                Issues.Clear();
                IssueGroups.Clear();
                HighIssueCount = 0;
                MediumIssueCount = 0;
                LowIssueCount = 0;
                EventCount = 0;
                ScanTypeText = "—";
                TimeRangeText = "—";
                LastUpdatedText = "No audit has completed";
                UpdateCharts();
                if (!_isRunningScan)
                {
                    StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Informational;
                    StatusMessage = "No audit data for today";
                    IsStatusVisible = true;
                }

                return;
            }

            HealthScore = result.HealthScore;
            HealthScoreText = result.HealthScore.ToString();
            HasAuditData = true;
            Issues.Clear();
            var categorizedIssues = new List<AuditIssueEnhanced>();
            var counts = new int[3]; // High, Medium, Low
            foreach (var issue in result.Findings)
            {
                if (issue.DetectedAt == default)
                {
                    issue.DetectedAt = result.Timestamp;
                }

                Issues.Add(issue);
                categorizedIssues.Add(IssueCategorizer.CategorizeIssue(issue));
                switch (issue.Severity)
                {
                    case "High":
                        counts[0]++;
                        break;
                    case "Medium":
                        counts[1]++;
                        break;
                    case "Low":
                        counts[2]++;
                        break;
                }
            }

            HighIssueCount = counts[0];
            MediumIssueCount = counts[1];
            LowIssueCount = counts[2];
            ShowEmptyIssues = Issues.Count == 0;
            UpdateIssueGroups(categorizedIssues);
            EventCount = ReadMetadataInt(result, "EventCount");
            ScanTypeText = ReadMetadataString(result, "ScanType");
            TimeRangeText = ReadMetadataString(result, "TimeRange");
            LastUpdatedText = $"Updated {result.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
            UpdateCharts();
            StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Success;
            StatusMessage = LastUpdatedText;
            IsStatusVisible = true;
        }
        catch (Exception ex)
        {
            StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Error;
            StatusMessage = $"Load failed: {ex.Message}";
            IsStatusVisible = true;
        }
        finally
        {
            if (!_isRunningScan)
            {
                IsLoading = false;
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
        if (_isRunningScan || IsLoading)
        {
            return;
        }

        _isRunningScan = true;
        IsLoading = true;
        IsStatusVisible = true;
        StatusMessage = fastScan
            ? "Running fast scan..."
            : "Running full scan...";
        StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Informational;

        try
        {
            bool succeeded = await _schedulerService.ExecuteAuditAsync(fastScan);
            if (!succeeded)
            {
                if (StatusSeverity != Microsoft.UI.Xaml.Controls.InfoBarSeverity.Error)
                {
                    StatusSeverity = Microsoft.UI.Xaml.Controls.InfoBarSeverity.Error;
                    StatusMessage = fastScan ? "Fast scan failed" : "Full scan failed";
                    IsStatusVisible = true;
                }
            }
        }
        finally
        {
            _isRunningScan = false;
            IsLoading = false;
        }
    }

    private void UpdateCharts()
    {
        SeverityPieSeries = new ISeries[]
        {
            new PieSeries<int>
            {
                Name = "High",
                Values = new[] { HighIssueCount },
                Fill = new SolidColorPaint(SKColors.IndianRed)
            },
            new PieSeries<int>
            {
                Name = "Medium",
                Values = new[] { MediumIssueCount },
                Fill = new SolidColorPaint(SKColors.Orange)
            },
            new PieSeries<int>
            {
                Name = "Low",
                Values = new[] { LowIssueCount },
                Fill = new SolidColorPaint(SKColors.Gold)
            }
        };
    }

    private void UpdateIssueGroups(IEnumerable<AuditIssueEnhanced> categorizedIssues)
    {
        var groups = categorizedIssues
            .GroupBy(issue => issue.CategoryGroup)
            .Select(CreateIssueGroup)
            .OrderBy(group => GetIssueGroupOrder(group.GroupName))
            .ThenByDescending(group => group.CriticalCount)
            .ThenByDescending(group => group.HighCount)
            .ToList();

        IssueGroups.Clear();
        foreach (var group in groups)
        {
            IssueGroups.Add(group);
        }
    }

    private static IssueGroup CreateIssueGroup(IGrouping<string, AuditIssueEnhanced> group)
    {
        var issues = group
            .OrderByDescending(issue => issue.Severity)
            .ThenByDescending(issue => issue.DetectedAt)
            .ToList();

        var sections = issues
            .GroupBy(issue => issue.Category)
            .Select(category => new IssueCategorySection
            {
                CategoryName = category.First().CategoryLabel,
                CategoryIcon = category.First().CategoryIcon,
                CategoryColor = category.First().CategoryColor,
                TotalCount = category.Count(),
                CriticalCount = category.Count(issue => issue.Severity == IssueSeverity.Critical),
                HighCount = category.Count(issue => issue.Severity == IssueSeverity.High),
                MediumCount = category.Count(issue => issue.Severity == IssueSeverity.Medium),
                LowCount = category.Count(issue => issue.Severity == IssueSeverity.Low),
                Issues = new ObservableCollection<AuditIssueEnhanced>(
                    category.OrderByDescending(issue => issue.Severity)
                        .ThenByDescending(issue => issue.DetectedAt))
            })
            .OrderByDescending(section => section.CriticalCount)
            .ThenByDescending(section => section.HighCount)
            .ThenByDescending(section => section.TotalCount)
            .ThenBy(section => section.CategoryName)
            .ToList();

        return new IssueGroup
        {
            GroupName = group.Key,
            GroupIcon = GetGroupIcon(group.Key),
            GroupColor = GetGroupColor(group.Key),
            TotalCount = issues.Count,
            CriticalCount = issues.Count(issue => issue.Severity == IssueSeverity.Critical),
            HighCount = issues.Count(issue => issue.Severity == IssueSeverity.High),
            MediumCount = issues.Count(issue => issue.Severity == IssueSeverity.Medium),
            LowCount = issues.Count(issue => issue.Severity == IssueSeverity.Low),
            Issues = new ObservableCollection<AuditIssueEnhanced>(issues),
            CategorySections = new ObservableCollection<IssueCategorySection>(sections)
        };
    }

    private static string GetGroupIcon(string groupName)
    {
        return groupName switch
        {
            "Security Issues" => "",
            "System Issues" => "",
            "Application Issues" => "",
            "Network Issues" => "",
            _ => ""
        };
    }

    private static string GetGroupColor(string groupName)
    {
        return groupName switch
        {
            "Security Issues" => "#DC2626",
            "System Issues" => "#0EA5E9",
            "Application Issues" => "#8B5CF6",
            "Network Issues" => "#0EA5E9",
            _ => "#6B7280"
        };
    }

    private static int GetIssueGroupOrder(string groupName)
    {
        return groupName switch
        {
            "Security Issues" => 0,
            "System Issues" => 1,
            "Application Issues" => 2,
            "Network Issues" => 3,
            _ => 4
        };
    }

    private static int ReadMetadataInt(AuditResult result, string key)
    {
        if (result.Metadata?.TryGetValue(key, out var value) != true)
        {
            return 0;
        }

        if (value.ValueKind == System.Text.Json.JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        return 0;
    }

    private static string ReadMetadataString(AuditResult result, string key)
    {
        if (result.Metadata?.TryGetValue(key, out var value) != true)
        {
            return "—";
        }

        return value.ValueKind == System.Text.Json.JsonValueKind.String
            ? value.GetString() ?? "—"
            : "—";
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
        _schedulerService.AuditCompleted -= OnAuditCompleted;
        _schedulerService.AuditFailed -= OnAuditFailed;
        _schedulerService.AuditProgress -= OnAuditProgress;
    }
}
