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

public class IssueCategorySection
{
    public string CategoryName { get; set; } = string.Empty;
    public string CategoryIcon { get; set; } = string.Empty;
    public string CategoryColor { get; set; } = string.Empty;
    public int TotalCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public ObservableCollection<AuditIssueEnhanced> Issues { get; set; } = new();
}

public class IssueGroup
{
    public string GroupName { get; set; } = string.Empty;
    public string GroupIcon { get; set; } = string.Empty;
    public string GroupColor { get; set; } = string.Empty;
    public int TotalCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public ObservableCollection<AuditIssueEnhanced> Issues { get; set; } = new();
    public ObservableCollection<IssueCategorySection> CategorySections { get; set; } = new();
}

public partial class DashboardViewModelEnhanced : ObservableObject, IDisposable
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
    private int highIssueCount;

    [ObservableProperty]
    private int mediumIssueCount;

    [ObservableProperty]
    private int lowIssueCount;

    [ObservableProperty]
    private int totalIssueCount;

    [ObservableProperty]
    private string searchText = string.Empty;

    [ObservableProperty]
    private string selectedCategoryFilter = "All";

    [ObservableProperty]
    private string selectedSeverityFilter = "All";

    public ObservableCollection<string> CategoryFilters { get; } = new()
    {
        "All", "Security Issues", "Configuration Issues", "System Issues", "Compliance Issues"
    };

    public ObservableCollection<string> SeverityFilters { get; } = new()
    {
        "All", "Critical", "High", "Medium", "Low", "Info"
    };

    private List<AuditIssueEnhanced> _allIssues = new();

    public DashboardViewModelEnhanced(
        DataStorageService storageService,
        AuditSchedulerService schedulerService,
        DispatcherQueue? dispatcherQueue = null)
    {
        _storageService = storageService;
        _schedulerService = schedulerService;
        _dispatcherQueue = dispatcherQueue;

        _schedulerService.AuditCompleted += OnAuditCompleted;
        _schedulerService.AuditFailed += (sender, e) => OnAuditFailed(sender, e.Message);
        _schedulerService.AuditProgress += (sender, e) => OnAuditProgress(sender, e.Message);
    }

    [RelayCommand]
    private async Task LoadDataAsync()
    {
        if (IsLoading)
            return;

        try
        {
            IsLoading = true;
            StatusMessage = "Loading audit data...";
            IsStatusVisible = true;

            var result = await _storageService.GetLatestResultAsync();
            if (result == null)
            {
                HasAuditData = false;
                ShowEmptyIssues = true;
                HealthScore = 100;
                HealthScoreText = "—";
                _allIssues.Clear();
                IssueGroups.Clear();
                UpdateSeverityCounts();
                return;
            }

            HasAuditData = true;
            ShowEmptyIssues = false;

            // Convert AuditIssue to AuditIssueEnhanced
            _allIssues = result.Findings
                .Select(issue => IssueCategorizer.CategorizeIssue(issue))
                .ToList();

            ApplyFilters();

            if (result.Metadata?.TryGetValue("HealthScore", out var scoreElement) == true)
            {
                if (scoreElement.ValueKind == JsonValueKind.Number && scoreElement.TryGetInt32(out int score))
                {
                    HealthScore = score;
                    HealthScoreText = $"{score}";
                }
                else
                {
                    HealthScore = result.HealthScore;
                    HealthScoreText = $"{result.HealthScore}";
                }
            }
            else
            {
                HealthScore = result.HealthScore;
                HealthScoreText = $"{result.HealthScore}";
            }

            UpdateSeverityCounts();
            UpdateSeverityChart();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error loading data: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
            IsStatusVisible = false;
        }
    }

    [RelayCommand]
    private async Task RunAuditAsync()
    {
        if (_isRunningScan)
            return;

        _isRunningScan = true;
        try
        {
            StatusMessage = "Starting audit...";
            IsStatusVisible = true;
            await _schedulerService.ExecuteAuditAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Audit failed: {ex.Message}";
        }
    }

    partial void OnSearchTextChanged(string value)
    {
        ApplyFilters();
    }

    partial void OnSelectedCategoryFilterChanged(string value)
    {
        ApplyFilters();
    }

    partial void OnSelectedSeverityFilterChanged(string value)
    {
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        var filtered = _allIssues.AsEnumerable();

        // Apply search filter
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.ToLowerInvariant();
            filtered = filtered.Where(i =>
                i.Title.ToLowerInvariant().Contains(search) ||
                i.Description.ToLowerInvariant().Contains(search) ||
                i.RootCause.ToLowerInvariant().Contains(search));
        }

        // Apply category filter
        if (SelectedCategoryFilter != "All")
        {
            filtered = filtered.Where(i => i.CategoryGroup == SelectedCategoryFilter);
        }

        // Apply severity filter
        if (SelectedSeverityFilter != "All")
        {
            filtered = filtered.Where(i => i.Severity.ToString() == SelectedSeverityFilter);
        }

        var filteredList = filtered.ToList();

        // Group by CategoryGroup
        var groups = filteredList
            .GroupBy(i => i.CategoryGroup)
            .Select(g => new IssueGroup
            {
                GroupName = g.Key,
                GroupIcon = g.First().CategoryIcon,
                GroupColor = g.First().CategoryColor,
                TotalCount = g.Count(),
                CriticalCount = g.Count(i => i.Severity == IssueSeverity.Critical),
                HighCount = g.Count(i => i.Severity == IssueSeverity.High),
                MediumCount = g.Count(i => i.Severity == IssueSeverity.Medium),
                LowCount = g.Count(i => i.Severity == IssueSeverity.Low),
                Issues = new ObservableCollection<AuditIssueEnhanced>(g.ToList())
            })
            .OrderByDescending(g => g.CriticalCount)
            .ThenByDescending(g => g.HighCount)
            .ToList();

        IssueGroups.Clear();
        foreach (var group in groups)
        {
            IssueGroups.Add(group);
        }

        TotalIssueCount = filteredList.Count;
    }

    private void UpdateSeverityCounts()
    {
        HighIssueCount = _allIssues.Count(i => i.Severity == IssueSeverity.High || i.Severity == IssueSeverity.Critical);
        MediumIssueCount = _allIssues.Count(i => i.Severity == IssueSeverity.Medium);
        LowIssueCount = _allIssues.Count(i => i.Severity == IssueSeverity.Low || i.Severity == IssueSeverity.Info);
    }

    private void UpdateSeverityChart()
    {
        var criticalCount = _allIssues.Count(i => i.Severity == IssueSeverity.Critical);
        var highCount = _allIssues.Count(i => i.Severity == IssueSeverity.High);
        var mediumCount = _allIssues.Count(i => i.Severity == IssueSeverity.Medium);
        var lowCount = _allIssues.Count(i => i.Severity == IssueSeverity.Low);
        var infoCount = _allIssues.Count(i => i.Severity == IssueSeverity.Info);

        SeverityPieSeries = new ISeries[]
        {
            new PieSeries<int>
            {
                Values = new[] { criticalCount },
                Name = "Critical",
                Fill = new SolidColorPaint(SKColor.Parse("#F97316"))
            },
            new PieSeries<int>
            {
                Values = new[] { highCount },
                Name = "High",
                Fill = new SolidColorPaint(SKColor.Parse("#DC2626"))
            },
            new PieSeries<int>
            {
                Values = new[] { mediumCount },
                Name = "Medium",
                Fill = new SolidColorPaint(SKColor.Parse("#F59E0B"))
            },
            new PieSeries<int>
            {
                Values = new[] { lowCount },
                Name = "Low",
                Fill = new SolidColorPaint(SKColor.Parse("#10B981"))
            },
            new PieSeries<int>
            {
                Values = new[] { infoCount },
                Name = "Info",
                Fill = new SolidColorPaint(SKColor.Parse("#3B82F6"))
            }
        };
    }

    private void OnAuditCompleted(object? sender, EventArgs e)
    {
        _isRunningScan = false;
        _dispatcherQueue?.TryEnqueue(async () =>
        {
            StatusMessage = "Audit completed successfully";
            await LoadDataAsync();
        });
    }

    private void OnAuditFailed(object? sender, string error)
    {
        _isRunningScan = false;
        _dispatcherQueue?.TryEnqueue(() =>
        {
            StatusMessage = $"Audit failed: {error}";
            IsStatusVisible = true;
        });
    }

    private void OnAuditProgress(object? sender, string message)
    {
        _dispatcherQueue?.TryEnqueue(() =>
        {
            StatusMessage = message;
            IsStatusVisible = true;
        });
    }

    public void Dispose()
    {
        _schedulerService.AuditCompleted -= OnAuditCompleted;
    }
}
