using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

public partial class TrendsViewModel : ObservableObject
{
    private readonly DataStorageService _storageService;
    private readonly DispatcherQueue? _dispatcherQueue;

    [ObservableProperty]
    private ISeries[] issueCountSeries = Array.Empty<ISeries>();

    [ObservableProperty]
    private ISeries[] healthScoreSeries = Array.Empty<ISeries>();

    [ObservableProperty]
    private List<string> dateLabels = new();

    [ObservableProperty]
    private double averageIssueCount;

    [ObservableProperty]
    private double issueCountAxisMaximum = 1;

    [ObservableProperty]
    private double averageHealthScore = 100;

    [ObservableProperty]
    private string trendStatus = "No data";

    [ObservableProperty]
    private bool isLoading;

    [ObservableProperty]
    private bool isStatusVisible;

    [ObservableProperty]
    private InfoBarSeverity statusSeverity = InfoBarSeverity.Informational;

    [ObservableProperty]
    private string statusMessage = "Ready";

    public TrendsViewModel(DataStorageService storageService)
    {
        _storageService = storageService;
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
    }

    [RelayCommand]
    private async Task LoadDataAsync()
    {
        if (_dispatcherQueue is { HasThreadAccess: false })
        {
            _dispatcherQueue.TryEnqueue(() => _ = LoadDataCommand.ExecuteAsync(null));
            return;
        }

        if (IsLoading)
        {
            return;
        }

        IsLoading = true;
        IsStatusVisible = true;
        StatusSeverity = InfoBarSeverity.Informational;
        StatusMessage = "Loading seven-day trend...";

        try
        {
            var results = await _storageService.GetTrendsAsync(7);
            var dailyResults = results
                .GroupBy(r => r.Timestamp.ToLocalTime().Date)
                .Select(group => group.OrderByDescending(r => r.Timestamp).First())
                .OrderBy(r => r.Timestamp)
                .ToList();

            DateLabels = dailyResults.Select(r => r.Timestamp.ToLocalTime().ToString("MM/dd")).ToList();
            var issueCounts = dailyResults.Select(r => (double)r.Findings.Count).ToArray();
            var healthScores = dailyResults.Select(r => (double)r.HealthScore).ToArray();

            AverageIssueCount = issueCounts.Length > 0 ? issueCounts.Average() : 0;
            IssueCountAxisMaximum = issueCounts.Length > 0
                ? Math.Max(1, issueCounts.Max())
                : 1;
            AverageHealthScore = healthScores.Length > 0 ? healthScores.Average() : 100;
            TrendStatus = GetTrendStatus(healthScores);

            IssueCountSeries = new ISeries[]
            {
                new ColumnSeries<double>
                {
                    Name = "Issues",
                    Values = issueCounts,
                    Fill = new SolidColorPaint(new SKColor(255, 117, 90, 210)),
                    Stroke = new SolidColorPaint(new SKColor(255, 117, 90)) { StrokeThickness = 1 },
                    MaxBarWidth = 34,
                    Rx = 4,
                    Ry = 4
                }
            };
            HealthScoreSeries = new ISeries[]
            {
                new LineSeries<double>
                {
                    Name = "Health",
                    Values = healthScores,
                    Fill = new SolidColorPaint(new SKColor(32, 201, 166, 42)),
                    Stroke = new SolidColorPaint(new SKColor(32, 201, 166)) { StrokeThickness = 3 },
                    GeometryFill = new SolidColorPaint(new SKColor(32, 201, 166)),
                    GeometryStroke = new SolidColorPaint(new SKColor(255, 255, 255)) { StrokeThickness = 2 },
                    GeometrySize = 8,
                    LineSmoothness = 0.25
                }
            };

            StatusMessage = dailyResults.Count > 0
                ? $"Loaded {dailyResults.Count} days"
                : "No historical data";
            StatusSeverity = dailyResults.Count > 0
                ? InfoBarSeverity.Success
                : InfoBarSeverity.Informational;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Load failed: {ex.Message}";
            StatusSeverity = InfoBarSeverity.Error;
            IsStatusVisible = true;
            TrendStatus = "Unavailable";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private static string GetTrendStatus(double[] values)
    {
        if (values.Length < 2)
        {
            return "Not enough data";
        }

        double delta = values[^1] - values[0];
        if (delta > 5)
        {
            return "Improving";
        }

        if (delta < -5)
        {
            return "Needs attention";
        }

        return "Stable";
    }
}
