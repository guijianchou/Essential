using System;
using System.Collections.Generic;
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

/// <summary>One calendar day in the trend window, built from the latest scan of that day.</summary>
public sealed class TrendDay
{
    public DateTime Date { get; init; }
    public string Label { get; init; } = string.Empty;
    public bool HasData { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public int Total => High + Medium + Low;
    public int? Health { get; init; }
    public int Scans { get; init; }
    public int Events { get; init; }
}

public sealed class CategoryTotal
{
    public string Name { get; init; } = string.Empty;
    public int Count { get; init; }
}

public partial class TrendsViewModel : ObservableObject
{
    public const int WindowDays = 7;

    private readonly DataStorageService _storageService;
    private readonly DispatcherQueue? _dispatcherQueue;

    [ObservableProperty]
    private List<TrendDay> trendDays = new();

    [ObservableProperty]
    private List<CategoryTotal> categoryTotals = new();

    [ObservableProperty]
    private bool hasData;

    [ObservableProperty]
    private string scansText = "0";

    [ObservableProperty]
    private string scansDetailText = AppText.Get("in the past 7 days");

    [ObservableProperty]
    private string averageHealthText = "–";

    [ObservableProperty]
    private string averageHealthDetailText = AppText.Get("no scans yet");

    [ObservableProperty]
    private string findingsPerScanText = "–";

    [ObservableProperty]
    private string findingsPerScanDetailText = AppText.Get("no scans yet");

    [ObservableProperty]
    private string trendStatus = AppText.Get("No data");

    [ObservableProperty]
    private string trendDetailText = AppText.Get("Run a scan to start the history.");

    [ObservableProperty]
    private HealthBand trendBand = HealthBand.Good;

    [ObservableProperty]
    private double categoryChartHeight = 160;

    [ObservableProperty]
    private bool isLoading;

    [ObservableProperty]
    private bool isStatusVisible;

    [ObservableProperty]
    private InfoBarSeverity statusSeverity = InfoBarSeverity.Informational;

    [ObservableProperty]
    private string statusMessage = AppText.Get("Ready");

    public TrendsViewModel(DataStorageService storageService)
    {
        _storageService = storageService;
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
        AppText.Current.LanguageChanged += (_, _) =>
        {
            if (_dispatcherQueue is { HasThreadAccess: false })
                _dispatcherQueue.TryEnqueue(() => _ = LoadDataCommand.ExecuteAsync(null));
            else _ = LoadDataCommand.ExecuteAsync(null);
        };
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

        try
        {
            var results = await _storageService.GetTrendsAsync(WindowDays);
            var byDay = results
                .GroupBy(result => result.Timestamp.ToLocalTime().Date)
                .ToDictionary(group => group.Key, group => group.OrderBy(result => result.Timestamp).ToList());

            var today = DateTime.Today;
            var days = new List<TrendDay>();
            var categoryCounts = new Dictionary<string, int>();
            for (int offset = WindowDays - 1; offset >= 0; offset--)
            {
                var date = today.AddDays(-offset);
                string label = date == today ? AppText.Get("Today") : date.ToString("ddd d", AppText.Culture);
                if (!byDay.TryGetValue(date, out var dayResults))
                {
                    days.Add(new TrendDay { Date = date, Label = label, HasData = false });
                    continue;
                }

                var latest = dayResults[^1];
                var breakdown = HealthScoreCalculator.Calculate(latest.Findings);
                foreach (var finding in latest.Findings)
                {
                    string category = IssueCategorizer.CategorizeIssue(finding).CategoryLabel;
                    categoryCounts[category] = categoryCounts.TryGetValue(category, out int count) ? count + 1 : 1;
                }

                days.Add(new TrendDay
                {
                    Date = date,
                    Label = label,
                    HasData = true,
                    High = breakdown.HighCount,
                    Medium = breakdown.MediumCount,
                    Low = breakdown.LowCount,
                    Health = breakdown.Score,
                    Scans = dayResults.Count,
                    Events = ReadMetadataInt(latest, "EventCount")
                });
            }

            TrendDays = days;
            CategoryTotals = categoryCounts
                .Select(pair => new CategoryTotal { Name = pair.Key, Count = pair.Value })
                .OrderByDescending(total => total.Count)
                .ThenBy(total => total.Name)
                .ToList();
            CategoryChartHeight = Math.Max(160, 36 * CategoryTotals.Count + 32);

            var withData = days.Where(day => day.HasData).ToList();
            HasData = withData.Count > 0;

            int scans = results.Count;
            ScansText = scans.ToString("N0", AppText.Culture);
            ScansDetailText = withData.Count == 1
                ? AppText.Get("on 1 of 7 days")
                : AppText.Format("on {0} of 7 days", withData.Count);

            if (withData.Count > 0)
            {
                double averageHealth = withData.Average(day => day.Health ?? 0);
                AverageHealthText = Math.Round(averageHealth).ToString(AppText.Culture);
                AverageHealthDetailText = HealthScoreCalculator.GetVerdict((int)Math.Round(averageHealth)).ToLowerInvariant();

                double perScan = results.Average(result => result.Findings.Count);
                FindingsPerScanText = perScan.ToString(perScan >= 10 ? "0" : "0.#", AppText.Culture);
                FindingsPerScanDetailText = scans == 1 ? AppText.Get("from 1 scan") : AppText.Format("average across {0} scans", scans);
            }
            else
            {
                AverageHealthText = "–";
                AverageHealthDetailText = AppText.Get("no scans yet");
                FindingsPerScanText = "–";
                FindingsPerScanDetailText = AppText.Get("no scans yet");
            }

            UpdateTrendStatus(withData);

            IsStatusVisible = false;
        }
        catch (Exception ex)
        {
            StatusMessage = AppText.Format("Load failed: {0}", ex.Message);
            StatusSeverity = InfoBarSeverity.Error;
            IsStatusVisible = true;
            TrendStatus = AppText.Get("Unavailable");
            TrendDetailText = AppText.Get("The history could not be read.");
        }
        finally
        {
            IsLoading = false;
        }
    }

    private void UpdateTrendStatus(List<TrendDay> withData)
    {
        if (withData.Count == 0)
        {
            TrendStatus = AppText.Get("No data");
            TrendDetailText = AppText.Get("Run a scan to start the history.");
            TrendBand = HealthBand.Good;
            return;
        }

        var last = withData[^1];
        int lastHealth = last.Health ?? 0;
        if (withData.Count == 1)
        {
            TrendStatus = HealthScoreCalculator.GetVerdict(lastHealth);
            TrendBand = HealthScoreCalculator.GetBand(lastHealth);
            TrendDetailText = AppText.Format("Only one day of data ({0}, health {1}).", last.Label.ToLowerInvariant(), lastHealth);
            return;
        }

        var first = withData[0];
        int delta = lastHealth - (first.Health ?? 0);
        string firstLabel = first.Label == AppText.Get("Today") ? AppText.Get("today") : first.Label;
        string lastLabel = last.Label == AppText.Get("Today") ? AppText.Get("today") : last.Label;
        TrendDetailText = AppText.Format("Health {0} on {1} to {2} {3}.", first.Health, firstLabel, lastHealth, lastLabel);

        if (delta > 5)
        {
            TrendStatus = AppText.Get("Improving");
            TrendBand = HealthBand.Good;
        }
        else if (delta < -5)
        {
            TrendStatus = AppText.Get("Getting worse");
            TrendBand = lastHealth < HealthScoreCalculator.WarningThreshold ? HealthBand.Risk : HealthBand.Warning;
        }
        else
        {
            TrendStatus = AppText.Get("Stable");
            TrendBand = HealthScoreCalculator.GetBand(lastHealth);
        }
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
}
