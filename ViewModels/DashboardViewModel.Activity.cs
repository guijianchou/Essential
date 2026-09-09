using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

public partial class DashboardViewModel
{
    private List<AuditActivityDay> _activity = new();
    private DateTime _activityToday = DateTime.Today;
    [ObservableProperty] private List<DashboardDay> activityDays = new();
    [ObservableProperty] private string activityScansText = "0";
    [ObservableProperty] private string activityFindingsText = "0";
    [ObservableProperty] private string activeDaysText = "0";
    [ObservableProperty] private string averageHealthText = "--";
    [ObservableProperty] private string activityHint = "";
    [ObservableProperty] private int activityColumns = 15;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRangeAll), nameof(IsRange30), nameof(IsRange7))]
    private int activityRangeDays = 30;
    public bool IsRangeAll => ActivityRangeDays == 0;
    public bool IsRange30 => ActivityRangeDays == 30;
    public bool IsRange7 => ActivityRangeDays == 7;

    [RelayCommand]
    private void SetActivityRange(string? range)
    {
        ActivityRangeDays = range switch { "7" => 7, "0" => 0, _ => 30 };
        RebuildActivity();
    }

    [RelayCommand]
    private void SelectLatest()
    {
        _selectedDate = null;
        OnPropertyChanged(nameof(SelectedAuditLabel));
        UpdateActivitySelection();
        _ = LoadDataCommand.ExecuteAsync(null);
    }

    private void ApplyActivity(List<AuditActivityDay> days, DateTime today)
    {
        _activity = days;
        _activityToday = today.Date;
        RebuildActivity();
    }

    private void RebuildActivity()
    {
        var days = _activity ?? new List<AuditActivityDay>();
        var today = _activityToday == default ? DateTime.Today : _activityToday;
        DateTime start = ActivityRangeDays == 0
            ? days.Count == 0 ? today.AddDays(-29) : days.Min(day => day.Date)
            : today.AddDays(1 - ActivityRangeDays);
        var visible = days.Where(day => day.Date >= start && day.Date <= today).ToList();
        ActivityScansText = visible.Sum(day => day.Scans).ToString("N0", AppText.Culture);
        ActivityFindingsText = visible.Sum(day => day.Findings).ToString("N0", AppText.Culture);
        ActiveDaysText = visible.Count(day => day.Scans > 0).ToString("N0", AppText.Culture);
        int assessed = visible.Sum(day => day.AssessedScans);
        AverageHealthText = assessed == 0 ? "--"
            : ((double)visible.Sum(day => day.ScoreSum) / assessed).ToString("0.0", AppText.Culture);

        // All-time totals stay all-time. Bound the visual grid to one year and state the cap explicitly.
        DateTime gridStart = start < today.AddDays(-364) ? today.AddDays(-364) : start;
        var byDate = visible.ToDictionary(day => day.Date);
        var dates = Enumerable.Range(0, Math.Max(0, (today - gridStart).Days + 1)).Select(index => gridStart.AddDays(index)).ToList();
        if (ActivityDays == null || !ActivityDays.Select(day => day.Date).SequenceEqual(dates))
            ActivityDays = dates.Select(date => new DashboardDay { Date = date }).ToList();
        foreach (var cell in ActivityDays)
        {
            byDate.TryGetValue(cell.Date, out var day);
            cell.Scans = day?.Scans ?? 0;
            cell.Findings = day?.Findings ?? 0;
            cell.RefreshLabels();
        }
        int rows = Math.Max(1, (int)Math.Ceiling(ActivityDays.Count / 15.0));
        ActivityColumns = Math.Max(1, (int)Math.Ceiling((double)ActivityDays.Count / rows));
        ActivityHint = AppText.Get(gridStart > start
            ? "Heatmap: latest 365 days. Totals include all retained history. Color indicates audit count, not safety."
            : "Each square is a day. Color indicates audit count, not safety. Select a day to inspect its latest audit.");
        UpdateActivitySelection();
    }

    private void UpdateActivitySelection()
    {
        DateTime? date = _selectedDate ?? _displayedResult?.Timestamp.ToLocalTime().Date;
        if (RecentDays != null)
            foreach (var day in RecentDays) day.IsSelected = day.Date == date;
        if (ActivityDays != null)
            foreach (var day in ActivityDays) day.IsSelected = day.Date == date;
        OnPropertyChanged(nameof(SelectedDayText));
    }
}
