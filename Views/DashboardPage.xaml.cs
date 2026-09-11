using System;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Services;
using LocalSecurityAudit.ViewModels;

namespace LocalSecurityAudit.Views;

public sealed partial class DashboardPage : Page
{
    private bool _isFindingDialogOpen;

    public DashboardViewModel ViewModel { get; }

    public DashboardPage()
    {
        ViewModel = App.Current.Services.GetService<DashboardViewModel>()
            ?? throw new InvalidOperationException("DashboardViewModel not registered");

        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        ApplyHealthPresentation();
        _ = ViewModel.LoadDataCommand.ExecuteAsync(null);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
    }

    private void OnActualThemeChanged(FrameworkElement sender, object args)
    {
        ApplyHealthPresentation();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(DashboardViewModel.HealthScore)
            or nameof(DashboardViewModel.HasAssessment)
            or nameof(DashboardViewModel.HealthBand))
        {
            ApplyHealthPresentation();
        }
        else if (e.PropertyName == nameof(DashboardViewModel.IsDateLoading))
        {
            // Keep date navigation available while only the result panels transition.
            ContentMotion.SetLoading(HealthScoreContent, ViewModel.IsDateLoading);
            ContentMotion.SetLoading(AuditSummaryContent, ViewModel.IsDateLoading);
            ContentMotion.SetLoading(AuditDetailsContent, ViewModel.IsDateLoading);
            ContentMotion.SetLoading(FindingsContent, ViewModel.IsDateLoading);
        }
    }

    private void ApplyHealthPresentation()
    {
        bool hasAuditData = ViewModel.HasAssessment;

        string brushKey = !hasAuditData
            ? "TextFillColorTertiaryBrush"
            : ViewModel.HealthBand switch
            {
                HealthBand.Good => "HealthGoodBrush",
                HealthBand.Warning => "HealthWarningBrush",
                _ => "HealthRiskBrush"
            };

        var brush = ThemeResources.GetBrush(this, brushKey);
        if (brush != null)
        {
            HealthDot.Fill = brush;
        }
    }

    private void OnFilterClick(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleButton button && button.Tag is string filter)
        {
            ViewModel.SetSeverityFilterCommand.Execute(filter);
            button.IsChecked = true;
        }
    }

    private void OnAuditDateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
    {
        if (ViewModel.SelectedAuditDate?.Date == args.NewDate?.Date) return;
        if (args.NewDate is { } date)
            ViewModel.SelectDayCommand.Execute(new DashboardDay { Date = date.Date });
        else
            ViewModel.SelectLatestCommand.Execute(null);
    }

    private void OnActivityRangeClick(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleButton { Tag: string range } button)
        {
            ViewModel.SetActivityRangeCommand.Execute(range);
            button.IsChecked = true;
        }
    }

    private void OnSourceFilterClick(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleButton button && button.Tag is string log)
        {
            ViewModel.SetSourceFilterCommand.Execute(log);
            button.IsChecked = true;
        }
    }

    private void OnFindingsViewClick(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleButton button && button.Tag is string view)
        {
            ViewModel.SetFindingsViewCommand.Execute(view);
            button.IsChecked = true;
        }
    }

    private async void OnFindingClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button
            || button.Tag is not AuditIssueEnhanced issue
            || XamlRoot == null
            || _isFindingDialogOpen)
        {
            return;
        }

        _isFindingDialogOpen = true;
        try
        {
            var dialog = new FindingDetailsDialog(issue, XamlRoot, ActualTheme);
            await dialog.ShowAsync();
        }
        catch (Exception ex)
        {
            App.GetService<DiagnosticLogService>().WriteException("Finding details could not be opened", ex);
            ViewModel.StatusSeverity = InfoBarSeverity.Error;
            ViewModel.StatusMessage = AppText.Get("Finding details could not be opened. Check the diagnostic log.");
            ViewModel.IsStatusVisible = true;
        }
        finally
        {
            _isFindingDialogOpen = false;
        }
    }

    private void OnStatusBarClosed(InfoBar sender, object args)
    {
        ViewModel.IsStatusVisible = false;
    }
}
