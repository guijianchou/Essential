using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.Measure;
using SkiaSharp;
using LocalSecurityAudit.ViewModels;

namespace LocalSecurityAudit.Views;

public sealed partial class TrendsPage : Page
{
    public TrendsViewModel ViewModel { get; }

    public TrendsPage()
    {
        ViewModel = App.Current.Services.GetService<TrendsViewModel>()
            ?? throw new InvalidOperationException("TrendsViewModel not registered");

        InitializeComponent();
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        ConfigureCharts();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        _ = ViewModel.LoadDataCommand.ExecuteAsync(null);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(TrendsViewModel.DateLabels)
            or nameof(TrendsViewModel.IssueCountSeries)
            or nameof(TrendsViewModel.HealthScoreSeries))
        {
            ConfigureCharts();
        }
    }

    private void ConfigureCharts()
    {
        var labels = ViewModel.DateLabels;
        var labelsPaint = new SolidColorPaint(new SKColor(140, 151, 165, 220));
        var separatorPaint = new SolidColorPaint(new SKColor(140, 151, 165, 45)) { StrokeThickness = 1 };
        var tickPaint = new SolidColorPaint(new SKColor(140, 151, 165, 90)) { StrokeThickness = 1 };
        IssueCountChart.XAxes = new List<Axis>
        {
            new Axis
            {
                Labels = labels,
                TextSize = 11,
                LabelsPaint = labelsPaint,
                SeparatorsPaint = null,
                TicksPaint = tickPaint,
                LabelsRotation = 0,
                MinStep = 1,
                ForceStepToMin = true
            }
        };
        IssueCountChart.YAxes = new List<Axis>
        {
            new Axis
            {
                TextSize = 11,
                MinLimit = 0,
                MaxLimit = ViewModel.IssueCountAxisMaximum,
                MinStep = 1,
                ForceStepToMin = true,
                LabelsPaint = labelsPaint,
                SeparatorsPaint = separatorPaint,
                TicksPaint = tickPaint,
                Labeler = value => value.ToString("0")
            }
        };
        IssueCountChart.Series = ViewModel.IssueCountSeries;
        IssueCountChart.AnimationsSpeed = TimeSpan.Zero;
        IssueCountChart.LegendPosition = LegendPosition.Hidden;
        IssueCountChart.TooltipPosition = TooltipPosition.Top;
        IssueCountChart.DrawMargin = new Margin(40, 12, 18, 34);

        HealthScoreChart.XAxes = new List<Axis>
        {
            new Axis
            {
                Labels = labels,
                TextSize = 11,
                LabelsPaint = labelsPaint,
                SeparatorsPaint = null,
                TicksPaint = tickPaint,
                LabelsRotation = 0,
                MinStep = 1,
                ForceStepToMin = true
            }
        };
        HealthScoreChart.YAxes = new List<Axis>
        {
            new Axis
            {
                TextSize = 11,
                MinLimit = 0,
                MaxLimit = 100,
                MinStep = 20,
                ForceStepToMin = true,
                LabelsPaint = labelsPaint,
                SeparatorsPaint = separatorPaint,
                TicksPaint = tickPaint,
                Labeler = value => value.ToString("0")
            }
        };
        HealthScoreChart.Series = ViewModel.HealthScoreSeries;
        HealthScoreChart.AnimationsSpeed = TimeSpan.Zero;
        HealthScoreChart.LegendPosition = LegendPosition.Hidden;
        HealthScoreChart.TooltipPosition = TooltipPosition.Top;
        HealthScoreChart.DrawMargin = new Margin(40, 12, 18, 34);
    }

    private void OnStatusBarClosed(InfoBar sender, object args)
    {
        ViewModel.IsStatusVisible = false;
    }
}
