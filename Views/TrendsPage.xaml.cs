using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using LiveChartsCore;
using LiveChartsCore.Drawing;
using LiveChartsCore.Measure;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView.WinUI;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Services;
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
        ConfigureCharts();
        ApplyTrendDot();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        ActualThemeChanged += OnActualThemeChanged;
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

    private void OnActualThemeChanged(FrameworkElement sender, object args)
    {
        ConfigureCharts();
        ApplyTrendDot();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(TrendsViewModel.TrendDays)
            or nameof(TrendsViewModel.CategoryTotals))
        {
            ConfigureCharts();
        }
        else if (e.PropertyName == nameof(TrendsViewModel.TrendBand))
        {
            ApplyTrendDot();
        }
    }

    private void ApplyTrendDot()
    {
        string key = !ViewModel.HasData
            ? "TextFillColorTertiaryBrush"
            : ViewModel.TrendBand switch
            {
                HealthBand.Good => "HealthGoodBrush",
                HealthBand.Warning => "HealthWarningBrush",
                _ => "HealthRiskBrush"
            };

        var brush = ThemeResources.GetBrush(this, key);
        if (brush != null)
        {
            TrendDot.Fill = brush;
        }
    }

    private void ConfigureCharts()
    {
        var palette = ChartPalette.For(ActualTheme);
        var days = ViewModel.TrendDays;
        var labels = days.Select(day => day.Label).ToList();

        // Findings by day: one stacked column per day, most severe at the baseline.
        var high = days.Select(day => (double)day.High).ToArray();
        var medium = days.Select(day => (double)day.Medium).ToArray();
        var low = days.Select(day => (double)day.Low).ToArray();
        int maxTotal = days.Count == 0 ? 0 : days.Max(day => day.Total);
        var (findingsMax, findingsStep) = NiceAxis(maxTotal);

        FindingsChart.Series = new ISeries[]
        {
            StackedColumn(AppText.Get("High"), high, palette.High),
            StackedColumn(AppText.Get("Medium"), medium, palette.Medium),
            StackedColumn(AppText.Get("Low"), low, palette.Low)
        };
        FindingsChart.XAxes = new[] { CategoryAxis(labels, palette) };
        FindingsChart.YAxes = new[] { ValueAxis(findingsMax, findingsStep, palette) };
        ApplyChartChrome(FindingsChart, palette);

        // Health by day: a single line with gaps on days without a scan.
        var health = days.Select(day => day.HasData ? (double?)day.Health : null).ToArray();
        HealthChart.Series = new ISeries[]
        {
            new LineSeries<double?>
            {
                Name = AppText.Get("Health"),
                Values = health,
                Stroke = new SolidColorPaint(palette.Series) { StrokeThickness = 2 },
                Fill = new SolidColorPaint(palette.SeriesWash),
                GeometrySize = 9,
                GeometryFill = new SolidColorPaint(palette.Series),
                GeometryStroke = new SolidColorPaint(palette.Surface) { StrokeThickness = 2 },
                LineSmoothness = 0,
                EnableNullSplitting = true
            }
        };
        HealthChart.XAxes = new[] { CategoryAxis(labels, palette) };
        HealthChart.YAxes = new[] { ValueAxis(100, 25, palette) };
        ApplyChartChrome(HealthChart, palette);

        // Findings by category: single-hue horizontal bars, largest at the top.
        var totals = ViewModel.CategoryTotals.OrderBy(total => total.Count).ThenByDescending(total => total.Name).ToList();
        int maxCategory = totals.Count == 0 ? 0 : totals.Max(total => total.Count);
        var (categoryMax, categoryStep) = NiceAxis(maxCategory);
        CategoryChart.Series = new ISeries[]
        {
            new RowSeries<double>
            {
                Name = AppText.Get("Findings"),
                Values = totals.Select(total => (double)total.Count).ToArray(),
                Fill = new SolidColorPaint(palette.Series),
                Stroke = null,
                MaxBarWidth = 18,
                Rx = 3,
                Ry = 3,
                DataLabelsPaint = ChartPalette.TextPaint(palette.InkPrimary, localized: false),
                DataLabelsSize = ChartPalette.TextSize,
                DataLabelsPosition = DataLabelsPosition.End,
                DataLabelsPadding = new Padding(8, 0, 0, 0),
                DataLabelsFormatter = point => $"{point.Model:0}"
            }
        };
        CategoryChart.YAxes = new[]
        {
            new Axis
            {
                Labels = totals.Select(total => total.Name).ToList(),
                TextSize = ChartPalette.TextSize,
                LabelsPaint = LabelPaint(palette),
                SeparatorsPaint = null,
                TicksPaint = null,
                MinStep = 1,
                ForceStepToMin = true
            }
        };
        CategoryChart.XAxes = new[]
        {
            new Axis
            {
                MinLimit = 0,
                MaxLimit = categoryMax,
                MinStep = categoryStep,
                ForceStepToMin = true,
                LabelsPaint = null,
                SeparatorsPaint = new SolidColorPaint(palette.Grid) { StrokeThickness = 1 },
                TicksPaint = null
            }
        };
        ApplyChartChrome(CategoryChart, palette);
    }

    private static StackedColumnSeries<double> StackedColumn(string name, double[] values, SkiaSharp.SKColor color)
    {
        return new StackedColumnSeries<double>
        {
            Name = name,
            Values = values,
            Fill = new SolidColorPaint(color),
            Stroke = null,
            MaxBarWidth = 22,
            Rx = 0,
            Ry = 0
        };
    }

    private static Axis CategoryAxis(List<string> labels, ChartPalette palette)
    {
        return new Axis
        {
            Labels = labels,
            TextSize = ChartPalette.TextSize,
            LabelsPaint = LabelPaint(palette),
            SeparatorsPaint = null,
            TicksPaint = null,
            LabelsRotation = 0,
            MinStep = 1,
            ForceStepToMin = true,
            // Keep every day visible even when a series has gaps.
            MinLimit = -0.5,
            MaxLimit = Math.Max(0, labels.Count - 1) + 0.5
        };
    }

    private static Axis ValueAxis(double maximum, double step, ChartPalette palette)
    {
        return new Axis
        {
            MinLimit = 0,
            MaxLimit = maximum,
            MinStep = step,
            ForceStepToMin = true,
            TextSize = ChartPalette.TextSize,
            LabelsPaint = ChartPalette.TextPaint(palette.InkSecondary, localized: false),
            SeparatorsPaint = new SolidColorPaint(palette.Grid) { StrokeThickness = 1 },
            TicksPaint = null,
            Labeler = value => value.ToString("0")
        };
    }

    private static SolidColorPaint LabelPaint(ChartPalette palette)
    {
        return ChartPalette.TextPaint(palette.InkSecondary);
    }

    private static void ApplyChartChrome(CartesianChart chart, ChartPalette palette)
    {
        chart.LegendPosition = LegendPosition.Hidden;
        chart.TooltipPosition = TooltipPosition.Top;
        chart.TooltipTextPaint = ChartPalette.TextPaint(palette.InkPrimary);
        chart.TooltipBackgroundPaint = new SolidColorPaint(palette.TooltipBackground);
        chart.TooltipTextSize = ChartPalette.TextSize;
        chart.AnimationsSpeed = TimeSpan.FromMilliseconds(250);
    }

    /// <summary>Rounds an axis maximum to a clean step so gridlines land on whole numbers.</summary>
    private static (double Maximum, double Step) NiceAxis(int maximum)
    {
        if (maximum <= 4)
        {
            return (4, 1);
        }

        if (maximum <= 8)
        {
            return (8, 2);
        }

        double step = maximum <= 20 ? 5 : maximum <= 50 ? 10 : maximum <= 100 ? 20 : 50;
        return (Math.Ceiling(maximum / step) * step, step);
    }

    private void OnStatusBarClosed(InfoBar sender, object args)
    {
        ViewModel.IsStatusVisible = false;
    }
}
