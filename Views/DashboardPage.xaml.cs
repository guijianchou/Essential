using System;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using LocalSecurityAudit.ViewModels;
using LocalSecurityAudit.Models;
using Windows.Foundation;

namespace LocalSecurityAudit.Views;

public sealed partial class DashboardPage : Page
{
    public DashboardViewModel ViewModel { get; }

    public DashboardPage()
    {
        // Get ViewModel from DI
        ViewModel = App.Current.Services.GetService<DashboardViewModel>()
            ?? throw new InvalidOperationException("DashboardViewModel not registered");

        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
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

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(DashboardViewModel.HealthScore)
            or nameof(DashboardViewModel.HasAuditData))
        {
            ApplyHealthPresentation();
        }
    }

    private void ApplyHealthPresentation()
    {
        bool hasAuditData = ViewModel.HasAuditData;
        int score = Math.Clamp(ViewModel.HealthScore, 0, 100);
        HealthRing.Data = hasAuditData && score > 0
            ? CreateHealthGeometry(score)
            : null;
        HealthRing.Visibility = hasAuditData && score > 0
            ? Visibility.Visible
            : Visibility.Collapsed;

        string resourceKey = !hasAuditData
            ? "ControlStrongStrokeColorDefaultBrush"
            : score >= 80
                ? "SystemFillColorSuccessBrush"
                : score >= 50
                    ? "SystemFillColorCautionBrush"
                    : "SystemFillColorCriticalBrush";
        if (Application.Current.Resources[resourceKey] is Brush brush)
        {
            HealthRing.Stroke = brush;
            HealthScoreText.Foreground = brush;
        }
    }

    private static Geometry CreateHealthGeometry(int score)
    {
        const double size = 132;
        const double center = size / 2;
        const double radius = 62;

        if (score >= 100)
        {
            return new EllipseGeometry
            {
                Center = new Point(center, center),
                RadiusX = radius,
                RadiusY = radius
            };
        }

        double angle = score / 100d * Math.PI * 2d;
        var start = new Point(center, center - radius);
        var end = new Point(
            center + Math.Sin(angle) * radius,
            center - Math.Cos(angle) * radius);
        var figure = new PathFigure
        {
            StartPoint = start,
            IsClosed = false,
            IsFilled = false
        };
        figure.Segments.Add(new ArcSegment
        {
            Point = end,
            Size = new Size(radius, radius),
            IsLargeArc = score > 50,
            SweepDirection = SweepDirection.Clockwise
        });

        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        return geometry;
    }

    private void OnStatusBarClosed(InfoBar sender, object args)
    {
        ViewModel.IsStatusVisible = false;
    }
}
