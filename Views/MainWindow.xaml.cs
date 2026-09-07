using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media.Animation;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Services;
using LocalSecurityAudit.ViewModels;
using Windows.Graphics;
using Windows.UI.ViewManagement;

namespace LocalSecurityAudit.Views;

public sealed partial class MainWindow : Window
{
    private const double MinimumWidthDip = 1040;
    private const double MinimumHeightDip = 640;
    private const double InitialWidthDip = 1280;
    private const double InitialHeightDip = 820;

    private readonly SettingsService _settingsService;
    private readonly AuditSchedulerService _schedulerService;
    private TrayIcon? _trayIcon;
    private WindowSizeGuard? _sizeGuard;
    private bool _isClosed;
    private bool _isHiddenToTray;
    private bool _isClosing;
    private bool _isPaneToggling;
    private readonly UISettings _uiSettings = new();
    private readonly Dictionary<FrameworkElement, Action> _releaseStepBindings = new();

    public MainViewModel ViewModel { get; }

    public MainWindow(
        MainViewModel viewModel,
        SettingsService settingsService,
        AuditSchedulerService schedulerService)
    {
        ViewModel = viewModel;
        _settingsService = settingsService;
        _schedulerService = schedulerService;
        InitializeComponent();
        Root.DataContext = ViewModel;

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.Title = AppText.Get("Local Security Audit");
        ApplyInitialBounds();
        _sizeGuard = new WindowSizeGuard(this, MinimumWidthDip, MinimumHeightDip);
        ApplyWindowIcon();
        Closed += OnClosed;
        AppWindow.Closing += OnAppWindowClosing;
        _settingsService.SettingsChanged += OnSettingsChanged;
        AppText.Current.LanguageChanged += OnLanguageChanged;
        _schedulerService.AuditCompleted += OnAuditCompleted;
        _schedulerService.AuditFailed += OnAuditFailed;
        Root.ActualThemeChanged += OnActualThemeChanged;
        ApplyTheme(_settingsService.Current.Theme);
        ApplyLanguage();
        NavigateToStartupPage();
    }

    /// <summary>
    /// Opens the page named by a "--page=trends" style argument. Used by tooling and
    /// shortcuts; the dashboard remains the default.
    /// </summary>
    private void NavigateToStartupPage()
    {
        string? requested = Environment.GetCommandLineArgs()
            .Select(argument => argument.Trim())
            .FirstOrDefault(argument => argument.StartsWith("--page=", StringComparison.OrdinalIgnoreCase));
        string page = requested?["--page=".Length..].ToLowerInvariant() ?? "dashboard";

        switch (page)
        {
            case "trends":
                if (FindMenuItem("trends") is { } trendsItem)
                {
                    NavigateIfNeeded(typeof(TrendsPage), trendsItem);
                }
                else
                {
                    ContentFrame.Navigate(typeof(TrendsPage));
                }

                break;
            case "settings":
                if (AppNavigation.SettingsItem is NavigationViewItem settingsItem)
                {
                    NavigateIfNeeded(typeof(SettingsPage), settingsItem);
                }
                else
                {
                    ContentFrame.Navigate(typeof(SettingsPage));
                }

                break;
            default:
                ContentFrame.Navigate(typeof(DashboardPage));
                break;
        }
    }

    private NavigationViewItem? FindMenuItem(string tag)
    {
        return AppNavigation.MenuItems
            .OfType<NavigationViewItem>()
            .FirstOrDefault(item => string.Equals(item.Tag?.ToString(), tag, StringComparison.OrdinalIgnoreCase));
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ApplyInitialBounds();
        ApplyTitleBarTheme(Root.ActualTheme);
        InitializeTrayIcon();
        _ = ViewModel.LoadSavedTimeAsync(App.GetService<DataStorageService>());
    }

    private void OnNavigationSizeChanged(object sender, SizeChangedEventArgs e)
    {
        // Native PaneFooter precedes the footer menu; reserve two navigation rows and two footer rows.
        if (WorkflowHost != null) WorkflowHost.Height = Math.Max(160, e.NewSize.Height - 184);
    }

    private void OnPaneOpening(NavigationView sender, object args)
    {
        if (WorkflowHost != null) FadePaneLabels(0, 1, 180);
    }

    private void FadePaneLabels(float from, float to, int milliseconds)
    {
        bool motion = _uiSettings.AnimationsEnabled;
        var labels = _releaseStepBindings.Keys.Select(element => element.FindName("StepText"))
            .OfType<FrameworkElement>().Append(WorkflowHeading).Append(WorkflowSummary);
        foreach (var label in labels)
        {
            var visual = ElementCompositionPreview.GetElementVisual(label);
            visual.StopAnimation("Opacity");
            visual.Opacity = to;
            if (!motion) continue;
            var fade = visual.Compositor.CreateScalarKeyFrameAnimation();
            fade.InsertKeyFrame(0, from);
            fade.InsertKeyFrame(1, to);
            fade.Duration = TimeSpan.FromMilliseconds(milliseconds);
            visual.StartAnimation("Opacity", fade);
        }
    }

    private async Task TogglePaneAsync()
    {
        if (_isPaneToggling) return;
        _isPaneToggling = true;
        try
        {
            if (ViewModel.IsPaneOpen && _uiSettings.AnimationsEnabled)
            {
                FadePaneLabels(1, 0, 120);
                await Task.Delay(120);
            }
            if (!_isClosed) ViewModel.IsPaneOpen = !ViewModel.IsPaneOpen;
        }
        finally { _isPaneToggling = false; }
    }

    private void AnimateStepEntry(FrameworkElement element)
    {
        if (!_uiSettings.AnimationsEnabled) return;
        ElementCompositionPreview.SetIsTranslationEnabled(element, true);
        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;
        var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0.16f, 1), new Vector2(0.3f, 1));
        var fade = compositor.CreateScalarKeyFrameAnimation();
        fade.InsertKeyFrame(0, 0.55f);
        fade.InsertKeyFrame(1, 1, easing);
        fade.Duration = TimeSpan.FromMilliseconds(180);
        visual.StartAnimation("Opacity", fade);
        var slide = compositor.CreateScalarKeyFrameAnimation();
        slide.InsertKeyFrame(0, 4);
        slide.InsertKeyFrame(1, 0, easing);
        slide.Duration = fade.Duration;
        visual.StartAnimation("Translation.Y", slide);
    }

    private void OnScanStepLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement element || element.DataContext is not ScanStep step
            || _releaseStepBindings.ContainsKey(element)) return;
        var meter = (ProgressBar)element.FindName("BatchProgress");
        var ring = (ProgressRing)element.FindName("ActiveRing");
        var staticIcon = (FontIcon)element.FindName("StaticActiveIcon");
        var previousState = step.State;
        double previousPercent = step.Percent;
        Storyboard? animation = null;
        meter.Value = step.Percent;

        void UpdatePresentation()
        {
            bool motion = _uiSettings.AnimationsEnabled;
            ring.IsActive = step.IsActive && motion;
            staticIcon.Visibility = step.IsActive && !motion ? Visibility.Visible : Visibility.Collapsed;
            if (previousState != step.State)
            {
                previousState = step.State;
                if (step.State != AuditStepState.Pending) AnimateStepEntry(element);
            }
            if (previousPercent == step.Percent) return;
            previousPercent = step.Percent;
            double from = meter.Value;
            animation?.Stop();
            meter.Value = step.Percent;
            // Only confirmed batch counts animate; resets and disabled motion update immediately.
            if (!motion || step.Percent <= from) return;
            var tween = new DoubleAnimation
            {
                From = from, To = step.Percent, Duration = new Duration(TimeSpan.FromMilliseconds(220)),
                EnableDependentAnimation = true, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            Storyboard.SetTarget(tween, meter);
            Storyboard.SetTargetProperty(tween, "Value");
            animation = new Storyboard { FillBehavior = FillBehavior.Stop };
            animation.Children.Add(tween);
            animation.Begin();
        }

        PropertyChangedEventHandler changed = (_, _) => UpdatePresentation();
        step.PropertyChanged += changed;
        _releaseStepBindings[element] = () => { step.PropertyChanged -= changed; animation?.Stop(); ring.IsActive = false; };
        UpdatePresentation();
    }

    private void OnScanStepUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement element && _releaseStepBindings.Remove(element, out var release)) release();
    }

    private async void NavigationView_ItemInvoked(
        NavigationView sender,
        NavigationViewItemInvokedEventArgs args)
    {
        if (args.IsSettingsInvoked)
        {
            if (AppNavigation.SettingsItem is NavigationViewItem settingsItem)
            {
                NavigateIfNeeded(typeof(SettingsPage), settingsItem);
            }
            else if (ContentFrame.CurrentSourcePageType != typeof(SettingsPage))
            {
                ContentFrame.Navigate(typeof(SettingsPage));
            }

            return;
        }

        if (args.InvokedItemContainer is not NavigationViewItem item)
        {
            return;
        }

        switch (item.Tag?.ToString())
        {
            case "toggle-pane":
                await TogglePaneAsync();
                break;
            case "dashboard":
                NavigateIfNeeded(typeof(DashboardPage), item);
                break;
            case "trends":
                NavigateIfNeeded(typeof(TrendsPage), item);
                break;
        }
    }

    private void OnSettingsChanged(object? sender, EventArgs e)
    {
        if (_isClosed)
        {
            return;
        }

        string theme = _settingsService.Current.Theme;
        DispatcherQueue.TryEnqueue(() =>
        {
            ApplyTheme(theme);
            ApplyLanguage();
            ApplyTrayIconVisibility();
        });
    }

    private void OnActualThemeChanged(FrameworkElement sender, object args)
    {
        ApplyTitleBarTheme(Root.ActualTheme);
    }

    private void ApplyLanguage()
    {
        AppWindow.Title = AppText.Get("Local Security Audit");
        Root.Language = AppText.Culture.Name;
        if (FindMenuItem("dashboard") is { } dashboardItem)
            dashboardItem.Content = AppText.Get("Dashboard");
        if (FindMenuItem("trends") is { } trendsItem)
            trendsItem.Content = AppText.Get("Trends");
        if (AppNavigation.SettingsItem is NavigationViewItem settingsItem)
            settingsItem.Content = AppText.Get("Settings");
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        if (!_isClosed) DispatcherQueue.TryEnqueue(ApplyLanguage);
    }

    private void OnAuditCompleted(object? sender, AuditCompletedEventArgs e)
    {
        if (_isClosed)
        {
            return;
        }

        DispatcherQueue.TryEnqueue(() =>
        {
            if (_isClosed || _trayIcon is null)
            {
                return;
            }

            var settings = _settingsService.Current;
            bool hasHighSeverityIssue = e.HasHighSeverityIssue && settings.HighSeverityNotification;
            if (settings.ScanCompleteNotification)
            {
                string message = AppText.Format("{0} issue(s) found in the latest audit.", e.Result.Findings.Count);
                if (hasHighSeverityIssue)
                {
                    message += AppText.Get(" High-severity findings require review.");
                }

                _trayIcon.ShowNotification(
                    AppText.Get("Local Security Audit"),
                    message,
                    isError: hasHighSeverityIssue);
            }
            else if (hasHighSeverityIssue)
            {
                _trayIcon.ShowNotification(
                    AppText.Get("High-severity issue detected"),
                    AppText.Get("Review the latest audit on the dashboard."),
                    isError: true);
            }
        });
    }

    private void OnAuditFailed(object? sender, AuditFailedEventArgs e)
    {
        if (_isClosed)
        {
            return;
        }

        DispatcherQueue.TryEnqueue(() =>
        {
            if (!_isClosed && _settingsService.Current.ScanCompleteNotification)
            {
                _trayIcon?.ShowNotification(AppText.Get("Audit failed"), e.Message, isError: true);
            }
        });
    }

    private void ContentFrame_NavigationFailed(object sender, NavigationFailedEventArgs e)
    {
        e.Handled = true;
        ContentFrame.Content = new TextBlock
        {
            Text = AppText.Format("Unable to open this section.\n{0}", e.Exception.Message),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(48, 32, 48, 32)
        };
    }

    private void ApplyTheme(string theme)
    {
        Root.RequestedTheme = theme switch
        {
            "dark" => ElementTheme.Dark,
            "light" => ElementTheme.Light,
            _ => ElementTheme.Default
        };

        ApplyTitleBarTheme(Root.ActualTheme);
    }

    private void ApplyTitleBarTheme(ElementTheme theme)
    {
        if (!AppWindowTitleBar.IsCustomizationSupported())
        {
            return;
        }

        var titleBar = AppWindow.TitleBar;
        titleBar.BackgroundColor = Microsoft.UI.Colors.Transparent;
        titleBar.InactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
        titleBar.ButtonBackgroundColor = Microsoft.UI.Colors.Transparent;
        titleBar.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
        bool dark = theme == ElementTheme.Dark
            || (theme == ElementTheme.Default && Application.Current.RequestedTheme == ApplicationTheme.Dark);
        var foreground = dark ? Microsoft.UI.Colors.White : Microsoft.UI.Colors.Black;
        var hoverBackground = dark
            ? Windows.UI.Color.FromArgb(0x1A, 0xFF, 0xFF, 0xFF)
            : Windows.UI.Color.FromArgb(0x1A, 0x00, 0x00, 0x00);

        titleBar.ButtonForegroundColor = foreground;
        titleBar.ButtonHoverForegroundColor = foreground;
        titleBar.ButtonHoverBackgroundColor = hoverBackground;
        titleBar.ButtonPressedForegroundColor = foreground;
        titleBar.ButtonPressedBackgroundColor = hoverBackground;
        titleBar.ButtonInactiveForegroundColor = dark
            ? Windows.UI.Color.FromArgb(0x80, 0xFF, 0xFF, 0xFF)
            : Windows.UI.Color.FromArgb(0x80, 0x00, 0x00, 0x00);
    }

    private void OnClosed(object sender, WindowEventArgs args)
    {
        _isClosed = true;
        ViewModel.Dispose();
        foreach (var release in _releaseStepBindings.Values) release();
        _releaseStepBindings.Clear();
        _sizeGuard?.Dispose();
        _sizeGuard = null;
        _settingsService.SettingsChanged -= OnSettingsChanged;
        AppText.Current.LanguageChanged -= OnLanguageChanged;
        _schedulerService.AuditCompleted -= OnAuditCompleted;
        _schedulerService.AuditFailed -= OnAuditFailed;
        Root.ActualThemeChanged -= OnActualThemeChanged;
        AppWindow.Closing -= OnAppWindowClosing;
        DisposeTrayIcon();
    }

    private void InitializeTrayIcon()
    {
        string iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");
        if (!System.IO.File.Exists(iconPath))
        {
            return;
        }

        try
        {
            _trayIcon = new TrayIcon(WinRT.Interop.WindowNative.GetWindowHandle(this), iconPath);
            _trayIcon.RestoreRequested += OnTrayRestoreRequested;
            _trayIcon.ExitRequested += OnTrayExitRequested;
            ApplyTrayIconVisibility();
        }
        catch
        {
            _trayIcon = null;
        }
    }

    private void ApplyTrayIconVisibility()
    {
        if (_trayIcon is null)
        {
            return;
        }

        var settings = _settingsService.Current;
        bool shouldShow = settings.MinimizeToTray
            || settings.HighSeverityNotification
            || settings.ScanCompleteNotification;

        try
        {
            if (shouldShow)
            {
                _trayIcon.Show();
            }
            else
            {
                _trayIcon.Hide();
            }
        }
        catch
        {
            // A missing or restarted notification area must not terminate the app.
        }
    }

    private void OnTrayRestoreRequested(object? sender, EventArgs e)
    {
        BringToFront();
    }

    /// <summary>Shows, restores and focuses the window, including when it was hidden to the tray.</summary>
    public void BringToFront()
    {
        if (_isClosed)
        {
            return;
        }

        AppWindow.Show();
        _isHiddenToTray = false;
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        ShowWindow(hwnd, 9); // SW_RESTORE
        Activate();
        SetForegroundWindow(hwnd);
        ApplyTrayIconVisibility();
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private void OnTrayExitRequested(object? sender, EventArgs e)
    {
        _isClosing = true;
        Close();
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_isClosing)
        {
            return;
        }

        if (!_isHiddenToTray
            && _settingsService.Current.MinimizeToTray
            && _trayIcon is not null)
        {
            try
            {
                _trayIcon.Show();
                _isHiddenToTray = true;
                AppWindow.Hide();
                args.Cancel = true;
            }
            catch
            {
                _isHiddenToTray = false;
            }
        }
    }

    private void DisposeTrayIcon()
    {
        if (_trayIcon is null)
        {
            return;
        }

        _trayIcon.RestoreRequested -= OnTrayRestoreRequested;
        _trayIcon.ExitRequested -= OnTrayExitRequested;
        _trayIcon.Dispose();
        _trayIcon = null;
    }

    private void ApplyInitialBounds()
    {
        double scale = Root.XamlRoot?.RasterizationScale ?? 1d;
        var displayArea = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary);
        var workArea = displayArea.WorkArea;
        int width = Math.Min((int)Math.Ceiling(InitialWidthDip * scale), workArea.Width);
        int height = Math.Min((int)Math.Ceiling(InitialHeightDip * scale), workArea.Height);
        int x = workArea.X + Math.Max(0, (workArea.Width - width) / 2);
        int y = workArea.Y + Math.Max(0, (workArea.Height - height) / 2);
        AppWindow.MoveAndResize(new RectInt32(x, y, width, height));
    }

    private void ApplyWindowIcon()
    {
        string iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");
        if (System.IO.File.Exists(iconPath))
        {
            AppWindow.SetIcon(iconPath);
        }
    }

    private void NavigateIfNeeded(Type pageType, NavigationViewItem item)
    {
        AppNavigation.SelectedItem = item;
        if (ContentFrame.CurrentSourcePageType != pageType)
        {
            ContentFrame.Navigate(pageType);
        }
    }
}
