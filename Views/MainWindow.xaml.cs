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
using Microsoft.UI.Xaml.Media.Imaging;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Models;
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
        foreach (var task in HubTaskCatalog.Tasks)
            AppNavigation.MenuItems.Add(new NavigationViewItem
            {
                Tag = task.Id,
                Content = AppText.Get(task.Title),
                VerticalAlignment = VerticalAlignment.Top,
                Icon = new FontIcon { Glyph = task.Glyph, FontSize = 16 }
            });
        Root.DataContext = ViewModel;
        ViewModel.PropertyChanged += OnWorkflowPropertyChanged;

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.Title = ViewModel.WindowTitle;
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
        _uiSettings.ColorValuesChanged += OnSystemColorsChanged;
        ApplyTheme(_settingsService.Current.Theme);
        ApplyLanguage();
        NavigateToStartupPage();
    }

    /// <summary>
    /// Opens a requested page; old overview/trends shortcuts resolve to security audit.
    /// </summary>
    private void NavigateToStartupPage()
    {
        string? requested = Environment.GetCommandLineArgs()
            .Select(argument => argument.Trim())
            .FirstOrDefault(argument => argument.StartsWith("--page=", StringComparison.OrdinalIgnoreCase));
        string page = requested?["--page=".Length..].ToLowerInvariant() ?? "dashboard";

        switch (page)
        {
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
                NavigateIfNeeded(typeof(DashboardPage), FindMenuItem(HubTaskCatalog.SecurityAuditId)!);
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
        UpdateWorkflowHeight(AppNavigation.ActualHeight);
        ApplyTitleBarTheme(Root.ActualTheme);
        ApplyLogoTheme(Root.ActualTheme);
        ApplyLanguage();
        UpdateWorkflowPresentation();
        InitializeTrayIcon();
    }

    private void OnNavigationSizeChanged(object sender, SizeChangedEventArgs e)
        => UpdateWorkflowHeight(e.NewSize.Height);

    private void UpdateWorkflowHeight(double navigationHeight)
    {
        // Never bind the viewport limit to its own ancestor's ActualHeight: a hidden
        // workflow can retain a zero-height viewport when it becomes visible.
        double availableHeight = Math.Max(0, navigationHeight - 312);
        if (WorkflowHost != null) WorkflowHost.MaxHeight = availableHeight;
        if (WorkflowScroll != null) WorkflowScroll.MaxHeight = availableHeight;
        if (StepDetailsScroll != null) StepDetailsScroll.MaxHeight = Math.Clamp(availableHeight - 330, 48, 128);
    }

    private void OnExpandPaneClick(object sender, RoutedEventArgs e) => ViewModel.IsPaneOpen = true;

    private void OnWorkflowStepClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is ScanStep step) ViewModel.SelectedStep = step;
        ViewModel.IsPaneOpen = true;
    }

    private void OnWorkflowPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.IsPaneOpen))
            WorkflowHost.Padding = ViewModel.IsPaneOpen ? new Thickness(8, 0, 8, 0) : new Thickness(0);
        if (e.PropertyName == nameof(MainViewModel.SelectedStep))
        {
            StepDetailsScroll.ChangeView(0, 0, null, true);
            WorkflowScroll.ChangeView(0, 0, null, true);
        }
        if (e.PropertyName is nameof(MainViewModel.WorkflowTitle) or nameof(MainViewModel.SelectedStep)
            or nameof(MainViewModel.WorkflowPercent)) UpdateWorkflowPresentation();
    }

    private void UpdateWorkflowPresentation()
    {
        string? key = ViewModel.IsWorkflowFailed ? "HealthRiskBrush" : ViewModel.IsTranslationPending ? "SeverityMediumTextBrush"
            : ViewModel.IsWorkflowComplete || !ViewModel.Steps.Any(step => step.IsActive) && ViewModel.HasSavedResult ? "HealthGoodBrush" : null;
        if (key != null) WorkflowProgress.Foreground = ThemeResources.GetBrush(Root, key);
        else WorkflowProgress.ClearValue(Control.ForegroundProperty);
        WorkflowStatusIcon.Foreground = WorkflowProgress.Foreground;
        CompactWorkflowStatusIcon.Foreground = WorkflowProgress.Foreground;
        string? selectedKey = ViewModel.SelectedStep?.IsFailed == true ? "HealthRiskBrush"
            : ViewModel.SelectedStep?.IsDone == true ? "HealthGoodBrush" : null;
        if (selectedKey != null) SelectedStepProgress.Foreground = ThemeResources.GetBrush(Root, selectedKey);
        else SelectedStepProgress.ClearValue(Control.ForegroundProperty);
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
        var ring = (ProgressRing)element.FindName("ActiveRing");
        var staticIcon = (FontIcon)element.FindName("StaticActiveIcon");
        var title = (TextBlock)element.FindName("StepTitle");
        var status = (TextBlock)element.FindName("StepStatus");
        var previousState = step.State;

        void UpdatePresentation()
        {
            bool motion = _uiSettings.AnimationsEnabled;
            ring.IsActive = step.IsActive && motion;
            status.Foreground = step.IsFailed ? ThemeResources.GetBrush(element, "HealthRiskBrush")
                : step.IsDone ? ThemeResources.GetBrush(element, "HealthGoodBrush")
                : step.IsActive ? staticIcon.Foreground : title.Foreground;
            title.FontWeight = step.IsActive || step.IsFailed ? Microsoft.UI.Text.FontWeights.SemiBold : Microsoft.UI.Text.FontWeights.Normal;
            staticIcon.Visibility = step.IsActive && !motion ? Visibility.Visible : Visibility.Collapsed;
            if (previousState != step.State)
            {
                previousState = step.State;
                if (step.State != AuditStepState.Pending) AnimateStepEntry(element);
            }
        }

        PropertyChangedEventHandler changed = (_, _) => UpdatePresentation();
        void ThemeChanged(FrameworkElement sender, object args) => UpdatePresentation();
        step.PropertyChanged += changed;
        element.ActualThemeChanged += ThemeChanged;
        _releaseStepBindings[element] = () =>
        {
            step.PropertyChanged -= changed;
            element.ActualThemeChanged -= ThemeChanged;
            ring.IsActive = false;
        };
        UpdatePresentation();
    }

    private void OnScanStepUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement element && _releaseStepBindings.Remove(element, out var release)) release();
    }

    private void NavigationView_ItemInvoked(
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
            case HubTaskCatalog.SecurityAuditId:
                NavigateIfNeeded(typeof(DashboardPage), item);
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
        ApplyLogoTheme(Root.ActualTheme);
        UpdateWorkflowPresentation();
    }

    private void ApplyLanguage()
    {
        AppWindow.Title = ViewModel.WindowTitle;
        Root.Language = AppText.Culture.Name;
        foreach (var task in HubTaskCatalog.Tasks)
            if (FindMenuItem(task.Id) is { } item)
                item.Content = AppText.Get(task.Title);
        if (AppNavigation.SettingsItem is NavigationViewItem settingsItem)
        {
            settingsItem.Content = AppText.Get("Settings");
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(settingsItem, AppText.Get("Settings"));
            ToolTipService.SetToolTip(settingsItem, AppText.Get("Settings"));
        }
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
                    AppText.Get("Essential"),
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
        var systemBackground = _uiSettings.GetColorValue(UIColorType.Background);
        Root.RequestedTheme = theme switch
        {
            "dark" => ElementTheme.Dark,
            "light" => ElementTheme.Light,
            _ => systemBackground.R + systemBackground.G + systemBackground.B < 384 ? ElementTheme.Dark : ElementTheme.Light
        };

        ApplyLogoTheme(Root.ActualTheme);
        ApplyTitleBarTheme(Root.ActualTheme);
    }

    private void OnSystemColorsChanged(UISettings sender, object args)
    {
        if (!_isClosed && _settingsService.Current.Theme == "system")
            DispatcherQueue.TryEnqueue(() => { if (!_isClosed) ApplyTheme("system"); });
    }

    private void ApplyLogoTheme(ElementTheme theme)
    {
        bool dark = theme == ElementTheme.Dark
            || (theme == ElementTheme.Default && Application.Current.RequestedTheme == ApplicationTheme.Dark);
        string suffix = dark ? "dark" : "light";
        TitleBarLogo.Source = new BitmapImage(new Uri($"ms-appx:///Assets/logo-{suffix}-32.png"));
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
        ViewModel.PropertyChanged -= OnWorkflowPropertyChanged;
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
        _uiSettings.ColorValuesChanged -= OnSystemColorsChanged;
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
        => ExitApplication();

    public void ExitApplication()
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
