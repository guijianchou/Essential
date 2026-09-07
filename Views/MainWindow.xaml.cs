using System;
using System.Linq;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Services;
using LocalSecurityAudit.ViewModels;
using Windows.Graphics;

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
            case "toggle-pane":
                ViewModel.IsPaneOpen = !ViewModel.IsPaneOpen;
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
