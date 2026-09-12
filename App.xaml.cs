using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.UI.Xaml;
using LocalSecurityAudit.Services;
using LocalSecurityAudit.ViewModels;
using LocalSecurityAudit.Views;

namespace LocalSecurityAudit;

public partial class App : Application
{
    private IHost _host;
    private MainWindow? _mainWindow;

    public static new App Current => (App)Application.Current;
    public IServiceProvider Services => _host.Services;

    public App(SettingsService settings)
    {
        InitializeComponent();

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices((context, services) =>
            {
                // Register ViewModels
                services.AddTransient<MainViewModel>();
                services.AddSingleton<DashboardViewModel>();
                services.AddSingleton<TrendsViewModel>();
                services.AddSingleton<OptimizationViewModel>();
                services.AddSingleton<SettingsViewModel>();

                // Register Services
                services.AddSingleton(settings);
                services.AddSingleton<DiagnosticLogService>();
                services.AddSingleton<KernelManagerService>();
                services.AddSingleton<EventLogService>();
                services.AddSingleton<AiAnalysisService>();
                services.AddSingleton(sp => DataStorageService.CreateAsync(settings.ActiveMode).GetAwaiter().GetResult());
                services.AddSingleton<AuditSchedulerService>();
                services.AddHostedService(serviceProvider =>
                    serviceProvider.GetRequiredService<AuditSchedulerService>());

                // Register Views
                services.AddTransient<MainWindow>();
            })
            .Build();

    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            // WinUI 1.4 cannot access Application.Resources in the App constructor.
            Resources["AppText"] = AppText.Current;
            _mainWindow = _host.Services.GetRequiredService<MainWindow>();
            _mainWindow.Activate();
            await _host.StartAsync();
        }
        catch (Exception ex)
        {
            _host.Services.GetRequiredService<DiagnosticLogService>()
                .WriteException("Main window startup failed", ex);
            throw;
        }
    }

    /// <summary>Brings the existing window to the front when a second launch is redirected here.</summary>
    public void ActivateMainWindow()
    {
        var window = _mainWindow;
        if (window == null)
        {
            return;
        }

        window.DispatcherQueue.TryEnqueue(window.BringToFront);
    }

    public async Task ExitForModeChangeAsync()
    {
        await _host.StopAsync();
        _mainWindow?.ExitApplication();
    }

    public static T GetService<T>() where T : class
    {
        return Current.Services.GetRequiredService<T>();
    }
}
