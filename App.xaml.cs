using System;
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

    public static new App Current => (App)Application.Current;
    public IServiceProvider Services => _host.Services;

    public App()
    {
        InitializeComponent();

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices((context, services) =>
            {
                // Register ViewModels
                services.AddTransient<MainViewModel>();
                services.AddSingleton<DashboardViewModel>();
                services.AddSingleton<TrendsViewModel>();
                services.AddSingleton<SettingsViewModel>();

                // Register Services
                services.AddSingleton<SettingsService>();
                services.AddSingleton<DiagnosticLogService>();
                services.AddSingleton<EventLogService>();
                services.AddSingleton<AiAnalysisService>();
                services.AddSingleton(sp => DataStorageService.CreateAsync().GetAwaiter().GetResult());
                services.AddSingleton<AuditSchedulerService>();
                services.AddHostedService(serviceProvider =>
                    serviceProvider.GetRequiredService<AuditSchedulerService>());

                // Register Views
                services.AddTransient<MainWindow>();
            })
            .Build();

        // Start hosted services manually
        _host.StartAsync();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var mainWindow = _host.Services.GetRequiredService<MainWindow>();
        mainWindow.Activate();
    }

    public static T GetService<T>() where T : class
    {
        return Current.Services.GetRequiredService<T>();
    }
}
