using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Dispatching;
using LocalSecurityAudit.ViewModels;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.Views;

public sealed partial class DashboardPageEnhanced : Page
{
    public DashboardViewModelEnhanced ViewModel { get; }

    public DashboardPageEnhanced()
    {
        this.InitializeComponent();

        var storageService = App.GetService<DataStorageService>();
        var schedulerService = App.GetService<AuditSchedulerService>();
        var dispatcherQueue = DispatcherQueue.GetForCurrentThread();

        ViewModel = new DashboardViewModelEnhanced(storageService, schedulerService, dispatcherQueue);
        _ = ViewModel.LoadDataCommand.ExecuteAsync(null);
    }
}
