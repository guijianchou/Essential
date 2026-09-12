using Microsoft.UI.Xaml.Controls;
using LocalSecurityAudit.ViewModels;

namespace LocalSecurityAudit.Views;

public sealed partial class OptimizationPage : Page
{
    public OptimizationViewModel ViewModel { get; }

    public OptimizationPage()
    {
        ViewModel = App.GetService<OptimizationViewModel>();
        InitializeComponent();
        DataContext = ViewModel;
    }

    private void ConfirmCleanup_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (ViewModel.CurrentPhase == ScanPhase.SelectingTargets && ViewModel.SelectedFiles.Count > 0)
        {
            ViewModel.CurrentPhase = ScanPhase.ExecutionPending;
        }
    }
}
