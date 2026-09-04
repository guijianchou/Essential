using CommunityToolkit.Mvvm.ComponentModel;

namespace LocalSecurityAudit.ViewModels;

public partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private string title = "LocalSecurityAudit";
}
