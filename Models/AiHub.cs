using System;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace LocalSecurityAudit.Models;

public partial class AiTarget : ObservableObject
{
    [ObservableProperty]
    private string name = "";

    [ObservableProperty]
    private bool isActive;

    [ObservableProperty]
    private string baseUrl = "";

    [ObservableProperty]
    private string apiKey = "";

    [ObservableProperty]
    private string mode = "responses"; // "chat" or "responses"

    [ObservableProperty]
    private string model = "gpt-5.6-sol";

    [ObservableProperty]
    private string effort = "medium"; // low, medium, high, xhigh, max

    [ObservableProperty]
    private bool isExpanded;

    // Parent hub reference for RemoveTarget command
    public AiHub? ParentHub { get; set; }
}

public partial class AiHub : ObservableObject
{
    [ObservableProperty]
    private string name = "";

    [ObservableProperty]
    private ObservableCollection<AiTarget> targets = new();

    [ObservableProperty]
    private bool isExpanded;
}
