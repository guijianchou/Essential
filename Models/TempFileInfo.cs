using CommunityToolkit.Mvvm.ComponentModel;
using System;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.ViewModels;

public partial class TempFileInfo : ObservableObject
{
    [ObservableProperty]
    private bool isSelected;

    [ObservableProperty]
    private string filePath = "";

    [ObservableProperty]
    private long sizeInBytes;

    [ObservableProperty]
    private DateTime lastModified;

    [ObservableProperty]
    private string category = "";

    [ObservableProperty]
    private bool isLocked;

    [ObservableProperty]
    private RiskLevel risk;

    [ObservableProperty]
    private string? skipReason;

    public string SizeText => FormatFileSize(SizeInBytes);
    public string LastModifiedText => LastModified.ToString("yyyy-MM-dd HH:mm");
    public string RiskText => Risk switch
    {
        RiskLevel.Low => "Low",
        RiskLevel.Medium => "Medium",
        RiskLevel.High => "High",
        RiskLevel.Unknown => "Unknown",
        _ => "Unknown"
    };

    private static string FormatFileSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}
