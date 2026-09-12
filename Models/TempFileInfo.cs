using CommunityToolkit.Mvvm.ComponentModel;
using System;

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

    public string SizeText => FormatFileSize(SizeInBytes);
    public string LastModifiedText => LastModified.ToString("yyyy-MM-dd HH:mm");

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
