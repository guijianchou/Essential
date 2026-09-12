using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace LocalSecurityAudit.ViewModels;

public enum ScanPhase
{
    Idle,
    Scanning,
    SelectingTargets,
    AwaitingConfirmation,
    ExecutionPending
}

public sealed partial class OptimizationViewModel : ObservableObject
{
    private DispatcherQueue? _dispatcherQueue;

    [ObservableProperty]
    private ScanPhase _currentPhase = ScanPhase.Idle;

    [ObservableProperty]
    private ObservableCollection<TempFileInfo> _scannedFiles = new();

    partial void OnScannedFilesChanged(ObservableCollection<TempFileInfo> value)
    {
        OnPropertyChanged(nameof(HasScannedFiles));
        OnPropertyChanged(nameof(ScannedFilesSummary));
    }

    public bool HasScannedFiles => ScannedFiles.Count > 0;

    public string ScannedFilesSummary
    {
        get
        {
            if (ScannedFiles.Count == 0) return string.Empty;
            long totalSize = ScannedFiles.Sum(f => f.SizeInBytes);
            return $"{ScannedFiles.Count} files, {FormatFileSize(totalSize)}";
        }
    }

    [ObservableProperty]
    private ObservableCollection<string> _selectedFiles = new();

    [ObservableProperty]
    private long _estimatedSpace;

    public bool CanConfirmCleanup => CurrentPhase == ScanPhase.SelectingTargets && SelectedFiles.Count > 0;

    public bool IsExecutionPending => CurrentPhase == ScanPhase.ExecutionPending;

    partial void OnCurrentPhaseChanged(ScanPhase value)
    {
        OnPropertyChanged(nameof(CanConfirmCleanup));
        OnPropertyChanged(nameof(IsExecutionPending));
    }

    [RelayCommand]
    private void ConfirmCleanup()
    {
        CurrentPhase = ScanPhase.ExecutionPending;
    }

    [RelayCommand]
    private async Task ScanTempFilesAsync()
    {
        _dispatcherQueue ??= DispatcherQueue.GetForCurrentThread();

        CurrentPhase = ScanPhase.Scanning;
        ScannedFiles.Clear();

        await Task.Run(() =>
        {
            var tempPaths = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            };

            foreach (var tempPath in tempPaths)
            {
                if (!Directory.Exists(tempPath)) continue;

                try
                {
                    var files = Directory.GetFiles(tempPath, "*.*", SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        try
                        {
                            var fileInfo = new FileInfo(file);
                            var tempFileInfo = new TempFileInfo
                            {
                                FilePath = file,
                                SizeInBytes = fileInfo.Length,
                                LastModified = fileInfo.LastWriteTime,
                                IsSelected = false
                            };

                            _dispatcherQueue?.TryEnqueue(() => ScannedFiles.Add(tempFileInfo));
                        }
                        catch { /* Skip files that cannot be accessed */ }
                    }
                }
                catch { /* Skip directories that cannot be accessed */ }
            }
        });

        CurrentPhase = ScanPhase.SelectingTargets;
    }

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
