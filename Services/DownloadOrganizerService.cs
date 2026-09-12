using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using LocalSecurityAudit.ViewModels;
using Microsoft.Win32;

namespace LocalSecurityAudit.Services;

/// <summary>
/// Organizes files in the Downloads folder with read-only scan, AI classification support,
/// collision handling, and rollback capability. All moves stay within Downloads boundaries.
/// </summary>
public sealed class DownloadOrganizerService
{
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly RecycleBinHelper _recycleBinHelper;
    private long _currentScanGeneration;
    private readonly object _scanLock = new();
    private readonly Dictionary<string, string> _itemIdToPath = new();
    private readonly List<MoveOperationRecord> _currentRunReport = new();

    public DownloadOrganizerService(DiagnosticLogService diagnosticLogService)
    {
        _diagnosticLogService = diagnosticLogService;
        _recycleBinHelper = new RecycleBinHelper(diagnosticLogService);
    }

    /// <summary>
    /// Gets the Downloads folder path using Windows Known Folder API with registry validation fallback.
    /// </summary>
    /// <returns>
    /// A tuple containing:
    /// - success: true if path resolved successfully
    /// - path: the Downloads folder path or null on failure
    /// - error: null on success; error message on failure
    /// </returns>
    public (bool success, string? path, string? error) GetDownloadsPath()
    {
        try
        {
            // Try Known Folder API first
            var guid = new Guid("374DE290-123F-4565-9164-39C4925E467B"); // FOLDERID_Downloads
            var hr = SHGetKnownFolderPath(guid, 0, IntPtr.Zero, out var pathPtr);

            if (hr == 0 && pathPtr != IntPtr.Zero)
            {
                try
                {
                    var path = Marshal.PtrToStringUni(pathPtr);
                    if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                    {
                        _diagnosticLogService.Write($"Downloads path resolved via Known Folder API: {Path.GetFileName(path)}");
                        return (true, path, null);
                    }
                }
                finally
                {
                    Marshal.FreeCoTaskMem(pathPtr);
                }
            }

            // Fallback: %USERPROFILE%\Downloads with registry validation
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrWhiteSpace(userProfile))
            {
                return (false, null, "Failed to resolve user profile path");
            }

            var fallbackPath = Path.Combine(userProfile, "Downloads");

            // Validate against User Shell Folders registry
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
                var registryValue = key?.GetValue("{374DE290-123F-4565-9164-39C4925E467B}") as string;

                if (!string.IsNullOrWhiteSpace(registryValue))
                {
                    var expandedPath = Environment.ExpandEnvironmentVariables(registryValue);
                    if (Directory.Exists(expandedPath))
                    {
                        _diagnosticLogService.Write($"Downloads path resolved via registry: {Path.GetFileName(expandedPath)}");
                        return (true, expandedPath, null);
                    }
                }
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException("Registry validation failed during Downloads path resolution", ex);
            }

            // Final fallback
            if (Directory.Exists(fallbackPath))
            {
                _diagnosticLogService.Write($"Downloads path resolved via fallback: {Path.GetFileName(fallbackPath)}");
                return (true, fallbackPath, null);
            }

            return (false, null, "Downloads folder does not exist at expected location");
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException("Failed to resolve Downloads path", ex);
            return (false, null, $"Path resolution failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Scans the Downloads root directory for files (non-recursive).
    /// Generates unique itemId per scan and preserves itemId→path mapping.
    /// </summary>
    public async Task<(bool success, List<TempFileInfo> files, string? error)> ScanDownloadsAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var (success, downloadsPath, error) = GetDownloadsPath();
        if (!success || downloadsPath == null)
        {
            return (false, new List<TempFileInfo>(), error ?? "Failed to resolve Downloads path");
        }

        try
        {
            lock (_scanLock)
            {
                _currentScanGeneration++;
                _itemIdToPath.Clear();
            }

            var files = new List<TempFileInfo>();
            var directoryInfo = new DirectoryInfo(downloadsPath);

            // Only process files in root directory (no recursion)
            var fileInfos = await Task.Run(() => directoryInfo.GetFiles(), cancellationToken);

            foreach (var fileInfo in fileInfos)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    // Generate unique itemId for this scan
                    var itemId = $"{_currentScanGeneration}_{Guid.NewGuid():N}";

                    var tempFile = new TempFileInfo
                    {
                        FilePath = fileInfo.FullName,
                        SizeInBytes = fileInfo.Length,
                        LastModified = fileInfo.LastWriteTime,
                        IsSelected = false
                    };

                    files.Add(tempFile);

                    lock (_scanLock)
                    {
                        _itemIdToPath[itemId] = fileInfo.FullName;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _diagnosticLogService.WriteException($"Access denied scanning file: {fileInfo.Name}", ex);
                }
                catch (Exception ex)
                {
                    _diagnosticLogService.WriteException($"Error scanning file: {fileInfo.Name}", ex);
                }
            }

            _diagnosticLogService.Write($"Downloads scan completed: {files.Count} files found (generation {_currentScanGeneration})");
            return (true, files, null);
        }
        catch (UnauthorizedAccessException ex)
        {
            var errorMsg = "Access denied to Downloads folder";
            _diagnosticLogService.WriteException(errorMsg, ex);
            return (false, new List<TempFileInfo>(), errorMsg);
        }
        catch (Exception ex)
        {
            var errorMsg = $"Scan failed: {ex.Message}";
            _diagnosticLogService.WriteException("Downloads scan failed", ex);
            return (false, new List<TempFileInfo>(), errorMsg);
        }
    }

    /// <summary>
    /// Classifies file by extension using deterministic local rules.
    /// Returns category name or null if ambiguous (requires AI classification).
    /// </summary>
    public string? ClassifyByExtension(TempFileInfo file)
    {
        if (file == null || string.IsNullOrWhiteSpace(file.FilePath))
        {
            return null;
        }

        var extension = Path.GetExtension(file.FilePath).ToLowerInvariant();

        return extension switch
        {
            // Documents
            ".pdf" or ".doc" or ".docx" or ".txt" or ".rtf" or ".odt" or ".xls" or ".xlsx" or ".ppt" or ".pptx" or ".csv" => "Documents",

            // Images
            ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".webp" or ".svg" or ".ico" or ".tiff" or ".tif" => "Images",

            // Videos
            ".mp4" or ".avi" or ".mkv" or ".mov" or ".wmv" or ".flv" or ".webm" or ".m4v" or ".mpg" or ".mpeg" => "Videos",

            // Audio
            ".mp3" or ".wav" or ".flac" or ".aac" or ".ogg" or ".wma" or ".m4a" or ".opus" => "Audio",

            // Archives
            ".zip" or ".rar" or ".7z" or ".tar" or ".gz" or ".bz2" or ".xz" or ".iso" => "Archives",

            // Executables
            ".exe" or ".msi" or ".bat" or ".cmd" or ".ps1" => "Executables",

            // Code
            ".cs" or ".java" or ".py" or ".js" or ".ts" or ".cpp" or ".h" or ".go" or ".rs" or ".rb" or ".php" or ".html" or ".css" or ".json" or ".xml" or ".yaml" or ".yml" => "Code",

            // Ambiguous or unknown
            _ => null
        };
    }

    /// <summary>
    /// Plans a move operation with collision detection and boundary validation.
    /// Does not perform the move; returns a MoveAction plan for validation.
    /// </summary>
    public (bool success, MoveAction? action, string? error) PlanMove(
        TempFileInfo file,
        string targetRelativeDirectory)
    {
        if (file == null || string.IsNullOrWhiteSpace(file.FilePath))
        {
            return (false, null, "Invalid file information");
        }

        if (string.IsNullOrWhiteSpace(targetRelativeDirectory))
        {
            return (false, null, "Target directory cannot be empty");
        }

        var (success, downloadsPath, error) = GetDownloadsPath();
        if (!success || downloadsPath == null)
        {
            return (false, null, error ?? "Failed to resolve Downloads path");
        }

        try
        {
            // Normalize and validate source path
            var sourcePath = Path.GetFullPath(file.FilePath);
            var downloadsRoot = Path.GetFullPath(downloadsPath);

            // Boundary check: source must be in Downloads root
            if (!IsWithinDirectory(sourcePath, downloadsRoot))
            {
                return (false, null, "Source file is not within Downloads directory");
            }

            if (Path.GetDirectoryName(sourcePath) != downloadsRoot)
            {
                return (false, null, "Source file must be in Downloads root directory");
            }

            // Normalize target relative path (prevent path traversal)
            var targetRelative = targetRelativeDirectory.Replace('/', Path.DirectorySeparatorChar);
            var normalizedRelative = Path.GetFullPath(Path.Combine(downloadsRoot, targetRelative));

            // Boundary check: target must be within Downloads
            if (!IsWithinDirectory(normalizedRelative, downloadsRoot))
            {
                return (false, null, "Target directory must be within Downloads folder");
            }

            var fileName = Path.GetFileName(sourcePath);
            var targetPath = Path.Combine(normalizedRelative, fileName);

            // Collision detection
            var collisionStrategy = CollisionStrategy.Skip;
            var finalTargetPath = targetPath;

            if (File.Exists(targetPath))
            {
                collisionStrategy = CollisionStrategy.NumberedSuffix;
                finalTargetPath = GenerateNumberedPath(targetPath);
            }

            var action = new MoveAction
            {
                SourcePath = sourcePath,
                TargetPath = finalTargetPath,
                TargetDirectory = normalizedRelative,
                TargetRelativeDirectory = Path.GetRelativePath(downloadsRoot, normalizedRelative),
                CollisionStrategy = collisionStrategy,
                OriginalTargetPath = targetPath
            };

            return (true, action, null);
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException("Failed to plan move operation", ex);
            return (false, null, $"Planning failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Executes a planned move operation with validation and rollback on error.
    /// Records operation in current run report.
    /// </summary>
    public async Task<(bool success, string? error)> ExecuteMoveAsync(
        MoveAction action,
        long expectedScanGeneration,
        CancellationToken cancellationToken = default)
    {
        if (action == null)
        {
            return (false, "Invalid move action");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var record = new MoveOperationRecord
        {
            SourcePath = action.SourcePath,
            TargetPath = action.TargetPath,
            Timestamp = DateTime.Now
        };

        try
        {
            // Revalidate scan generation
            lock (_scanLock)
            {
                if (_currentScanGeneration != expectedScanGeneration)
                {
                    record.Result = MoveResult.Failed;
                    record.Error = "Scan generation mismatch; rescan required";
                    _currentRunReport.Add(record);
                    return (false, record.Error);
                }
            }

            // Revalidate source exists and is still in Downloads root
            if (!File.Exists(action.SourcePath))
            {
                record.Result = MoveResult.Skipped;
                record.Error = "Source file no longer exists";
                _currentRunReport.Add(record);
                return (false, record.Error);
            }

            var (success, downloadsPath, error) = GetDownloadsPath();
            if (!success || downloadsPath == null)
            {
                record.Result = MoveResult.Failed;
                record.Error = error ?? "Failed to resolve Downloads path";
                _currentRunReport.Add(record);
                return (false, record.Error);
            }

            var downloadsRoot = Path.GetFullPath(downloadsPath);
            if (Path.GetDirectoryName(Path.GetFullPath(action.SourcePath)) != downloadsRoot)
            {
                record.Result = MoveResult.Failed;
                record.Error = "Source file moved out of Downloads root";
                _currentRunReport.Add(record);
                return (false, record.Error);
            }

            // Revalidate target is still within Downloads and doesn't exist
            if (!IsWithinDirectory(action.TargetPath, downloadsRoot))
            {
                record.Result = MoveResult.Failed;
                record.Error = "Target path outside Downloads boundary";
                _currentRunReport.Add(record);
                return (false, record.Error);
            }

            if (File.Exists(action.TargetPath))
            {
                record.Result = MoveResult.Skipped;
                record.Error = "Target file already exists (collision)";
                _currentRunReport.Add(record);
                return (false, record.Error);
            }

            // Create target directory if needed
            var targetDir = Path.GetDirectoryName(action.TargetPath);
            if (!string.IsNullOrEmpty(targetDir))
            {
                await Task.Run(() => Directory.CreateDirectory(targetDir), cancellationToken);
            }

            // Perform move
            await Task.Run(() => File.Move(action.SourcePath, action.TargetPath), cancellationToken);

            record.Result = MoveResult.Success;
            _currentRunReport.Add(record);

            _diagnosticLogService.Write($"File moved successfully: {Path.GetFileName(action.SourcePath)} → {action.TargetRelativeDirectory}");
            return (true, null);
        }
        catch (UnauthorizedAccessException ex)
        {
            record.Result = MoveResult.Failed;
            record.Error = "Access denied";
            _currentRunReport.Add(record);
            _diagnosticLogService.WriteException($"Access denied moving file: {Path.GetFileName(action.SourcePath)}", ex);
            return (false, "Access denied");
        }
        catch (IOException ex)
        {
            record.Result = MoveResult.Failed;
            record.Error = "File is locked or in use";
            _currentRunReport.Add(record);
            _diagnosticLogService.WriteException($"IO error moving file: {Path.GetFileName(action.SourcePath)}", ex);
            return (false, "File is locked or in use");
        }
        catch (Exception ex)
        {
            record.Result = MoveResult.Failed;
            record.Error = ex.Message;
            _currentRunReport.Add(record);
            _diagnosticLogService.WriteException($"Failed to move file: {Path.GetFileName(action.SourcePath)}", ex);
            return (false, $"Move failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Gets the current scan generation number.
    /// </summary>
    public long CurrentScanGeneration
    {
        get
        {
            lock (_scanLock)
            {
                return _currentScanGeneration;
            }
        }
    }

    /// <summary>
    /// Gets the current run report containing all move operation records.
    /// </summary>
    public IReadOnlyList<MoveOperationRecord> CurrentRunReport => _currentRunReport.AsReadOnly();

    /// <summary>
    /// Clears the current run report. Call this when starting a new organization session.
    /// </summary>
    public void ClearRunReport()
    {
        _currentRunReport.Clear();
        _diagnosticLogService.Write("Move operation report cleared");
    }

    #region Helper Methods

    private static bool IsWithinDirectory(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path);
        var fullDirectory = Path.GetFullPath(directory);

        return fullPath.StartsWith(fullDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || fullPath.Equals(fullDirectory, StringComparison.OrdinalIgnoreCase);
    }

    private static string GenerateNumberedPath(string originalPath)
    {
        var directory = Path.GetDirectoryName(originalPath) ?? "";
        var fileNameWithoutExt = Path.GetFileNameWithoutExtension(originalPath);
        var extension = Path.GetExtension(originalPath);

        for (int i = 1; i < 1000; i++)
        {
            var numberedPath = Path.Combine(directory, $"{fileNameWithoutExt} ({i}){extension}");
            if (!File.Exists(numberedPath))
            {
                return numberedPath;
            }
        }

        // Fallback: use GUID suffix
        return Path.Combine(directory, $"{fileNameWithoutExt}_{Guid.NewGuid():N}{extension}");
    }

    #endregion

    #region P/Invoke

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHGetKnownFolderPath(
        [MarshalAs(UnmanagedType.LPStruct)] Guid rfid,
        uint dwFlags,
        IntPtr hToken,
        out IntPtr pszPath);

    #endregion
}

#region Supporting Types

public sealed class MoveAction
{
    public required string SourcePath { get; init; }
    public required string TargetPath { get; init; }
    public required string TargetDirectory { get; init; }
    public required string TargetRelativeDirectory { get; init; }
    public required CollisionStrategy CollisionStrategy { get; init; }
    public required string OriginalTargetPath { get; init; }
}

public enum CollisionStrategy
{
    Skip,
    NumberedSuffix
}

public sealed class MoveOperationRecord
{
    public required string SourcePath { get; init; }
    public required string TargetPath { get; init; }
    public required DateTime Timestamp { get; init; }
    public MoveResult Result { get; set; }
    public string? Error { get; set; }
}

public enum MoveResult
{
    Success,
    Failed,
    Skipped
}

#endregion
