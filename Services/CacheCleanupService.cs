using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using LocalSecurityAudit.ViewModels;

namespace LocalSecurityAudit.Services;

/// <summary>
/// Provides whitelist-only cache scanning and safe cleanup via Recycle Bin.
/// Read-only scan phase followed by user confirmation before any deletion.
/// </summary>
public sealed class CacheCleanupService
{
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly RecycleBinHelper _recycleBinHelper;

    // Whitelist categories with their risk profile and reasons
    private static readonly List<CacheLocationDefinition> WhitelistDefinitions = new()
    {
        new("Current user temp", () => Path.GetTempPath(), RiskLevel.Low, "Standard temp directory, safe to clean"),
        new("LocalAppData temp", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"), RiskLevel.Low, "Windows temp cache"),
        new("Chrome cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cache"), RiskLevel.Medium, "Browser cache, may affect browsing speed"),
        new("Edge cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Cache"), RiskLevel.Medium, "Browser cache, may affect browsing speed"),
        new("Firefox cache", () => GetFirefoxCachePath(), RiskLevel.Medium, "Browser cache, may affect browsing speed"),
        new("npm cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "npm-cache"), RiskLevel.Low, "Package manager cache, safe to clean"),
        new("pip cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "pip", "cache"), RiskLevel.Low, "Package manager cache, safe to clean"),
        new("NuGet cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages"), RiskLevel.Medium, "Package cache, may slow builds until restored"),
        new("pnpm cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "pnpm", "cache"), RiskLevel.Low, "Package manager cache, safe to clean"),
        new("Thumbnail cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Explorer"), RiskLevel.Low, "Thumbnail cache, will regenerate"),
        new("Icon cache", () => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IconCache.db"), RiskLevel.Low, "Icon cache, will regenerate"),
    };

    // Forbidden paths - never scan these even if they appear in whitelist
    private static readonly HashSet<string> ForbiddenRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), // entire %LOCALAPPDATA%
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), // entire %USERPROFILE%
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        @"C:\Windows",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
    };

    public CacheCleanupService(
        DiagnosticLogService diagnosticLogService,
        RecycleBinHelper recycleBinHelper)
    {
        _diagnosticLogService = diagnosticLogService;
        _recycleBinHelper = recycleBinHelper;
    }

    /// <summary>
    /// Returns all whitelisted cache locations with expanded environment variables.
    /// Does NOT scan the filesystem, only returns path definitions.
    /// </summary>
    public List<CacheLocation> GetCacheLocations()
    {
        var locations = new List<CacheLocation>();

        foreach (var def in WhitelistDefinitions)
        {
            try
            {
                var path = def.PathResolver();
                if (string.IsNullOrWhiteSpace(path))
                {
                    _diagnosticLogService.Write($"CacheCleanup: Skipping {def.Name} - path resolver returned empty");
                    continue;
                }

                var normalizedPath = Path.GetFullPath(path);

                // Check if this is a forbidden root
                if (IsForbiddenPath(normalizedPath))
                {
                    _diagnosticLogService.Write($"CacheCleanup: REJECTED {def.Name} at '{Path.GetFileName(normalizedPath)}' - forbidden root directory");
                    locations.Add(new CacheLocation
                    {
                        Name = def.Name,
                        Path = normalizedPath,
                        Risk = def.Risk,
                        IsValid = false,
                        SkipReason = "Forbidden root directory (entire LOCALAPPDATA/USERPROFILE not allowed)"
                    });
                    continue;
                }

                // Check if path requires admin rights (system directories)
                if (RequiresAdmin(normalizedPath))
                {
                    _diagnosticLogService.Write($"CacheCleanup: Skipping {def.Name} at '{Path.GetFileName(normalizedPath)}' - requires admin");
                    locations.Add(new CacheLocation
                    {
                        Name = def.Name,
                        Path = normalizedPath,
                        Risk = def.Risk,
                        IsValid = false,
                        SkipReason = "Requires administrator privileges"
                    });
                    continue;
                }

                locations.Add(new CacheLocation
                {
                    Name = def.Name,
                    Path = normalizedPath,
                    Risk = def.Risk,
                    Reason = def.Reason,
                    IsValid = true
                });
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException($"CacheCleanup: Failed to resolve path for {def.Name}", ex);
                locations.Add(new CacheLocation
                {
                    Name = def.Name,
                    Path = "",
                    Risk = RiskLevel.Unknown,
                    IsValid = false,
                    SkipReason = $"Path resolution error: {ex.Message}"
                });
            }
        }

        return locations;
    }

    /// <summary>
    /// Scans only whitelisted cache locations and returns TempFileInfo list.
    /// Read-only operation - no files are modified or deleted.
    /// </summary>
    public List<TempFileInfo> ScanCache(CancellationToken ct = default)
    {
        var results = new List<TempFileInfo>();
        var locations = GetCacheLocations();

        _diagnosticLogService.Write($"CacheCleanup: Starting scan of {locations.Count} locations");

        foreach (var location in locations.Where(l => l.IsValid))
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (!Directory.Exists(location.Path) && !File.Exists(location.Path))
                {
                    _diagnosticLogService.Write($"CacheCleanup: Location does not exist: {Path.GetFileName(location.Path)}");
                    continue;
                }

                var isFile = File.Exists(location.Path);
                if (isFile)
                {
                    // Single file (e.g., IconCache.db)
                    var info = ScanSingleFile(location.Path, location.Name, location.Risk, ct);
                    if (info != null)
                    {
                        results.Add(info);
                    }
                }
                else
                {
                    // Directory - enumerate contents
                    var items = ScanDirectory(location.Path, location.Name, location.Risk, ct);
                    results.AddRange(items);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                _diagnosticLogService.WriteException($"CacheCleanup: Access denied to {Path.GetFileName(location.Path)}", ex);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException($"CacheCleanup: Error scanning {Path.GetFileName(location.Path)}", ex);
            }
        }

        _diagnosticLogService.Write($"CacheCleanup: Scan complete, found {results.Count} items");
        return results;
    }

    /// <summary>
    /// Calculates total size of a file or directory recursively.
    /// Returns 0 on error, logs exception details.
    /// </summary>
    public long CalculateSize(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                return new FileInfo(path).Length;
            }

            if (Directory.Exists(path))
            {
                var dirInfo = new DirectoryInfo(path);
                long totalSize = 0;

                try
                {
                    foreach (var file in dirInfo.EnumerateFiles("*", SearchOption.AllDirectories))
                    {
                        try
                        {
                            totalSize += file.Length;
                        }
                        catch (UnauthorizedAccessException)
                        {
                            // Skip inaccessible files
                        }
                        catch (FileNotFoundException)
                        {
                            // File deleted during scan
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    // Skip inaccessible subdirectories
                }

                return totalSize;
            }

            return 0;
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException($"CacheCleanup: Error calculating size for {Path.GetFileName(path)}", ex);
            return 0;
        }
    }

    /// <summary>
    /// Checks if a file is currently locked by another process.
    /// Returns true if locked, false if accessible.
    /// </summary>
    public bool IsFileLocked(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }

    /// <summary>
    /// Assesses risk level for a cache item based on age, size, location and lock status.
    /// Returns Low/Medium/High or Unknown if assessment fails.
    /// </summary>
    public RiskLevel AssessRisk(TempFileInfo item)
    {
        try
        {
            // Locked files are higher risk (may be in use)
            if (item.IsLocked)
            {
                return RiskLevel.High;
            }

            var age = DateTime.Now - item.LastModified;

            // Very recent files (< 1 hour) are higher risk
            if (age.TotalHours < 1)
            {
                return RiskLevel.Medium;
            }

            // Old files (> 30 days) in temp/cache are safe to clean
            if (age.TotalDays > 30)
            {
                return RiskLevel.Low;
            }

            // Large files (> 100 MB) warrant caution
            if (item.SizeInBytes > 100 * 1024 * 1024)
            {
                return RiskLevel.Medium;
            }

            // Browser caches and package caches
            var lowerPath = item.FilePath.ToLowerInvariant();
            if (lowerPath.Contains("chrome") || lowerPath.Contains("edge") || lowerPath.Contains("firefox"))
            {
                return RiskLevel.Medium;
            }

            if (lowerPath.Contains("nuget") || lowerPath.Contains("npm") || lowerPath.Contains("pip"))
            {
                return RiskLevel.Low;
            }

            // Default for temp directories
            return RiskLevel.Low;
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException($"CacheCleanup: Risk assessment failed for {Path.GetFileName(item.FilePath)}", ex);
            return RiskLevel.Unknown;
        }
    }

    /// <summary>
    /// Deletes cache items by moving them to Recycle Bin.
    /// Revalidates each item before deletion: still exists, not locked, still in whitelist.
    /// Returns list of (path, success, error) tuples.
    /// </summary>
    public List<CleanupResult> DeleteCacheItems(IEnumerable<TempFileInfo> items, CancellationToken ct = default)
    {
        var results = new List<CleanupResult>();
        var validLocations = GetCacheLocations()
            .Where(l => l.IsValid)
            .Select(l => l.Path)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                // Revalidate: still exists?
                if (!File.Exists(item.FilePath) && !Directory.Exists(item.FilePath))
                {
                    results.Add(new CleanupResult
                    {
                        Path = item.FilePath,
                        Success = false,
                        Error = "Item no longer exists"
                    });
                    continue;
                }

                // Revalidate: still in whitelist?
                var normalizedPath = Path.GetFullPath(item.FilePath);
                var isInWhitelist = validLocations.Any(wl => normalizedPath.StartsWith(wl, StringComparison.OrdinalIgnoreCase));
                if (!isInWhitelist)
                {
                    _diagnosticLogService.Write($"CacheCleanup: BLOCKED deletion of {Path.GetFileName(item.FilePath)} - no longer in whitelist");
                    results.Add(new CleanupResult
                    {
                        Path = item.FilePath,
                        Success = false,
                        Error = "Path not in whitelist"
                    });
                    continue;
                }

                // Revalidate: still unlocked?
                if (IsFileLocked(item.FilePath))
                {
                    results.Add(new CleanupResult
                    {
                        Path = item.FilePath,
                        Success = false,
                        Error = "File is locked"
                    });
                    continue;
                }

                // Perform deletion via Recycle Bin
                var (success, error) = _recycleBinHelper.MoveToRecycleBin(item.FilePath);
                results.Add(new CleanupResult
                {
                    Path = item.FilePath,
                    Success = success,
                    Error = error
                });
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException($"CacheCleanup: Unexpected error deleting {Path.GetFileName(item.FilePath)}", ex);
                results.Add(new CleanupResult
                {
                    Path = item.FilePath,
                    Success = false,
                    Error = $"Unexpected error: {ex.Message}"
                });
            }
        }

        return results;
    }

    #region Private helpers

    private TempFileInfo? ScanSingleFile(string filePath, string category, RiskLevel risk, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists)
            {
                return null;
            }

            var isLocked = IsFileLocked(filePath);

            return new TempFileInfo
            {
                FilePath = filePath,
                SizeInBytes = fileInfo.Length,
                LastModified = fileInfo.LastWriteTime,
                Category = category,
                IsLocked = isLocked,
                Risk = isLocked ? RiskLevel.High : risk,
                SkipReason = isLocked ? "File is locked" : null
            };
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException($"CacheCleanup: Error scanning file {Path.GetFileName(filePath)}", ex);
            return null;
        }
    }

    private List<TempFileInfo> ScanDirectory(string dirPath, string category, RiskLevel risk, CancellationToken ct)
    {
        var results = new List<TempFileInfo>();

        try
        {
            var dirInfo = new DirectoryInfo(dirPath);
            if (!dirInfo.Exists)
            {
                return results;
            }

            // Enumerate files in directory (not recursive - just top level or add recursion if needed)
            foreach (var file in dirInfo.EnumerateFiles("*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    var isLocked = IsFileLocked(file.FullName);

                    results.Add(new TempFileInfo
                    {
                        FilePath = file.FullName,
                        SizeInBytes = file.Length,
                        LastModified = file.LastWriteTime,
                        Category = category,
                        IsLocked = isLocked,
                        Risk = isLocked ? RiskLevel.High : risk,
                        SkipReason = isLocked ? "File is locked" : null
                    });
                }
                catch (UnauthorizedAccessException)
                {
                    // Skip inaccessible files
                }
                catch (Exception ex)
                {
                    _diagnosticLogService.WriteException($"CacheCleanup: Error scanning file {file.Name}", ex);
                }
            }

            // Enumerate subdirectories
            foreach (var subDir in dirInfo.EnumerateDirectories("*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    var size = CalculateSize(subDir.FullName);
                    var isLocked = IsDirectoryLocked(subDir.FullName);

                    results.Add(new TempFileInfo
                    {
                        FilePath = subDir.FullName,
                        SizeInBytes = size,
                        LastModified = subDir.LastWriteTime,
                        Category = category,
                        IsLocked = isLocked,
                        Risk = isLocked ? RiskLevel.High : risk,
                        SkipReason = isLocked ? "Directory is locked" : null
                    });
                }
                catch (UnauthorizedAccessException)
                {
                    // Skip inaccessible directories
                }
                catch (Exception ex)
                {
                    _diagnosticLogService.WriteException($"CacheCleanup: Error scanning directory {subDir.Name}", ex);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            _diagnosticLogService.Write($"CacheCleanup: Access denied to directory {Path.GetFileName(dirPath)}");
        }
        catch (Exception ex)
        {
            _diagnosticLogService.WriteException($"CacheCleanup: Error enumerating directory {Path.GetFileName(dirPath)}", ex);
        }

        return results;
    }

    private bool IsDirectoryLocked(string dirPath)
    {
        try
        {
            // Try to enumerate files - if locked, this will fail
            var di = new DirectoryInfo(dirPath);
            _ = di.EnumerateFileSystemInfos().Take(1).Count();
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
        catch (IOException)
        {
            return true;
        }
    }

    private bool IsForbiddenPath(string path)
    {
        var normalizedPath = Path.GetFullPath(path);

        // Check if path IS a forbidden root (exact match)
        if (ForbiddenRoots.Contains(normalizedPath))
        {
            return true;
        }

        // Allow paths that are UNDER a forbidden root (subdirectories are OK)
        // This allows %LOCALAPPDATA%\Temp but blocks %LOCALAPPDATA% itself
        return false;
    }

    private bool RequiresAdmin(string path)
    {
        var lowerPath = path.ToLowerInvariant();
        return lowerPath.StartsWith(@"c:\windows\") ||
               lowerPath.StartsWith(@"c:\program files\") ||
               lowerPath.StartsWith(@"c:\program files (x86)\");
    }

    private static string GetFirefoxCachePath()
    {
        var firefoxProfilesDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Mozilla",
            "Firefox",
            "Profiles");

        if (!Directory.Exists(firefoxProfilesDir))
        {
            return "";
        }

        try
        {
            var profileDirs = Directory.GetDirectories(firefoxProfilesDir, "*.default*");
            if (profileDirs.Length > 0)
            {
                return Path.Combine(profileDirs[0], "cache2");
            }
        }
        catch
        {
            // Profile detection failed
        }

        return "";
    }

    #endregion
}

/// <summary>
/// Defines a cache location with its metadata.
/// </summary>
public sealed class CacheLocation
{
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public RiskLevel Risk { get; init; }
    public string Reason { get; init; } = "";
    public bool IsValid { get; init; }
    public string? SkipReason { get; init; }
}

/// <summary>
/// Result of a cleanup operation for a single item.
/// </summary>
public sealed class CleanupResult
{
    public string Path { get; init; } = "";
    public bool Success { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Risk level for cache items.
/// </summary>
public enum RiskLevel
{
    Unknown,
    Low,
    Medium,
    High
}

/// <summary>
/// Internal definition of a whitelisted cache location.
/// </summary>
internal sealed record CacheLocationDefinition(
    string Name,
    Func<string> PathResolver,
    RiskLevel Risk,
    string Reason
);
