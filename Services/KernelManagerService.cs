using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed record AiKernelStatus(string Kernel, bool Installed, string Version, string Path);
public sealed record AiKernelUpdateResult(AiKernelStatus Status, string LatestVersion, bool Changed, bool UsedBundledArchive = false);

/// <summary>Installs optional Codex and Pi command-line kernels outside the application package.</summary>
public sealed class KernelManagerService
{
    private static readonly HttpClient Client = CreateClient();
    private static readonly ConcurrentDictionary<string, (long Length, long Modified, string Version)> Versions = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _kernelRoot;
    private readonly HttpClient? _client;
    private readonly SemaphoreSlim _installGate = new(1, 1);

    internal KernelManagerService(string kernelRoot, HttpClient client)
    {
        _kernelRoot = Path.GetFullPath(kernelRoot);
        _client = client;
    }

    public KernelManagerService()
    {
        string dataRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalSecurityAudit");
        _kernelRoot = Path.Combine(dataRoot, "kernels");
    }

    public string KernelRoot => _kernelRoot;

    public AiKernelStatus GetStatus(string? kernel)
    {
        string normalized = AiKernelCatalog.Normalize(kernel);
        string executableName = ExecutableName(normalized);
        string[] candidates =
        {
            Path.Combine(_kernelRoot, normalized, executableName),
            Path.Combine(AppContext.BaseDirectory, executableName),
            Path.Combine(AppContext.BaseDirectory, "kernels", executableName)
        };
        string path = candidates.FirstOrDefault(candidate => IsCompleteInstallation(normalized, candidate))
            ?? candidates.FirstOrDefault(File.Exists) ?? candidates[0];
        if (!IsCompleteInstallation(normalized, path))
        {
            return new(normalized, false, string.Empty, path);
        }

        return new(normalized, true, ReadInstalledVersion(normalized, path), path);
    }

    public async Task<AiKernelStatus> GetStatusAsync(string? kernel, CancellationToken cancellationToken = default)
    {
        var status = GetStatus(kernel);
        if (!status.Installed) return status;
        string version = await VerifyExecutableAsync(status.Kernel, status.Path, cancellationToken);
        var file = new FileInfo(status.Path);
        Versions[status.Path] = (file.Length, file.LastWriteTimeUtc.Ticks, version);
        return status with { Version = version };
    }

    public async Task<string> CheckLatestVersionAsync(string? kernel, CancellationToken cancellationToken = default)
    {
        string normalized = AiKernelCatalog.Normalize(kernel);
        using var response = await (_client ?? Client).GetAsync(LatestReleaseUrl(normalized), cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return ReleaseVersion(document.RootElement);
    }

    public async Task<AiKernelUpdateResult> DownloadOrUpdateAsync(
        string? kernel,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        await _installGate.WaitAsync(cancellationToken);
        try { return await InstallIfNewerAsync(kernel, progress, cancellationToken); }
        finally { _installGate.Release(); }
    }

    private async Task<AiKernelUpdateResult> InstallIfNewerAsync(
        string? kernel, IProgress<double>? progress, CancellationToken cancellationToken)
    {
        string normalized = AiKernelCatalog.Normalize(kernel);
        var installed = await GetStatusAsync(normalized, cancellationToken);
        (string Version, string DownloadUrl, string Digest) release = (string.Empty, string.Empty, string.Empty);
        bool bundled = false;
        try
        {
            release = await GetReleaseAssetAsync(normalized, cancellationToken);
            if (installed.Installed && CompareVersions(installed.Version, release.Version) >= 0)
                return new(installed, release.Version, false);
            if (string.IsNullOrWhiteSpace(release.DownloadUrl) || release.Digest.Length != 64 || !release.Digest.All(Uri.IsHexDigit))
                throw new InvalidDataException($"The latest {normalized} release has no verified Windows archive digest.");
        }
        catch (HttpRequestException) when (!File.Exists(installed.Path) && BundledArchivePath(normalized) != null)
        {
            bundled = true;
        }

        Directory.CreateDirectory(_kernelRoot);
        string tempZip = Path.Combine(_kernelRoot, $".{normalized}-{Guid.NewGuid():N}.zip");
        string tempDirectory = Path.Combine(_kernelRoot, $".{normalized}-{Guid.NewGuid():N}");
        string targetDirectory = Path.Combine(_kernelRoot, normalized);
        string backupDirectory = Path.Combine(_kernelRoot, $".{normalized}-previous-{Guid.NewGuid():N}");
        string rootBoundary = Path.GetFullPath(_kernelRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (new[] { tempZip, tempDirectory, targetDirectory, backupDirectory }.Any(path =>
            !Path.GetFullPath(path).StartsWith(rootBoundary, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("Kernel installation path escaped its data directory.");
        try
        {
            string? expectedSha256 = bundled ? BundledArchiveSha256(normalized) : release.Digest;
            try
            {
                if (bundled)
                {
                    if (!TryCopyBundledArchive(normalized, tempZip, out expectedSha256))
                        throw new InvalidDataException("The bundled AI kernel archive is unavailable.");
                }
                else
                {
                    progress?.Report(0);
                    using var response = await (_client ?? Client).GetAsync(release.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                    response.EnsureSuccessStatusCode();
                    long? contentLength = response.Content.Headers.ContentLength;
                    await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
                    await using var destination = new FileStream(tempZip, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, true);
                    var buffer = new byte[64 * 1024];
                    long total = 0;
                    int read;
                    while ((read = await source.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
                    {
                        total += read;
                        if (total > 512L * 1024 * 1024)
                            throw new InvalidDataException("AI kernel archive is larger than the supported limit.");

                        await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                        if (contentLength is > 0)
                            progress?.Report(Math.Clamp(total / (double)contentLength.Value, 0, 1));
                    }

                    await destination.FlushAsync(cancellationToken);
                }
            }
            catch (HttpRequestException) when (!File.Exists(installed.Path) && TryCopyBundledArchive(normalized, tempZip, out expectedSha256))
            {
                bundled = true;
                progress?.Report(0.25);
            }

            if (string.IsNullOrWhiteSpace(expectedSha256))
            {
                throw new InvalidDataException("The AI kernel archive has no verified SHA-256 digest.");
            }

            string actualSha256 = await ComputeSha256Async(tempZip, cancellationToken);
            if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"The {normalized} archive SHA-256 does not match the official release digest.");
            }

            string stagedPath;
            using (var archive = ZipFile.OpenRead(tempZip))
            {
                stagedPath = ExtractKernelArchive(normalized, archive, tempDirectory);
            }

            if (new FileInfo(stagedPath).Length < 16 * 1024)
            {
                throw new InvalidDataException("The downloaded AI kernel executable is unexpectedly small.");
            }

            string version = await VerifyExecutableAsync(normalized, stagedPath, cancellationToken);
            if (!bundled && CompareVersions(version, release.Version) != 0)
                throw new InvalidDataException("The kernel executable version does not match its release.");
            var stagedFile = new FileInfo(stagedPath);
            await File.WriteAllTextAsync(Path.Combine(tempDirectory, "kernel-version.json"),
                JsonSerializer.Serialize(new { Version = version, Length = stagedFile.Length, Modified = stagedFile.LastWriteTimeUtc.Ticks }),
                cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();
            bool hadInstallation = Directory.Exists(targetDirectory);
            try { if (hadInstallation) await MoveKernelDirectoryAsync(targetDirectory, backupDirectory, cancellationToken); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new IOException(AppText.Get("The kernel installation is in use or cannot be replaced. Close active kernel processes and retry."), ex);
            }
            try { await MoveKernelDirectoryAsync(tempDirectory, targetDirectory, cancellationToken); }
            catch
            {
                if (hadInstallation && !Directory.Exists(targetDirectory))
                    await MoveKernelDirectoryAsync(backupDirectory, targetDirectory, CancellationToken.None);
                throw;
            }
            TryDeleteDirectory(backupDirectory);
            progress?.Report(1);
            return new(GetStatus(normalized), bundled ? string.Empty : release.Version, true, bundled);
        }
        finally
        {
            TryDeleteFile(tempZip);
            TryDeleteDirectory(tempDirectory);
        }
    }

    public string RequireExecutable(string? kernel)
    {
        var status = GetStatus(kernel);
        if (!status.Installed || string.IsNullOrWhiteSpace(status.Path))
        {
            throw new InvalidOperationException($"The {status.Kernel} AI kernel is not installed. Download it in Settings.");
        }

        return status.Path;
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("LocalSecurityAudit", "0.3.9"));
        return client;
    }

    private static string LatestReleaseUrl(string kernel) => kernel switch
    {
        AiKernelCatalog.Codex => "https://api.github.com/repos/openai/codex/releases/latest",
        AiKernelCatalog.Pi => "https://api.github.com/repos/earendil-works/pi/releases/latest",
        _ => throw new ArgumentOutOfRangeException(nameof(kernel))
    };

    private static string? BundledArchivePath(string kernel)
    {
        string fileName = kernel == AiKernelCatalog.Codex
            ? "codex-x86_64-pc-windows-msvc.exe.zip"
            : "pi-windows-x64.zip";
        string path = Path.Combine(AppContext.BaseDirectory, fileName);
        return File.Exists(path) ? path : null;
    }

    private static bool TryCopyBundledArchive(string kernel, string destination, out string? sha256)
    {
        sha256 = BundledArchiveSha256(kernel);
        string? source = BundledArchivePath(kernel);
        if (source == null)
        {
            return false;
        }

        File.Copy(source, destination, true);
        return true;
    }

    private static string ExecutableName(string kernel) => kernel == AiKernelCatalog.Codex ? "codex.exe" : "pi.exe";

    private static string? BundledArchiveSha256(string kernel) => kernel switch
    {
        // The Debug-only archives are the official assets used by the local kernel smoke test.
        AiKernelCatalog.Codex => "c016b0e6968b78586919c720d2685a03712f6d5f11bcd9d6f92c91eb8c41ba16",
        AiKernelCatalog.Pi => "002fa95b90d521245b9985d8f168caebc237ad56e7e30b319807dee1b2e17e1c",
        _ => null
    };

    private static string ParseVersion(string value)
    {
        var match = Regex.Match(value, @"(?<![\w.])\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?![\w.+-])");
        // GitHub tags can prefix the semantic version with 'v' or 'rust-v'.
        if (!match.Success && (value.StartsWith("rust-v", StringComparison.Ordinal) || value.StartsWith('v')))
            return ParseVersion(value[(value.StartsWith("rust-v", StringComparison.Ordinal) ? 6 : 1)..]);
        return match.Success ? match.Value : throw new InvalidDataException("The kernel version could not be determined.");
    }

    private static string ReleaseVersion(JsonElement release) => release.TryGetProperty("tag_name", out var tag)
        && tag.ValueKind == JsonValueKind.String ? ParseVersion(tag.GetString()!)
        : throw new InvalidDataException("The official release has no version tag.");

    internal static int CompareVersions(string local, string remote)
    {
        string[] left = ParseVersion(local).Split('+')[0].Split('-', 2);
        string[] right = ParseVersion(remote).Split('+')[0].Split('-', 2);
        int comparison = Version.Parse(left[0]).CompareTo(Version.Parse(right[0]));
        if (comparison != 0) return comparison;
        if (left.Length == 1 || right.Length == 1) return right.Length.CompareTo(left.Length);
        string[] leftParts = left[1].Split('.'), rightParts = right[1].Split('.');
        for (int i = 0; i < Math.Min(leftParts.Length, rightParts.Length); i++)
        {
            bool leftNumeric = leftParts[i].All(char.IsAsciiDigit), rightNumeric = rightParts[i].All(char.IsAsciiDigit);
            comparison = leftNumeric && rightNumeric
                ? leftParts[i].Length.CompareTo(rightParts[i].Length)
                : leftNumeric != rightNumeric ? (leftNumeric ? -1 : 1) : 0;
            if (comparison == 0) comparison = string.CompareOrdinal(leftParts[i], rightParts[i]);
            if (comparison != 0) return comparison;
        }
        return leftParts.Length.CompareTo(rightParts.Length);
    }

    private static string ReadInstalledVersion(string kernel, string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (Versions.TryGetValue(path, out var cached)
                && cached.Length == file.Length && cached.Modified == file.LastWriteTimeUtc.Ticks)
                return cached.Version;
            string manifest = Path.Combine(file.DirectoryName!, "kernel-version.json");
            if (File.Exists(manifest))
            {
                using var document = JsonDocument.Parse(File.ReadAllText(manifest));
                var root = document.RootElement;
                if (root.ValueKind == JsonValueKind.Object
                    && root.TryGetProperty("Length", out var length) && length.ValueKind == JsonValueKind.Number && length.TryGetInt64(out long savedLength) && savedLength == file.Length
                    && root.TryGetProperty("Modified", out var modified) && modified.ValueKind == JsonValueKind.Number && modified.TryGetInt64(out long ticks) && ticks == file.LastWriteTimeUtc.Ticks
                    && root.TryGetProperty("Version", out var version) && version.ValueKind == JsonValueKind.String)
                    return ParseVersion(version.GetString()!);
            }
            if (kernel == AiKernelCatalog.Pi)
            {
                using var package = JsonDocument.Parse(File.ReadAllText(Path.Combine(file.DirectoryName!, "package.json")));
                if (package.RootElement.ValueKind == JsonValueKind.Object
                    && package.RootElement.TryGetProperty("version", out var version) && version.ValueKind == JsonValueKind.String)
                    return ParseVersion(version.GetString()!);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { }
        return string.Empty;
    }

    private async Task<(string Version, string DownloadUrl, string Digest)> GetReleaseAssetAsync(
        string kernel,
        CancellationToken cancellationToken)
    {
        using var response = await (_client ?? Client).GetAsync(LatestReleaseUrl(kernel), cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
        string version = ReleaseVersion(document.RootElement);
        string archiveName = ArchiveName(kernel);
        if (!document.RootElement.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            return (version, string.Empty, string.Empty);
        foreach (var asset in assets.EnumerateArray())
        {
            if (!asset.TryGetProperty("name", out var name)
                || !string.Equals(name.GetString(), archiveName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string? digest = asset.TryGetProperty("digest", out var digestElement)
                ? digestElement.GetString()
                : null;
            if (!string.IsNullOrWhiteSpace(digest) && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
                digest = digest["sha256:".Length..];
            string? url = asset.TryGetProperty("browser_download_url", out var urlElement)
                ? urlElement.GetString()
                : null;
            return (version, url ?? string.Empty, digest?.Trim() ?? string.Empty);
        }

        return (version, string.Empty, string.Empty);
    }

    private static string ArchiveName(string kernel) => kernel switch
    {
        AiKernelCatalog.Codex => "codex-x86_64-pc-windows-msvc.exe.zip",
        AiKernelCatalog.Pi => "pi-windows-x64.zip",
        _ => throw new ArgumentOutOfRangeException(nameof(kernel))
    };

    private static ZipArchiveEntry? FindExecutableEntry(string kernel, IEnumerable<ZipArchiveEntry> entries)
    {
        var candidates = entries
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Name)
                && string.Equals(Path.GetExtension(entry.Name), ".exe", StringComparison.OrdinalIgnoreCase)
                && !entry.Name.Contains("sandbox", StringComparison.OrdinalIgnoreCase)
                && !entry.Name.Contains("setup", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (kernel == AiKernelCatalog.Pi)
        {
            return candidates.FirstOrDefault(entry => string.Equals(entry.Name, "pi.exe", StringComparison.OrdinalIgnoreCase));
        }

        return candidates.FirstOrDefault(entry => string.Equals(entry.Name, "codex-x86_64-pc-windows-msvc.exe", StringComparison.OrdinalIgnoreCase))
            ?? candidates.FirstOrDefault(entry => string.Equals(entry.Name, "codex.exe", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsCompleteInstallation(string kernel, string executable) => File.Exists(executable)
        && (kernel != AiKernelCatalog.Pi || new[] { "package.json", "theme/dark.json", "theme/light.json" }
            .All(relative => File.Exists(Path.Combine(Path.GetDirectoryName(executable)!, relative))));

    private static string ExtractKernelArchive(string kernel, ZipArchive archive, string directory)
    {
        var executable = FindExecutableEntry(kernel, archive.Entries)
            ?? throw new InvalidDataException($"The {kernel} archive did not contain a supported Windows CLI executable.");
        string boundary = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string prefix = executable.FullName[..(executable.FullName.LastIndexOf('/') + 1)];
        var entries = kernel == AiKernelCatalog.Pi
            ? archive.Entries.Where(entry => entry.FullName.StartsWith(prefix, StringComparison.Ordinal))
            : new[] { executable };
        long extractedBytes = 0;
        foreach (var entry in entries)
        {
            if (string.IsNullOrEmpty(entry.Name)) continue;
            extractedBytes = checked(extractedBytes + entry.Length);
            if (extractedBytes > 512L * 1024 * 1024) throw new InvalidDataException("Extracted kernel exceeds the supported limit.");
            string relative = entry == executable ? ExecutableName(kernel) : entry.FullName[prefix.Length..];
            string path = Path.GetFullPath(Path.Combine(directory, relative));
            if (!path.StartsWith(boundary, StringComparison.OrdinalIgnoreCase) || relative.Contains(':'))
                throw new InvalidDataException("Kernel archive contains an unsafe path.");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var input = entry.Open();
            using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            input.CopyTo(output);
        }
        string stagedPath = Path.Combine(directory, ExecutableName(kernel));
        if (!IsCompleteInstallation(kernel, stagedPath)) throw new InvalidDataException("Kernel archive is missing runtime resources.");
        return stagedPath;
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, true);
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task MoveKernelDirectoryAsync(string source, string destination, CancellationToken cancellationToken)
    {
        // Pi/Bun can leave the executable directory briefly locked after --version exits.
        // Retry only Windows access/sharing violations, with at most 3.1 seconds of delay.
        for (int attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                Directory.Move(source, destination);
                return;
            }
            catch (Exception ex) when (attempt < 5 && (ex is IOException or UnauthorizedAccessException)
                && (ex.HResult & 0xffff) is 5 or 32 or 33)
            {
                await Task.Delay(100 << attempt, cancellationToken);
            }
        }
    }

    private static async Task<string> VerifyExecutableAsync(string kernel, string path, CancellationToken cancellationToken)
    {
        string probeRoot = Path.Combine(Path.GetTempPath(), $"essential-kernel-version-{Guid.NewGuid():N}");
        Directory.CreateDirectory(probeRoot);
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = path,
                    WorkingDirectory = probeRoot,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            process.StartInfo.Environment["CODEX_HOME"] = probeRoot;
            process.StartInfo.Environment["PI_CODING_AGENT_DIR"] = probeRoot;
            process.StartInfo.Environment["PI_OFFLINE"] = "1";
            process.StartInfo.Environment["PI_SKIP_VERSION_CHECK"] = "1";
            process.StartInfo.Environment["PI_TELEMETRY"] = "0";
            process.StartInfo.ArgumentList.Add("--version");
            if (!process.Start()) throw new InvalidDataException($"The {kernel} executable could not be started.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
                string output = (await stdout).Trim();
                await stderr;
                if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
                    throw new InvalidDataException($"The {kernel} archive did not contain a runnable CLI executable.");
                return ParseVersion(output);
            }
            catch (OperationCanceledException)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                throw;
            }
        }
        finally { TryDeleteDirectory(probeRoot); }
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch { }
    }
}
