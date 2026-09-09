using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed record AiKernelStatus(string Kernel, bool Installed, string Version, string Path);

/// <summary>Installs optional Codex and Pi command-line kernels outside the application package.</summary>
public sealed class KernelManagerService
{
    private static readonly HttpClient Client = CreateClient();
    private readonly string _kernelRoot;

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
        if (normalized == AiKernelCatalog.Http)
        {
            return new(normalized, true, "built-in", string.Empty);
        }

        string executableName = ExecutableName(normalized);
        string[] candidates =
        {
            Path.Combine(AppContext.BaseDirectory, executableName),
            Path.Combine(AppContext.BaseDirectory, "kernels", executableName),
            Path.Combine(_kernelRoot, normalized, executableName)
        };
        string path = candidates.FirstOrDefault(File.Exists) ?? candidates[^1];
        if (!File.Exists(path))
        {
            return new(normalized, false, string.Empty, path);
        }

        string version;
        try
        {
            version = FileVersionInfo.GetVersionInfo(path).FileVersion?.Trim() ?? string.Empty;
        }
        catch
        {
            version = string.Empty;
        }

        return new(normalized, true, string.IsNullOrWhiteSpace(version) ? "installed" : version, path);
    }

    public async Task<string> CheckLatestVersionAsync(string? kernel, CancellationToken cancellationToken = default)
    {
        string normalized = AiKernelCatalog.Normalize(kernel);
        if (normalized == AiKernelCatalog.Http)
        {
            return "built-in";
        }

        using var response = await Client.GetAsync(LatestReleaseUrl(normalized), cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return document.RootElement.TryGetProperty("tag_name", out var tag)
            ? tag.GetString()?.Trim() ?? "unknown"
            : "unknown";
    }

    public async Task<AiKernelStatus> DownloadOrUpdateAsync(
        string? kernel,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string normalized = AiKernelCatalog.Normalize(kernel);
        if (normalized == AiKernelCatalog.Http)
        {
            return GetStatus(normalized);
        }

        Directory.CreateDirectory(_kernelRoot);
        string tempZip = Path.Combine(_kernelRoot, $".{normalized}-{Guid.NewGuid():N}.zip");
        string tempDirectory = Path.Combine(_kernelRoot, $".{normalized}-{Guid.NewGuid():N}");
        string targetDirectory = Path.Combine(_kernelRoot, normalized);
        string targetPath = Path.Combine(targetDirectory, ExecutableName(normalized));
        try
        {
            string? expectedSha256 = null;
            try
            {
                var releaseAsset = await GetReleaseAssetAsync(normalized, cancellationToken);
                expectedSha256 = releaseAsset.Digest;
                using var response = await Client.GetAsync(releaseAsset.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
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
                    {
                        throw new InvalidDataException("AI kernel archive is larger than the supported limit.");
                    }

                    await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    if (contentLength is > 0)
                    {
                        progress?.Report(Math.Clamp(total / (double)contentLength.Value, 0, 1));
                    }
                }

                await destination.FlushAsync(cancellationToken);
            }
            catch (HttpRequestException) when (TryCopyBundledArchive(normalized, tempZip, out expectedSha256))
            {
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

            Directory.CreateDirectory(tempDirectory);
            string stagedPath = Path.Combine(tempDirectory, ExecutableName(normalized));
            using (var archive = ZipFile.OpenRead(tempZip))
            {
                var entry = FindExecutableEntry(normalized, archive.Entries);
                if (entry == null)
                    throw new InvalidDataException($"The {normalized} archive did not contain a supported Windows CLI executable.");

                using var input = entry.Open();
                using var output = new FileStream(stagedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                input.CopyTo(output);
            }

            if (new FileInfo(stagedPath).Length < 16 * 1024)
            {
                throw new InvalidDataException("The downloaded AI kernel executable is unexpectedly small.");
            }

            await VerifyExecutableAsync(normalized, stagedPath, cancellationToken);

            Directory.CreateDirectory(targetDirectory);
            File.Move(stagedPath, targetPath, true);
            progress?.Report(1);
            return GetStatus(normalized);
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
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("LocalSecurityAudit", "0.3.8"));
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

    private async Task<(string DownloadUrl, string Digest)> GetReleaseAssetAsync(
        string kernel,
        CancellationToken cancellationToken)
    {
        using var response = await Client.GetAsync(LatestReleaseUrl(kernel), cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));
        string archiveName = ArchiveName(kernel);
        foreach (var asset in document.RootElement.GetProperty("assets").EnumerateArray())
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
            if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(digest))
                break;
            return (url, digest.Trim());
        }

        throw new InvalidDataException($"The latest {kernel} release has no verified Windows archive digest.");
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
            ?? candidates.FirstOrDefault(entry => string.Equals(entry.Name, "codex-command-runner.exe", StringComparison.OrdinalIgnoreCase))
            ?? candidates.FirstOrDefault(entry => string.Equals(entry.Name, "codex.exe", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, true);
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task VerifyExecutableAsync(string kernel, string path, CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
        process.StartInfo.ArgumentList.Add("--version");
        if (!process.Start()) throw new InvalidDataException($"The {kernel} executable could not be started.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            throw;
        }

        string output = (await process.StandardOutput.ReadToEndAsync(timeout.Token)).Trim();
        if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            throw new InvalidDataException($"The {kernel} archive did not contain a runnable CLI executable.");
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
