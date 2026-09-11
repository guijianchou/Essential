# Real installer against generated CLIs, bundled Pi and in-memory HTTP responses.
# Every installation and archive lives in this test's temporary directory.
param([string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll")
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$managerType = $assembly.GetType('LocalSecurityAudit.Services.KernelManagerService', $true)
$flags = [Reflection.BindingFlags]'NonPublic,Instance,Static'
$constructor = $managerType.GetConstructor([Reflection.BindingFlags]'NonPublic,Instance', $null, [type[]]@([string],[Net.Http.HttpClient]), $null)
$root = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ('essential-kernel-updates-' + [guid]::NewGuid().ToString('N'))))
$null = [IO.Directory]::CreateDirectory($root)
$clients = [Collections.Generic.List[Net.Http.HttpClient]]::new()
$script:passed = 0
$script:failed = 0
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
public sealed class KernelReleaseFixture : HttpMessageHandler
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    public static IDisposable HoldDirectory(string path)
    {
        var handle = CreateFile(path, 0x80000000, 3, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }
    public string Version = "0.85.1", Kernel = "pi", Digest = "";
    public byte[] Archive = Array.Empty<byte>();
    public bool IncludeAsset = true, FailRelease;
    public int ReleaseRequests, ArchiveRequests;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        await Task.Delay(20, token);
        if (request.RequestUri.AbsolutePath.EndsWith("/latest"))
        {
            Interlocked.Increment(ref ReleaseRequests);
            if (FailRelease) throw new HttpRequestException("Synthetic release check failure.");
            string name = Kernel == "pi" ? "pi-windows-x64.zip" : "codex-x86_64-pc-windows-msvc.exe.zip";
            var asset = new { name, browser_download_url = "https://example.invalid/" + name, digest = "sha256:" + Digest };
            string json = JsonSerializer.Serialize(new {
                tag_name = (Kernel == "codex" ? "rust-v" : "v") + Version,
                assets = IncludeAsset ? new[] { asset } : Array.Empty<object>()
            });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
        Interlocked.Increment(ref ArchiveRequests);
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Archive) };
    }
}
'@
function Assert-True([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
function Test-Case([string]$name, [scriptblock]$action) {
    try { $null = & $action; $script:passed++; "PASS $name" }
    catch { $script:failed++; "FAIL $name`: $($_.Exception.GetBaseException().Message)"; $_.ScriptStackTrace }
}
function New-Manager([string]$kernel = 'pi') {
    $handler = [KernelReleaseFixture]::new(); $handler.Kernel = $kernel
    $client = [Net.Http.HttpClient]::new($handler); $clients.Add($client)
    $directory = Join-Path $root ([guid]::NewGuid().ToString('N'))
    $manager = $constructor.Invoke([object[]]@([string]$directory, $client))
    return [pscustomobject]@{Manager=$manager;Handler=$handler;Client=$client;Root=$directory;Kernel=$kernel}
}
function New-VersionExecutable([string]$version) {
    $exe = Join-Path $root "cli-$version.exe"
    if (-not (Test-Path -LiteralPath $exe)) {
        $source = Join-Path $root "cli-$version.cs"
        @"
using System;
class VersionProbe {
    static void Main() {
        Console.Error.Write(new string('x', 131072));
        Console.WriteLine("synthetic-cli $version");
    }
}
"@ | Set-Content -LiteralPath $source -Encoding utf8
        $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        $compilerOutput = & $compiler /nologo /target:exe "/out:$exe" $source 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Synthetic CLI compilation failed: $compilerOutput" }
        $stream = [IO.File]::OpenWrite($exe)
        try { $stream.SetLength(32768) } finally { $stream.Dispose() }
    }
    return $exe
}
function Write-Installation([string]$directory, [string]$kernel, [string]$version) {
    $null = [IO.Directory]::CreateDirectory($directory)
    Copy-Item -LiteralPath (New-VersionExecutable $version) -Destination (Join-Path $directory "$kernel.exe")
    if ($kernel -eq 'pi') {
        $null = [IO.Directory]::CreateDirectory((Join-Path $directory 'theme'))
        [IO.File]::WriteAllText((Join-Path $directory 'package.json'), ('{"version":"' + $version + '"}'))
        foreach ($theme in 'dark','light') { [IO.File]::WriteAllText((Join-Path $directory "theme/$theme.json"), '{}') }
    }
}
function Set-Local($context, [string]$version) {
    Write-Installation (Join-Path $context.Root $context.Kernel) $context.Kernel $version
}
function Set-Release($context, [string]$version, [string]$executableVersion = '') {
    if (-not $executableVersion) { $executableVersion = $version }
    $directory = Join-Path $root ('archive-' + [guid]::NewGuid().ToString('N'))
    Write-Installation $directory $context.Kernel $executableVersion
    $zip = $directory + '.zip'
    [IO.Compression.ZipFile]::CreateFromDirectory($directory, $zip)
    $context.Handler.Version = $version
    $context.Handler.Archive = [IO.File]::ReadAllBytes($zip)
    $context.Handler.Digest = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Update-Kernel($context) {
    return $context.Manager.DownloadOrUpdateAsync($context.Kernel, $null, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
}
try {
    Test-Case 'Semantic comparison handles tags, prereleases, multi-digit components and build metadata' {
        $compare = $managerType.GetMethod('CompareVersions', $flags)
        foreach ($case in @(
            @('codex-cli 0.153.4','rust-v0.153.4',0), @('v0.85.1','0.85.1',0),
            @('0.9.0','0.10.0',-1), @('0.86.0','0.85.1',1), @('1.0.0-alpha.9','1.0.0-alpha.10',-1),
            @('1.0.0-alpha','1.0.0',-1), @('1.0.0','1.0.0-rc.1',1), @('1.0.0+a','1.0.0+b',0)
        )) { Assert-True ([Math]::Sign($compare.Invoke($null, @($case[0], $case[1]))) -eq $case[2]) 'Version precedence was incorrect.' }
    }
    foreach ($kernel in 'codex','pi') {
        Test-Case "$kernel same version performs no archive request or installation write" {
            $context = New-Manager $kernel; Set-Local $context '0.85.1'; $context.Handler.IncludeAsset = $false
            $path = $context.Manager.GetStatus($kernel).Path
            $before = (Get-Item -LiteralPath $path).LastWriteTimeUtc
            $result = Update-Kernel $context
            Assert-True (-not $result.Changed -and $result.Status.Version -eq '0.85.1') 'An equal version was reinstalled.'
            Assert-True ($context.Handler.ReleaseRequests -eq 1 -and $context.Handler.ArchiveRequests -eq 0) 'An equal version downloaded an archive.'
            Assert-True ((Get-Item -LiteralPath $path).LastWriteTimeUtc -eq $before -and -not (Test-Path -LiteralPath (Join-Path (Split-Path $path) 'kernel-version.json'))) 'A no-op update modified the installation.'
        }
        Test-Case "$kernel newer local version is never downgraded" {
            $context = New-Manager $kernel; Set-Local $context '0.86.0'; $context.Handler.IncludeAsset = $false
            $result = Update-Kernel $context
            Assert-True (-not $result.Changed -and $result.Status.Version -eq '0.86.0' -and $context.Handler.ArchiveRequests -eq 0) 'A newer installation was downgraded.'
        }
        Test-Case "$kernel concurrent updates download once and persist the verified CLI version" {
            $context = New-Manager $kernel; Set-Local $context '0.85.1'; Set-Release $context '0.86.0'
            $first = $context.Manager.DownloadOrUpdateAsync($kernel, $null, [Threading.CancellationToken]::None)
            $second = $context.Manager.DownloadOrUpdateAsync($kernel, $null, [Threading.CancellationToken]::None)
            $one = $first.GetAwaiter().GetResult(); $two = $second.GetAwaiter().GetResult()
            Assert-True ($one.Changed -and -not $two.Changed -and $context.Handler.ArchiveRequests -eq 1) 'Concurrent clicks downloaded or installed twice.'
            $restarted = $constructor.Invoke([object[]]@([string]$context.Root, $context.Client))
            $status = $restarted.GetStatus($kernel)
            Assert-True ($status.Version -eq '0.86.0' -and (Test-Path -LiteralPath (Join-Path (Split-Path $status.Path) 'kernel-version.json'))) 'Verified version was not available after restart.'
            Assert-True (@(Get-ChildItem -LiteralPath $context.Root -Force | Where-Object Name -like '.*').Count -eq 0) 'Successful update left staging files.'
        }
        Test-Case "$kernel release failure preserves the installed version without bundled downgrade" {
            $context = New-Manager $kernel; Set-Local $context '0.86.0'; $context.Handler.FailRelease = $true
            $failed = $false; try { $null = Update-Kernel $context } catch { $failed = $true }
            Assert-True ($failed -and $context.Manager.GetStatus($kernel).Version -eq '0.86.0' -and $context.Handler.ArchiveRequests -eq 0) 'Release failure replaced the installed kernel.'
        }
        Test-Case "$kernel invalid hash or mismatched executable version preserves the existing installation" {
            foreach ($failure in 'hash','version') {
                $context = New-Manager $kernel; Set-Local $context '0.85.1'
                if ($failure -eq 'hash') { Set-Release $context '0.86.0'; $context.Handler.Digest = '0' * 64 }
                else { Set-Release $context '0.86.0' '0.85.1' }
                $failed = $false; try { $null = Update-Kernel $context } catch { $failed = $true }
                Assert-True ($failed -and $context.Manager.GetStatus($kernel).Version -eq '0.85.1') 'Invalid release replaced a working installation.'
                Assert-True (@(Get-ChildItem -LiteralPath $context.Root -Force | Where-Object Name -like '.*').Count -eq 0) 'Failed verification left staging files.'
            }
        }
    }
    Test-Case 'Pi with missing runtime resources is repaired even when its executable version is current' {
        $context = New-Manager; Set-Local $context '0.85.1'; Set-Release $context '0.85.1'
        [IO.File]::Delete((Join-Path $context.Root 'pi/theme/light.json'))
        Assert-True (-not $context.Manager.GetStatus('pi').Installed) 'Incomplete Pi was considered ready.'
        $result = Update-Kernel $context
        Assert-True ($result.Changed -and $result.Status.Installed -and $result.Status.Version -eq '0.85.1' -and $context.Handler.ArchiveRequests -eq 1) 'Incomplete runtime was not repaired.'
    }
    Test-Case 'Missing installation resolves to the managed directory and installs the latest verified release' {
        $context = New-Manager
        Assert-True ($context.Manager.GetStatus('pi').Path -eq (Join-Path $context.Root 'pi/pi.exe')) 'Missing status pointed outside the managed directory.'
        Set-Release $context '0.86.0'
        $result = Update-Kernel $context
        Assert-True ($result.Changed -and $result.Status.Version -eq '0.86.0') 'A first installation did not complete.'
    }
    Test-Case 'Real Pi installs after its version probe and a repeat click does not download again' {
        $context = New-Manager; Set-Local $context '0.84.0'
        $zip = Join-Path (Split-Path -Parent $PSScriptRoot) 'pi-windows-x64.zip'
        $context.Handler.Archive = [IO.File]::ReadAllBytes($zip)
        $context.Handler.Digest = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedHash = $managerType.GetMethod('BundledArchiveSha256', $flags).Invoke($null, @('pi'))
        Assert-True ($context.Handler.Digest -eq $expectedHash) 'Bundled Pi digest changed.'
        $result = Update-Kernel $context
        Assert-True ($result.Changed -and $result.Status.Version -eq '0.85.1') 'Real Pi could not replace a previous installation.'
        $again = Update-Kernel $context
        Assert-True (-not $again.Changed -and $context.Handler.ArchiveRequests -eq 1) 'Repeated click reinstalled the same Pi release.'
    }
    Test-Case 'A persistently busy installation stops retrying and preserves the existing executable' {
        $context = New-Manager; Set-Local $context '0.85.1'; Set-Release $context '0.86.0'
        $directory = Join-Path $context.Root 'pi'
        $path = Join-Path $directory 'pi.exe'
        $before = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $handle = [KernelReleaseFixture]::HoldDirectory($directory)
        $timeout = [Threading.CancellationTokenSource]::new([timespan]::FromSeconds(10))
        try {
            $failure = $null
            try { $null = $context.Manager.DownloadOrUpdateAsync('pi', $null, $timeout.Token).GetAwaiter().GetResult() }
            catch { $failure = $_.Exception.GetBaseException() }
            $failureType = if ($failure) { $failure.GetType().Name } else { 'none' }
            Assert-True (($failure -is [IO.IOException] -or $failure -is [UnauthorizedAccessException]) -and -not $timeout.IsCancellationRequested) "A permanent lock was ignored or retried without a bound: failure=$failureType, canceled=$($timeout.IsCancellationRequested)."
            Assert-True ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $before) 'A busy installation was replaced or removed.'
        }
        finally { $timeout.Dispose(); $handle.Dispose() }
    }
}
finally {
    foreach ($client in $clients) { $client.Dispose() }
    $boundary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $root.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $root) -notmatch '^essential-kernel-updates-[a-f0-9]{32}$') { throw 'Refusing cleanup outside the generated test directory.' }
    [IO.Directory]::Delete($root, $true)
}
"Kernel update tests: $script:passed passed, $script:failed failed."
if ($script:failed) { exit 1 }
