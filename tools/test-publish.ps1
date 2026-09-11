# Read-only verification of a Windows x64 self-contained folder and optional ZIP.
# Does not launch the app, access user configuration/logs, or modify the package.
param(
    [Parameter(Mandatory)][string]$PublishDirectory,
    [string]$ZipPath
)
$ErrorActionPreference = 'Stop'
$packageRoot = (Resolve-Path -LiteralPath $PublishDirectory).Path
$sourceRoot = Split-Path -Parent $PSScriptRoot
[xml]$project = Get-Content -LiteralPath (Join-Path $sourceRoot 'LocalSecurityAudit.csproj') -Raw
$expectedVersion = [string]$project.Project.PropertyGroup.InformationalVersion
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

$files = @(Get-ChildItem -LiteralPath $packageRoot -File -Recurse)
$unexpected = @($files | Where-Object {
    $_.Name -in 'settings.json', 'API.txt', 'appsettings.local.json', 'secrets.json', 'AGENTS.md', 'collect-assistant-events.ps1', 'publish-assistant-audit.py', 'codex-x86_64-pc-windows-msvc.exe.zip', 'pi-windows-x64.zip' -or
    $_.Name -match '\.db(?:-wal|-shm)?$|\.log$|(?:evidence|result|analysis|diagnostic)[^\\]*\.(?:json|txt)$' -or
    ($_.Extension -eq '.json' -and $_.Name -notin 'Essential.deps.json', 'Essential.runtimeconfig.json')
})
Assert-True ($unexpected.Count -eq 0) 'The package contains user configuration, logs or audit data.'
'PASS Package contains no user configuration, logs or audit data.'

foreach ($relative in 'Essential.exe', 'Essential.dll', 'resources.pri', 'Assets/app.ico',
    'Assets/logo-light-32.png', 'Assets/logo-light-48.png', 'Assets/logo-light-256.png',
    'Assets/logo-dark-32.png', 'Assets/logo-dark-48.png', 'Assets/logo-dark-256.png',
    'Microsoft.ui.xaml.dll', 'Microsoft.Graphics.Canvas.dll', 'Microsoft.Graphics.Canvas.Interop.dll',
    'libSkiaSharp.dll', 'libHarfBuzzSharp.dll', 'e_sqlite3.dll', 'coreclr.dll', 'hostfxr.dll', 'hostpolicy.dll',
    'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll') {
    Assert-True (Test-Path -LiteralPath (Join-Path $packageRoot $relative) -PathType Leaf) ('Missing required runtime/resource: ' + $relative)
}
$runtime = Get-Content -LiteralPath (Join-Path $packageRoot 'Essential.runtimeconfig.json') -Raw | ConvertFrom-Json
Assert-True ($null -eq $runtime.runtimeOptions.framework -and $null -eq $runtime.runtimeOptions.frameworks -and
    @($runtime.runtimeOptions.includedFrameworks | Where-Object name -eq 'Microsoft.NETCore.App').Count -eq 1) 'The package is not .NET self-contained.'
'PASS Self-contained runtime, WinUI/Win2D, chart/SQLite natives and app assets are present.'

foreach ($name in 'Essential.exe', 'coreclr.dll', 'Microsoft.ui.xaml.dll', 'Microsoft.Graphics.Canvas.dll',
    'libSkiaSharp.dll', 'e_sqlite3.dll', 'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll') {
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead((Join-Path $packageRoot $name)))
    try {
        Assert-True ($reader.ReadUInt16() -eq 0x5A4D) ('Not a PE image: ' + $name)
        $reader.BaseStream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        $reader.BaseStream.Position = $peOffset
        Assert-True ($reader.ReadUInt32() -eq 0x4550 -and $reader.ReadUInt16() -eq 0x8664) ('Not an x64 image: ' + $name)
    }
    finally { $reader.Dispose() }
}
$exe = Join-Path $packageRoot 'Essential.exe'
Assert-True ([Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion -eq $expectedVersion) 'The package has a stale version.'
Assert-True ([Reflection.Assembly]::LoadFrom((Join-Path $packageRoot 'Essential.dll')).EntryPoint.DeclaringType.FullName -eq 'LocalSecurityAudit.Program') 'The package contains a test entry point.'
Assert-True ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($exe)).Contains('level="asInvoker"')) 'The package would require administrator rights at startup.'
'PASS Version, x64 architecture and ordinary-permission startup manifest match.'

foreach ($relative in 'Assets/app.ico', 'Assets/logo-light-32.png', 'Assets/logo-light-48.png', 'Assets/logo-light-256.png',
    'Assets/logo-dark-32.png', 'Assets/logo-dark-48.png', 'Assets/logo-dark-256.png') {
    $sourceHash = (Get-FileHash -LiteralPath (Join-Path $sourceRoot $relative)).Hash
    $packageHash = (Get-FileHash -LiteralPath (Join-Path $packageRoot $relative)).Hash
    Assert-True ($sourceHash -eq $packageHash) ('Stale packaged protocol/tool/asset: ' + $relative)
}
'PASS Packaged app assets match the source.'

if ($ZipPath) {
    $zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $ZipPath).Path)
    try {
        $entries = @($zip.Entries | Where-Object { -not $_.FullName.EndsWith('/') })
        $prefix = (Split-Path -Leaf $packageRoot) + '/'
        Assert-True ($entries.Count -eq $files.Count) 'ZIP file count differs from the verified folder.'
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entries) {
            Assert-True ($entry.FullName.StartsWith($prefix, [StringComparison]::Ordinal) -and $seen.Add($entry.FullName)) 'ZIP has an unexpected or duplicate path.'
            $path = [IO.Path]::GetFullPath((Join-Path $packageRoot $entry.FullName.Substring($prefix.Length)))
            Assert-True ($path.StartsWith($packageRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) 'ZIP path escapes the package root.'
            $stream = $entry.Open()
            try { $entryHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)) }
            finally { $stream.Dispose() }
            Assert-True ($entryHash -eq (Get-FileHash -LiteralPath $path).Hash) ('ZIP content mismatch: ' + $entry.FullName)
        }
    }
    finally { $zip.Dispose() }
    'PASS Every ZIP entry matches the verified publish folder by SHA-256.'
}
"Package verified: $expectedVersion x64; $($files.Count) files. No app launch or user-data access."
