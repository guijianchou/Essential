# Synthetic usage and temporary SQLite only; no event logs, credentials or remote AI.
param([string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll")
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$directory = Split-Path -Parent $assembly.Location
foreach ($dependency in 'Microsoft.Data.Sqlite.dll', 'SQLitePCLRaw.batteries_v2.dll') {
    $null = [Reflection.Assembly]::LoadFrom((Join-Path $directory $dependency))
}
$sqlitePath = Join-Path $directory 'e_sqlite3.dll'
if (-not (Test-Path -LiteralPath $sqlitePath)) { $sqlitePath = Join-Path $directory 'runtimes/win-x64/native/e_sqlite3.dll' }
$null = [Runtime.InteropServices.NativeLibrary]::Load($sqlitePath)
$root = Join-Path ([IO.Path]::GetTempPath()) ('lsa-token-regression-' + [guid]::NewGuid().ToString('N'))
$storage = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended', $root).GetAwaiter().GetResult()
function Assert-True([bool]$value, [string]$message) { if (-not $value) { throw $message }; "PASS $message" }
function Local-Time([string]$text) { return [datetime]::SpecifyKind([datetime]::Parse($text, [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Local) }
$now = Local-Time '2026-09-09T12:00:00'
$index = 0
foreach ($time in @('2026-08-31T23:59:59.9999999', '2026-09-06T23:59:59.9999999',
    '2026-09-08T23:59:59.9999999', '2026-09-09T00:00:00', '2026-09-09T12:00:00',
    '2026-09-10T00:00:00', '2026-09-14T00:00:00', '2026-10-01T00:00:00')) {
    $tokens = [long][math]::Pow(2, $index)
    $storage.RecordTokenUsage("request-$index", $tokens, $tokens, (Local-Time $time).ToUniversalTime())
    $index++
}
$day = $storage.GetTokenUsageTotals('day', $now)
$week = $storage.GetTokenUsageTotals('week', $now)
$month = $storage.GetTokenUsageTotals('month', $now)
Assert-True ($day.Item1 -eq 255 -and $day.Item2 -eq 255) 'All-time total includes every recorded request.'
Assert-True ($day.Item3 -eq 24 -and $day.Item4 -eq 24) 'Local day includes midnight and excludes the next midnight.'
Assert-True ($week.Item3 -eq 60 -and $week.Item4 -eq 60) 'Natural week starts Monday and excludes the next Monday.'
Assert-True ($month.Item3 -eq 126 -and $month.Item4 -eq 126) 'Natural month uses calendar boundaries rather than a rolling 30 days.'
$sunday = $storage.GetTokenUsageTotals('week', (Local-Time '2026-09-13T12:00:00'))
$monday = $storage.GetTokenUsageTotals('week', (Local-Time '2026-09-14T00:00:00'))
$october = $storage.GetTokenUsageTotals('month', (Local-Time '2026-10-01T00:00:00'))
Assert-True ($sunday.Item3 -eq 60 -and $monday.Item3 -eq 64 -and $october.Item3 -eq 128) 'Sunday, Monday and month rollover select the correct period.'
$storage.RecordTokenUsage('request-3', 20, 10, $now.AddDays(2).ToUniversalTime())
$storage.RecordTokenUsage('request-3', 20, 10, $now.AddDays(3).ToUniversalTime())
$storage.RecordTokenUsage('request-3', 8, 9, $now.ToUniversalTime())
$day = $storage.GetTokenUsageTotals('day', $now)
Assert-True ($day.Item1 -eq 267 -and $day.Item2 -eq 257 -and $day.Item3 -eq 36 -and $day.Item4 -eq 26) 'Repeated and stale snapshots neither double-count nor move usage into another day.'
$storage.RecordTokenUsage('', 99, 99, $now.ToUniversalTime())
$storage.RecordTokenUsage('invalid', -1, 99, $now.ToUniversalTime())
$reopened = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended', $root).GetAwaiter().GetResult()
$restored = $reopened.GetTokenUsageTotals('day', $now)
Assert-True ($restored.Equals($day)) 'Recorded usage survives reopening, and invalid identities or negative counts are ignored.'
Add-Type -TypeDefinition @'
using System;
using System.Linq;
using System.Threading.Tasks;
public static class ConcurrentUsageTest {
    public static void Run(object storage, DateTime timestamp) {
        var record = storage.GetType().GetMethod("RecordTokenUsage");
        Task.WaitAll(Enumerable.Range(1, 24).Select(index => Task.Run(() =>
            record.Invoke(storage, new object[] { "concurrent", (long)index, (long)index, timestamp }))).ToArray());
    }
}
'@
[ConcurrentUsageTest]::Run($storage, $now.ToUniversalTime())
$concurrent = $storage.GetTokenUsageTotals('day', $now)
Assert-True ($concurrent.Item1 -eq 291 -and $concurrent.Item2 -eq 281) 'Concurrent duplicate updates persist each request only once and keep its largest snapshot.'
$storage.CleanupOldDataAsync(1).GetAwaiter().GetResult()
$storage.VacuumDatabaseAsync().GetAwaiter().GetResult()
$fullMode = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('full', $root).GetAwaiter().GetResult()
Assert-True ($fullMode.GetTokenUsageTotals('day', $now).Equals($concurrent)) 'History cleanup, database compaction and mode changes retain the shared token totals.'
$settings = [LocalSecurityAudit.Services.SettingsService]::new($null, (Join-Path $root 'profile'))
foreach ($period in 'day', 'week', 'month') {
    $settings.Current.TokenUsagePeriod = $period
    $settings.Save($settings.Current)
    $loaded = [LocalSecurityAudit.Services.SettingsService]::new($null, (Join-Path $root 'profile'))
    Assert-True ($loaded.Current.TokenUsagePeriod -eq $period) "The $period display preference survives restart."
}
$settings.Current.TokenUsagePeriod = 'rolling'
$settings.Save($settings.Current)
Assert-True ($settings.Current.TokenUsagePeriod -eq 'day') 'Unsupported period values normalize to the natural day default.'
[Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools()
"Token regression artifacts: $root"
