# Synthetic kernel processes and a temporary SQLite database. No real settings, logs or network.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll",
    [switch]$SimulateConcurrentEdit
)
$ErrorActionPreference = 'Stop'
$assembly = [System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$directory = Split-Path -Parent $assembly.Location
foreach ($dependency in 'Microsoft.Data.Sqlite.dll', 'SQLitePCLRaw.batteries_v2.dll') {
    $null = [System.Reflection.Assembly]::LoadFrom((Join-Path $directory $dependency))
}
$sqlitePath = Join-Path $directory 'e_sqlite3.dll'
if (-not (Test-Path -LiteralPath $sqlitePath)) { $sqlitePath = Join-Path $directory 'runtimes/win-x64/native/e_sqlite3.dll' }
$null = [System.Runtime.InteropServices.NativeLibrary]::Load($sqlitePath)
[SQLitePCL.Batteries_V2]::Init()
$flags = [System.Reflection.BindingFlags]'NonPublic,Instance,Static'

. "$PSScriptRoot\kernel-test-support.ps1"
$fixture = New-KernelFixture $assembly
$settingsService = $fixture.SettingsService
$settings = $fixture.Settings
$logger = $fixture.Logger
$storageType = $assembly.GetType('LocalSecurityAudit.Services.DataStorageService', $true)
$storage = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($storageType)
$database = Join-Path ([IO.Path]::GetTempPath()) "lsa-workflow-$([guid]::NewGuid()).db"
$connectionString = "Data Source=$database;Pooling=False"
$storageType.GetField('_connectionString', $flags).SetValue($storage, $connectionString)
$storageType.GetField('_historyPaths', $flags).SetValue($storage, [string[]]@($database, "$database.assistant"))
$keeper = [Microsoft.Data.Sqlite.SqliteConnection]::new($connectionString)
$scheduler = $null
try {
    $keeper.Open()
    $null = $storageType.GetMethod('InitializeDatabaseAsync', $flags).Invoke($storage, @()).GetAwaiter().GetResult()
    $result = [LocalSecurityAudit.Models.AuditResult]::new()
    $result.Timestamp = [datetime]::UtcNow
    $result.HealthScore = 72
    foreach ($index in 0..8) {
        $issue = [LocalSecurityAudit.Models.AuditIssue]::new()
        $issue.Key = "source-$index"
        $issue.Title = "Historical finding $index"
        $issue.Description = "Stored description $index"
        $issue.RootCause = 'Uncertain cause'
        $issue.Recommendation = 'Review the source'
        $issue.EventRecordId = [string](100 + $index)
        $issue.EventDescription = "Original source $index"
        $result.Findings.Add($issue)
    }
    $null = $storage.SaveAuditResultAsync($result).GetAwaiter().GetResult()
    $capture = Set-KernelPlan $fixture @{Translate=$true;BlockInput='Historical finding 8'}
    $route = [LocalSecurityAudit.Models.AiTargetSettings]::new()
    $route.BaseUrl = 'https://primary.invalid'
    $route.ApiKey = 'synthetic-secret'
    $settings.AiTargets.Add($route)
    $analysis = $fixture.Analysis
    $scheduler = [LocalSecurityAudit.Services.AuditSchedulerService]::new($null, $analysis, $storage, $settingsService, $logger)
    $schedulerType = $scheduler.GetType()
    $recorder = [KernelWorkflowRecorder]::new()
    $progressEvent = $schedulerType.GetEvent('AuditProgress')
    $handler = [Delegate]::CreateDelegate($progressEvent.EventHandlerType, $recorder, $recorder.GetType().GetMethod('Record'))
    $progressEvent.AddEventHandler($scheduler, $handler)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $schedulerType.GetMethod('StartHistoryTranslation', $flags).Invoke($scheduler, @())
    if ($timer.Elapsed.TotalSeconds -gt 1) { throw 'Starting history translation blocked the caller.' }
    $waiting = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath (Join-Path $capture 'blocked')) -and $waiting.Elapsed.TotalSeconds -lt 10) { Start-Sleep -Milliseconds 20 }
    if (-not (Test-Path -LiteralPath (Join-Path $capture 'blocked'))) { throw 'The synthetic second batch never started.' }
    $history = [System.Threading.Tasks.Task]$schedulerType.GetField('_historyTask', $flags).GetValue($scheduler)
    if ($history.IsCompleted) { throw 'The mock second batch should still be waiting.' }
    if ($SimulateConcurrentEdit) {
        $edit = $keeper.CreateCommand()
        $edit.CommandText = 'UPDATE AuditResults SET FindingsJson=json_set(FindingsJson, ''$[0].ConcurrentEdit'', ''retained'')'
        $null = $edit.ExecuteNonQuery()
        $edit.Dispose()
    }
    $null = $schedulerType.GetMethod('PauseHistoryTranslationAsync', $flags).Invoke($scheduler, @()).WaitAsync([timespan]::FromSeconds(5)).GetAwaiter().GetResult()
    $saved = $storage.GetLatestResultAsync().GetAwaiter().GetResult()
    $complete = @($saved.Findings | Where-Object HasBilingualText)
    $expected = if ($SimulateConcurrentEdit) { 0 } else { 8 }
    if ($complete.Count -ne $expected) { throw "Expected $expected saved translations; found $($complete.Count)." }
    if ($saved.Findings[8].HasBilingualText -or $saved.HealthScore -ne 72) { throw 'The interrupted finding or health score changed.' }
    foreach ($index in 0..8) {
        if ($saved.Findings[$index].EventDescription -ne "Original source $index") { throw 'Translation changed original evidence.' }
    }
    $pending = $storage.GetLegacyFindingsAsync().GetAwaiter().GetResult()
    if ($pending.Count -ne 1) { throw 'The partially translated record was not eligible for the next scan.' }
    $translationStatus = @($recorder.Events.ToArray() | Where-Object Stage -eq Translate)[-1]
    $completionStatus = @($recorder.Events.ToArray() | Where-Object Stage -eq Complete)[-1]
    $expectedState = if ($SimulateConcurrentEdit) { 'Failed' } else { 'Skipped' }
    $usage = $storage.GetTokenUsageTotals('day', [datetime]::Now)
    if ($usage.Item1 -ne 120 -or $usage.Item2 -ne 30) { throw 'Completed historical translation usage was not persisted exactly once.' }
    if ($translationStatus.State.ToString() -ne $expectedState -or $completionStatus.State.ToString() -ne 'Done') {
        throw 'Sidebar status did not distinguish saved scan completion from incomplete history translation.'
    }
    if ($SimulateConcurrentEdit) {
        Write-Output 'PASS Concurrent history edits are preserved and the sidebar reports unsaved translation instead of false success.'
    }
    else {
        Write-Output 'PASS Background translation returns immediately; cancellation saves 8 completed findings, retains source evidence, and reports translation pending.'
    }
}
finally {
    if ($scheduler) { $null = $scheduler.StopAsync([System.Threading.CancellationToken]::None).GetAwaiter().GetResult(); $scheduler.Dispose() }
    Remove-KernelFixture $fixture
    $keeper.Dispose()
    [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools()
    [IO.File]::Delete($database)
}
