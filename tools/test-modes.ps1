# Synthetic-only mode/permission guards, mocked collection, Python -> .NET roundtrip and WAL refresh.
# Does not activate WinUI, elevate, read real settings/logs, or contact any AI endpoint.
param([string]$AssemblyPath = "$PSScriptRoot\..\bin\x64\Debug\net8.0-windows10.0.19041.0\LocalSecurityAudit.dll")
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$directory = Split-Path -Parent $assembly.Location
foreach ($dependency in 'Microsoft.Data.Sqlite.dll', 'SQLitePCLRaw.batteries_v2.dll') {
    $null = [Reflection.Assembly]::LoadFrom((Join-Path $directory $dependency))
}
$sqlitePath = Join-Path $directory 'e_sqlite3.dll'
if (-not (Test-Path -LiteralPath $sqlitePath)) { $sqlitePath = Join-Path $directory 'runtimes/win-x64/native/e_sqlite3.dll' }
$null = [Runtime.InteropServices.NativeLibrary]::Load($sqlitePath)
[SQLitePCL.Batteries_V2]::Init()
$flags = [Reflection.BindingFlags]'NonPublic,Instance,Static'
$settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
$storageType = $assembly.GetType('LocalSecurityAudit.Services.DataStorageService', $true)
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('lsa-mode-test-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $testRoot
$script:passed = 0
$script:failed = 0
$global:LsaModeTestScenario = 'normal'
$global:LsaModeTestReads = [Collections.Generic.List[string]]::new()
$collector = Join-Path $PSScriptRoot 'collect-assistant-events.ps1'
$publisher = Join-Path $PSScriptRoot 'publish-assistant-audit.py'

Add-Type -TypeDefinition @'
using System;
using System.Threading;
using System.Threading.Tasks;
public sealed class DatabaseChangeRecorder
{
    private int count;
    public int Count => Volatile.Read(ref count);
    public TaskCompletionSource<bool> Changed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public void Record() { if (Interlocked.Increment(ref count) > 1) Changed.TrySetResult(true); }
}
'@

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Test-Case([string]$Name, [scriptblock]$Action) {
    try { $null = & $Action; $script:passed++; "PASS $Name" }
    catch { $script:failed++; "FAIL $Name`: $($_.Exception.GetBaseException().Message)"; $_.ScriptStackTrace }
}
function Assert-Blocked([scriptblock]$Action) {
    $blocked = $false
    try { $null = & $Action }
    catch { $blocked = $_.Exception.GetBaseException() -is [InvalidOperationException] }
    Assert-True $blocked 'An assistant-only guard did not reject the action.'
}
function New-TestSettings([string]$Mode = 'assistant') {
    $service = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
    $settings = [LocalSecurityAudit.Models.AppSettings]::new()
    $settings.Mode = $Mode
    $settingsType.GetProperty('Current').SetValue($service, $settings)
    $settingsType.GetField('<ActiveMode>k__BackingField', $flags).SetValue($service, $Mode)
    return $service
}

# This function shadows the Windows cmdlet only within this test process. The collector
# runs in-process with &, so it cannot accidentally fall through to real event collection.
function Get-WinEvent {
    [CmdletBinding()]
    param([xml]$FilterXml, [int]$MaxEvents)
    $log = [string]$FilterXml.QueryList.Query.Path
    $global:LsaModeTestReads.Add($log)
    if ($log -notin 'Security', 'System', 'Application', 'Setup', 'ForwardedEvents') { throw 'Unexpected mock channel.' }
    if ($global:LsaModeTestScenario -eq 'denied' -and $log -eq 'Security') {
        $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('Synthetic denial'), 'SyntheticDenied', 'PermissionDenied', $null))
    }
    if ($log -ne 'Security') {
        $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Synthetic empty channel'), 'NoMatchingEventsFound', 'ObjectNotFound', $null))
    }
    foreach ($index in 2, 1) {
        $record = [pscustomobject]@{
            RecordId = $index; Id = 4625; ProviderName = 'SyntheticProvider'
            TimeCreated = [datetime]::Parse("2026-01-01T12:00:0${index}Z", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
            Message = "Synthetic event $index password=synthetic-password; Bearer AAAAAAAAAAAAAAAAAAAAAAAA"
            Xml = '<Event><EventData><Data Name="TargetUserName">synthetic-user</Data><Data Name="IpAddress">192.0.2.1</Data><Data Name="CommandLine">must-not-be-retained</Data></EventData></Event>'
        }
        $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.Xml }
        $record | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
        $record
    }
}

try {
    Test-Case 'Only full-access mode requires elevation; extended and full share the legacy database' {
        foreach ($mode in 'assistant', 'extended', 'full') {
            Assert-True ([LocalSecurityAudit.Models.AppMode]::Normalize($mode) -eq $mode) 'Known mode was lost.'
            Assert-True ([LocalSecurityAudit.Models.AppMode]::RequiresElevation($mode) -eq ($mode -eq 'full')) 'Wrong elevation gate.'
            $settings = New-TestSettings $mode
            Assert-True ($settings.IsAssistantMode -eq ($mode -eq 'assistant') -and $settings.IsFullMode -eq ($mode -eq 'full')) 'Wrong active permissions.'
            if ($mode -ne 'assistant') { $settings.EnsureExtendedMode() }
        }
        Assert-True ([LocalSecurityAudit.Services.DataStorageService]::GetDatabasePath('full', $testRoot) -eq [LocalSecurityAudit.Services.DataStorageService]::GetDatabasePath('extended', $testRoot)) 'Full mode lost existing history.'
    }

    Test-Case 'Native collection plans skip Security normally and include all five channels only in full mode' {
        $type = $assembly.GetType('LocalSecurityAudit.Services.EventLogService', $true)
        $now = [datetime]::UtcNow
        foreach ($full in $false, $true) {
            $queries = $type.GetMethod('BuildCollectionQueries', $flags).Invoke($null, @($full, $now.AddDays(-1), $now))
            Assert-True ($queries.Count -eq 5 -and @($queries | Where-Object Item1 -eq 'ForwardedEvents').Count -eq 1) 'A Windows log channel is missing.'
            $security = @($queries | Where-Object Item1 -eq 'Security')[0]
            Assert-True ([string]::IsNullOrEmpty($security.Item2) -eq (-not $full)) 'Extended collection would query Security.'
            if ($full) { Assert-True ($security.Item2.Contains('EventID=4625') -and $security.Item2.Contains('EventID=5157')) 'Security/firewall events are missing.' }
            $system = @($queries | Where-Object Item1 -eq 'System')[0]
            Assert-True ($system.Item2.Contains('@SystemTime < ') -and -not $system.Item2.Contains('@SystemTime <= ')) 'Window end is not exclusive.'
        }
        $collected = [LocalSecurityAudit.Models.EventCollectionResult]::new()
        $collected.Channels.Add([LocalSecurityAudit.Models.AuditChannelCoverage]::new('Security', 'skipped', 0, 'not_requested'))
        Assert-True ($collected.CoverageStatus -eq 'limited') 'Skipping a log claimed full coverage.'
        $collected.Channels.Add([LocalSecurityAudit.Models.AuditChannelCoverage]::new('System', 'unavailable', 0, 'access_denied'))
        Assert-True ($collected.CoverageStatus -eq 'partial') 'Read failure was hidden by skipped Security.'
    }

    Test-Case 'Default external collection never queries Security and records the intentional skip' {
        $global:LsaModeTestReads.Clear()
        $summary = & $collector -OutputPath (Join-Path $testRoot 'standard.json') -FromUtc '2026-01-01T00:00:00Z' -ToUtc '2026-01-02T00:00:00Z' | ConvertFrom-Json
        Assert-True ($summary.Channels.Count -eq 5 -and $summary.Channels[0].Status -eq 'skipped' -and $summary.Channels[0].Reason -eq 'not_requested') 'Default scope was not explicit.'
        Assert-True ('Security' -notin $global:LsaModeTestReads -and $global:LsaModeTestReads.Count -eq 4 -and 'ForwardedEvents' -in $global:LsaModeTestReads) 'Default collector touched Security or lost an ordinary channel.'
    }

    Test-Case 'Missing and invalid saved modes default safely without losing AI configuration' {
        $settings = [Text.Json.JsonSerializer]::Deserialize('{"Theme":"dark","AiTargets":[{"BaseUrl":"https://unused.invalid","ApiKey":"synthetic-key"}]}', [LocalSecurityAudit.Models.AppSettings])
        Assert-True ($settings.Mode -eq 'assistant') 'Old settings did not default to assistant.'
        $settings.Mode = 'unknown-mode'
        $settingsType.GetMethod('Normalize', $flags).Invoke($null, @($settings))
        Assert-True ($settings.Mode -eq 'assistant' -and $settings.Theme -eq 'dark' -and $settings.AiTargets[0].ApiKey -eq 'synthetic-key') 'Normalization lost configuration.'
    }

    Test-Case 'Configuration, diagnostics and results stay outside the executable working directory' {
        $fixtureRoot = Join-Path $testRoot 'path-isolation'
        $programDirectory = Join-Path $fixtureRoot 'program'
        $dataDirectory = Join-Path $fixtureRoot 'user-data'
        $null = New-Item -ItemType Directory -Path $programDirectory, $dataDirectory
        [IO.File]::WriteAllText((Join-Path $programDirectory 'API.txt'), "https://wrong-working-directory.invalid`nsynthetic-working-key")
        [IO.File]::WriteAllText((Join-Path $fixtureRoot 'API.txt'), "https://wrong-parent-directory.invalid`nsynthetic-parent-key")
        $settings = New-TestSettings
        $settingsType.GetField('_settingsPath', $flags).SetValue($settings, (Join-Path $dataDirectory 'settings.json'))
        $settingsType.GetField('_agentInstructionsPath', $flags).SetValue($settings, (Join-Path $dataDirectory 'AGENTS.md'))
        $previousDirectory = [Environment]::CurrentDirectory
        try {
            [Environment]::CurrentDirectory = $programDirectory
            $defaults = $settings.CreateDefaultSettings()
            Assert-True ($defaults.AiTargets[0].ApiKey -eq '' -and $defaults.AiTargets[0].BaseUrl -eq 'https://api.falsemeet.site') 'Defaults were imported from the working or parent directory.'
            [IO.File]::WriteAllText((Join-Path $dataDirectory 'API.txt'), "https://synthetic-user-data.invalid`nsynthetic-user-key")
            $defaults = $settings.CreateDefaultSettings()
            Assert-True ($defaults.AiTargets[0].BaseUrl -eq 'https://synthetic-user-data.invalid' -and $defaults.AiTargets[0].ApiKey -eq 'synthetic-user-key') 'The optional API file was not read from the user-data directory.'
            $defaults.DiagnosticLoggingEnabled = $true
            $settings.Save($defaults)
            $logger = [LocalSecurityAudit.Services.DiagnosticLogService]::new($settings)
            $logger.Write('Synthetic path-isolation check')
            Assert-True ($logger.LogPath -eq (Join-Path $dataDirectory 'diagnostic.log') -and (Test-Path -LiteralPath $logger.LogPath)) 'Diagnostics were written outside the configuration data directory.'
            foreach ($mode in 'assistant', 'extended', 'full') {
                $storage = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync($mode, $dataDirectory).GetAwaiter().GetResult()
                $expected = if ($mode -eq 'assistant') { Join-Path $dataDirectory 'assistant\audit_data.db' } else { Join-Path $dataDirectory 'audit_data.db' }
                Assert-True ($storage.DatabasePath -eq $expected) 'A result database used the executable working directory.'
                $defaultRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LocalSecurityAudit'
                $defaultExpected = if ($mode -eq 'assistant') { Join-Path $defaultRoot 'assistant\audit_data.db' } else { Join-Path $defaultRoot 'audit_data.db' }
                Assert-True ([LocalSecurityAudit.Services.DataStorageService]::GetDatabasePath($mode) -eq $defaultExpected) 'The default result path depends on the working directory.'
            }
            Assert-True ((Test-Path -LiteralPath (Join-Path $dataDirectory 'settings.json')) -and (Test-Path -LiteralPath (Join-Path $dataDirectory 'AGENTS.md'))) 'Configuration did not stay in user data.'
            $programFiles = @(Get-ChildItem -LiteralPath $programDirectory -File -Recurse)
            Assert-True ($programFiles.Count -eq 1 -and $programFiles[0].Name -eq 'API.txt') 'Configuration, diagnostics or results leaked into the executable working directory.'
        }
        finally { [Environment]::CurrentDirectory = $previousDirectory }
    }

    Test-Case 'Saving a next-start mode never changes the active process mode' {
        $settings = New-TestSettings
        $settingsPath = Join-Path $testRoot 'settings.json'
        $settingsType.GetField('_settingsPath', $flags).SetValue($settings, $settingsPath)
        $settingsType.GetField('_agentInstructionsPath', $flags).SetValue($settings, (Join-Path $testRoot 'policy.md'))
        $settings.Current.Mode = 'extended'
        $settings.Save($settings.Current)
        Assert-True ($settings.IsAssistantMode -and $settings.ActiveMode -eq 'assistant') 'The running process changed mode.'
        Assert-True ((Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json).Mode -eq 'extended') 'Next-start mode was not persisted.'
        Assert-Blocked { $settings.EnsureExtendedMode() }
    }

    Test-Case 'The two databases have the same table schema and preserve legacy data' {
        $script:extended = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended', $testRoot).GetAwaiter().GetResult()
        $row = [LocalSecurityAudit.Models.AuditResult]::new()
        $row.Timestamp = [datetime]::UtcNow; $row.HealthScore = 85
        $extended.SaveAuditResultAsync($row).GetAwaiter().GetResult()
        [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools()
        $script:legacyHash = (Get-FileHash -LiteralPath $extended.DatabasePath).Hash
        $script:assistant = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('assistant', $testRoot).GetAwaiter().GetResult()
        Assert-True ($assistant.IsReadOnly -and -not $extended.IsReadOnly) 'Storage access modes are wrong.'
        Assert-True ($assistant.DatabasePath -ne $extended.DatabasePath -and $extended.DatabasePath -eq (Join-Path $testRoot 'audit_data.db')) 'Legacy database was moved or modes share a path.'
        Assert-True ($assistant.GetLatestResultAsync().GetAwaiter().GetResult().Timestamp -eq $row.Timestamp) 'Assistant mode did not share extended history.'
        $schemas = foreach ($storage in $extended, $assistant) {
            $connection = [Microsoft.Data.Sqlite.SqliteConnection]::new($storageType.GetField('_connectionString', $flags).GetValue($storage))
            try { $connection.Open(); $command = $connection.CreateCommand(); $command.CommandText = "SELECT sql FROM sqlite_master WHERE name='AuditResults'"; $command.ExecuteScalar() }
            finally { $connection.Dispose() }
        }
        Assert-True ($schemas[0] -eq $schemas[1]) 'Mode schemas diverged.'
    }

    Test-Case 'Assistant storage blocks save, cleanup, vacuum, translation and optimization writes' {
        Assert-Blocked { $assistant.SaveAuditResultAsync([LocalSecurityAudit.Models.AuditResult]::new()).GetAwaiter().GetResult() }
        Assert-Blocked { $assistant.CleanupOldDataAsync().GetAwaiter().GetResult() }
        Assert-Blocked { $assistant.VacuumDatabaseAsync().GetAwaiter().GetResult() }
        $issues = [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
        Assert-Blocked { $assistant.UpdateTranslatedFindingsAsync(1, '[]', $issues).GetAwaiter().GetResult() }
        $updates = [Collections.Generic.Dictionary[int,LocalSecurityAudit.Models.AuditIssue]]::new()
        Assert-Blocked { $assistant.UpdateOptimizedFindingsAsync(1, '[]', $updates, 'gpt-6-astra').GetAwaiter().GetResult() }
        Assert-True ($storageType.GetField('_connectionString', $flags).GetValue($assistant).Contains('Mode=ReadOnly')) 'The database connection is not read-only.'
    }

    Test-Case 'Assistant services reject scans and every AI entry point before external access' {
        $settings = New-TestSettings
        # Null loggers and an empty URL also prevent accidental external I/O if a guard regresses.
        $ai = [LocalSecurityAudit.Services.AiAnalysisService]::new($settings, $null)
        $events = [LocalSecurityAudit.Services.EventLogService]::new($null, $settings)
        $scheduler = [LocalSecurityAudit.Services.AuditSchedulerService]::new($null, $ai, $assistant, $settings, $null)
        try {
            Assert-Blocked { $events.ReadAllEventsAsync([datetime]::UtcNow, [datetime]::UtcNow).GetAwaiter().GetResult() }
            Assert-Blocked { $scheduler.ExecuteAuditAsync().GetAwaiter().GetResult() }
            Assert-Blocked { $scheduler.OptimizeHistoryAsync('gpt-6-astra').GetAwaiter().GetResult() }
            Assert-Blocked { $ai.AnalyzeEventsAsync([Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()).GetAwaiter().GetResult() }
            $target = [LocalSecurityAudit.Models.AiTarget]::new(); $target.BaseUrl = ''
            Assert-Blocked { $ai.TestConnectionAsync($target).GetAwaiter().GetResult() }
            $issues = [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
            Assert-Blocked { $ai.TranslateLegacyFindingsAsync($issues).GetAwaiter().GetResult() }
            Assert-Blocked { $ai.OptimizeFindingsAsync($issues, 'gpt-6-astra').GetAwaiter().GetResult() }
            $scheduler.StartAsync([Threading.CancellationToken]::None).GetAwaiter().GetResult()
            $type = $scheduler.GetType()
            Assert-True ($null -eq $type.GetField('_initialTask', $flags).GetValue($scheduler) -and $null -eq $type.GetField('_loopCts', $flags).GetValue($scheduler)) 'Assistant startup scheduled an audit.'
        }
        finally { $scheduler.StopAsync([Threading.CancellationToken]::None).GetAwaiter().GetResult(); $scheduler.Dispose() }
    }

    Test-Case 'Mocked collector emits complete bounded evidence, redacts secrets and excludes command lines' {
        $script:evidencePath = Join-Path $testRoot 'evidence.json'
        $summary = & $collector -IncludeSecurity -OutputPath $evidencePath -FromUtc '2026-01-01T00:00:00Z' -ToUtc '2026-01-02T00:00:00Z' | ConvertFrom-Json
        $script:evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
        Assert-True ($summary.EventCount -eq 2 -and $evidence.Events.Count -eq 2 -and @($evidence.Channels | Where-Object Status -ne 'complete').Count -eq 0) 'Mock collection coverage was not complete.'
        $raw = Get-Content -LiteralPath $evidencePath -Raw
        Assert-True (-not $raw.Contains('synthetic-password') -and -not $raw.Contains('AAAAAAAAAAAAAAAAAAAAAAAA') -and -not $raw.Contains('must-not-be-retained')) 'Collector retained sensitive synthetic fields.'
        Assert-True ($evidence.Events[0].EventRef -eq 'Security:2' -and $evidence.Events[0].UserName -eq 'synthetic-user') 'Collector lost evidence identity.'
        $before = (Get-FileHash -LiteralPath $evidencePath).Hash
        $refused = $false
        try { & $collector -OutputPath $evidencePath } catch { $refused = $true }
        Assert-True ($refused -and (Get-FileHash -LiteralPath $evidencePath).Hash -eq $before) 'Collector overwrote prior evidence.'
    }

    Test-Case 'Permission denial and truncation are recorded instead of reported as complete' {
        $global:LsaModeTestScenario = 'denied'
        $denied = & $collector -IncludeSecurity -OutputPath (Join-Path $testRoot 'denied.json') -FromUtc '2026-01-01T00:00:00Z' -ToUtc '2026-01-02T00:00:00Z' | ConvertFrom-Json
        Assert-True ($denied.Channels[0].Status -eq 'unavailable' -and $denied.Channels[0].Reason -eq 'access_denied' -and $denied.EventCount -eq 0) 'Denied logs masqueraded as complete.'
        $global:LsaModeTestScenario = 'normal'
        $limited = & $collector -IncludeSecurity -OutputPath (Join-Path $testRoot 'limited.json') -FromUtc '2026-01-01T00:00:00Z' -ToUtc '2026-01-02T00:00:00Z' -MaxEventsPerChannel 1 | ConvertFrom-Json
        Assert-True ($limited.Channels[0].Status -eq 'truncated' -and $limited.EventCount -eq 1) 'Collection cap was not reported.'
    }

    Test-Case 'Python publisher results roundtrip through the actual .NET storage and date queries' {
        $resultPath = Join-Path $testRoot 'analysis.json'
        $result = @{
            Timestamp = [datetime]::UtcNow.ToString('o')
            Findings = @(@{ Key = 'synthetic_failed_logon'; EventRef = 'Security:2'; RelatedEventRefs = @('Security:1','Security:2');
                Title = 'Synthetic finding'; Description = 'Synthetic summary'; RootCause = 'Cause not established'; Recommendation = 'Review records';
                TitleZh = '合成问题'; DescriptionZh = '合成摘要'; RootCauseZh = '原因尚未确定'; RecommendationZh = '核对记录';
                Severity = 'Medium'; Confidence = 'High'; Category = 'Login'; Affected = 'synthetic-user' })
            Metadata = @{ SchemaVersion = 2; Mode = 'assistant'; RunId = $evidence.RunId; Producer = 'claude'; AnalysisModel = 'synthetic-model';
                ScanType = 'Full Scan'; AnalyzedEventRefs = @('Security:1','Security:2'); FilterSummary = '' }
        }
        [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $published = & python $publisher publish $resultPath --evidence $evidencePath --data-root $testRoot | ConvertFrom-Json
        Assert-True ($LASTEXITCODE -eq 0 -and $published.Added) 'Synthetic publish failed.'
        $saved = $assistant.GetLatestResultAsync().GetAwaiter().GetResult()
        Assert-True ($saved.HealthScore -eq 94 -and $saved.HasAssessment -and $saved.Findings[0].HasBilingualText) 'Stored JSON did not deserialize into an assessed bilingual result.'
        Assert-True ($saved.Findings[0].EventRecordId -eq '2' -and $saved.Findings[0].AnalysisModel -eq 'synthetic-model') 'Evidence/model provenance was lost.'
        $today = $assistant.GetTodayResultAsync().GetAwaiter().GetResult()
        Assert-True ($null -ne $today -and $today.Timestamp.Kind -eq 'Utc') 'Python timestamps were excluded from .NET date queries.'
        [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools()
        Assert-True ((Get-FileHash -LiteralPath $extended.DatabasePath).Hash -eq $legacyHash) 'Publishing changed the extended database.'
    }

    Test-Case 'Incomplete coverage keeps findings but removes scores from dashboard and trends' {
        $row = $assistant.GetLatestResultAsync().GetAwaiter().GetResult()
        $row.Metadata['CoverageStatus'] = [Text.Json.JsonDocument]::Parse('"partial"').RootElement.Clone()
        Assert-True ($row.HasIncompleteCoverage -and -not $row.HasAssessment -and $row.Findings.Count -eq 1) 'Partial audit became a health assessment.'
        $type = $assembly.GetType('LocalSecurityAudit.ViewModels.DashboardViewModel', $true)
        $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
        $type.GetField('_storageService', $flags).SetValue($model, $assistant)
        $type.GetField('_allIssues', $flags).SetValue($model, [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssueEnhanced]]::new())
        $model.FindingSections = [Collections.ObjectModel.ObservableCollection[LocalSecurityAudit.ViewModels.FindingSection]]::new()
        $type.GetField('severityFilter', $flags).SetValue($model, 'All'); $type.GetField('sourceFilter', $flags).SetValue($model, 'All')
        $type.GetMethod('ApplyResult', $flags).Invoke($model, @($row))
        Assert-True ($model.HealthScoreText -eq '--' -and -not $model.HasAssessment -and $model.TotalFindings -eq 1) 'The dashboard displayed a score or hid partial evidence.'
        $trendType = $assembly.GetType('LocalSecurityAudit.ViewModels.TrendsViewModel', $true)
        $trends = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($trendType)
        $trendType.GetField('_findings', $flags).SetValue($trends, [Collections.Generic.List[LocalSecurityAudit.ViewModels.HistoryFinding]]::new())
        $rows = [Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new(); $rows.Add($row)
        $trendType.GetMethod('ApplyResults', $flags).Invoke($trends, @($rows, 7, [datetime]::Today))
        Assert-True ($trends.AverageHealthText -eq '--' -and $trends.FindingCountText -eq '1' -and @($trends.TrendDays | Where-Object { $null -ne $_.Health }).Count -eq 0) 'Trends included partial scores or lost partial findings.'
    }

    Test-Case 'Limited scope keeps findings but never becomes an overall health assessment' {
        $row = $assistant.GetLatestResultAsync().GetAwaiter().GetResult()
        $row.Metadata['CoverageStatus'] = [Text.Json.JsonDocument]::Parse('"limited"').RootElement.Clone()
        Assert-True ($row.HasLimitedCoverage -and $row.HasIncompleteCoverage -and -not $row.HasAssessment) 'Limited scope earned a full score.'
        $type = $assembly.GetType('LocalSecurityAudit.ViewModels.DashboardViewModel', $true)
        $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
        $type.GetField('_storageService', $flags).SetValue($model, $assistant)
        $type.GetField('_allIssues', $flags).SetValue($model, [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssueEnhanced]]::new())
        $model.FindingSections = [Collections.ObjectModel.ObservableCollection[LocalSecurityAudit.ViewModels.FindingSection]]::new()
        $type.GetField('severityFilter', $flags).SetValue($model, 'All'); $type.GetField('sourceFilter', $flags).SetValue($model, 'All')
        $type.GetMethod('ApplyResult', $flags).Invoke($model, @($row))
        Assert-True ($model.HealthScoreText -eq '--' -and $model.TotalFindings -eq 1 -and $model.CoverageState.Contains('Security')) 'Skipped logs were presented as failure, safety, or hidden findings.'
    }

    Test-Case 'Verified daily scope displays a labelled score without becoming a full assessment' {
        $row = [LocalSecurityAudit.Models.AuditResult]::new()
        $row.Timestamp = [datetime]::UtcNow
        $issue = [LocalSecurityAudit.Models.AuditIssue]::new()
        $issue.Title = 'Synthetic System finding'; $issue.LogName = 'System'; $issue.Severity = 'Medium'
        $row.Findings.Add($issue)
        $metadata = '{"CoverageStatus":"limited","AnalyzedEventCount":2,"EventCount":2,"Channels":[{"LogName":"Security","Status":"skipped","Reason":"not_requested","EventCount":0},{"LogName":"System","Status":"complete","Reason":"none","EventCount":2},{"LogName":"Application","Status":"complete","Reason":"none","EventCount":0},{"LogName":"Setup","Status":"complete","Reason":"none","EventCount":0},{"LogName":"ForwardedEvents","Status":"complete","Reason":"none","EventCount":0}]}'
        $row.Metadata = [Text.Json.JsonSerializer]::Deserialize($metadata, [Collections.Generic.Dictionary[string,Text.Json.JsonElement]])
        Assert-True ($row.HasScopedAssessment -and -not $row.HasAssessment) 'Daily and full assessments were conflated.'
        $type = $assembly.GetType('LocalSecurityAudit.ViewModels.DashboardViewModel', $true)
        $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
        $type.GetField('_storageService', $flags).SetValue($model, $assistant)
        $type.GetField('_allIssues', $flags).SetValue($model, [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssueEnhanced]]::new())
        $model.FindingSections = [Collections.ObjectModel.ObservableCollection[LocalSecurityAudit.ViewModels.FindingSection]]::new()
        $type.GetField('severityFilter', $flags).SetValue($model, 'All'); $type.GetField('sourceFilter', $flags).SetValue($model, 'All')
        $type.GetMethod('ApplyResult', $flags).Invoke($model, @($row))
        Assert-True ($model.HealthScoreText -eq '94' -and $model.HasAssessment -and $model.HealthScoreLabel -eq 'Daily health score' -and $model.HealthSummaryText.Contains('Security')) 'Daily score is missing or lacks its scope label.'
        $row.Metadata['AnalyzedEventCount'] = [Text.Json.JsonDocument]::Parse('0').RootElement.Clone()
        $type.GetMethod('ApplyResult', $flags).Invoke($model, @($row))
        Assert-True (-not $row.HasScopedAssessment -and $model.HealthScoreText -eq '--' -and $model.TotalFindings -eq 1) 'No analyzed evidence yielded a daily score or hid existing findings.'
        $row.Findings.Clear()
        foreach ($invalid in $metadata.Replace('"limited"', '"partial"'), $metadata.Replace('"complete"', '"unavailable"'), $metadata.Replace('"ForwardedEvents"', '"System"'), $metadata.Replace('"EventCount":2', '"EventCount":"2"')) {
            $row.Metadata = [Text.Json.JsonSerializer]::Deserialize($invalid, [Collections.Generic.Dictionary[string,Text.Json.JsonElement]])
            Assert-True (-not $row.HasScopedAssessment) 'Invalid or incomplete channel coverage yielded a score.'
        }
    }

    Test-Case 'Activity ranges use all audits, omit partial scores and preserve the selected date' {
        $storage = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended', (Join-Path $testRoot 'activity')).GetAwaiter().GetResult()
        foreach ($offset in -40, -2, 0, 0) {
            $row = [LocalSecurityAudit.Models.AuditResult]::new()
            $row.Timestamp = [datetime]::Today.AddDays($offset).AddHours(12).ToUniversalTime()
            $coverage = if ($offset -eq -40) { 'complete' } elseif ($offset -eq -2) { 'limited' } else { 'partial' }
            $row.Metadata = [Text.Json.JsonSerializer]::Deserialize('{"CoverageStatus":"' + $coverage + '","AnalyzedEventCount":1}', [Collections.Generic.Dictionary[string,Text.Json.JsonElement]])
            $issue = [LocalSecurityAudit.Models.AuditIssue]::new(); $issue.Title = 'Synthetic activity'; $issue.Severity = 'High'
            $row.Findings.Add($issue)
            $row.HealthScore = 100 # The dashboard must use the same finding-based score as the selected audit, not this stale number.
            $storage.SaveAuditResultAsync($row).GetAwaiter().GetResult()
        }
        $days = $storage.GetAuditActivityAsync([datetime]::Today).GetAwaiter().GetResult()
        Assert-True ($days.Count -eq 3 -and $days[0].ScoreSum -eq 85 -and $days[1].AssessedScans -eq 0) 'Daily statistics hid audits or included limited scores.'
        $type = $assembly.GetType('LocalSecurityAudit.ViewModels.DashboardViewModel', $true)
        $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
        $selected = [datetime]::Today.AddDays(-2)
        $type.GetField('_selectedDate', $flags).SetValue($model, $selected)
        $type.GetMethod('ApplyActivity', $flags).Invoke($model, @($days, [datetime]::Today))
        Assert-True ($model.ActivityScansText -eq '4' -and $model.ActivityFindingsText -eq '4' -and $model.ActiveDaysText -eq '3' -and $model.AverageHealthText -eq '85.0') 'All-time statistics are not correct.'
        $model.SetActivityRangeCommand.Execute('30')
        Assert-True ($model.IsRange30 -and $model.ActivityDays.Count -eq 30 -and $model.ActivityColumns -eq 15 -and $model.ActivityScansText -eq '3' -and $model.AverageHealthText -eq '--') '30-day statistics included older/partial scores or used unbalanced date rows.'
        $model.SetActivityRangeCommand.Execute('7')
        Assert-True ($model.IsRange7 -and $model.ActivityDays.Count -eq 7 -and $model.ActivityColumns -eq 7 -and @($model.ActivityDays | Where-Object IsSelected).Count -eq 1 -and $type.GetField('_selectedDate', $flags).GetValue($model) -eq $selected) 'Range selection lost the selected audit date.'
        $cells = $model.ActivityDays
        $cell = $cells[4]
        $type.GetMethod('ApplyActivity', $flags).Invoke($model, @($days, [datetime]::Today))
        Assert-True ([object]::ReferenceEquals($cells, $model.ActivityDays) -and [object]::ReferenceEquals($cell, $model.ActivityDays[4])) 'Refreshing replaced date controls and lost keyboard focus.'
        Assert-True (@($model.ActivityDays | Where-Object { $_.Scans -eq 0 -and $_.ActivityOpacity -ne 0 }).Count -eq 0) 'No-audit days were colored as activity.'
        $old = [LocalSecurityAudit.Models.AuditActivityDay]::new(); $old.Date = [datetime]::Today.AddDays(-500); $old.Scans = 1
        $days.Add($old)
        $type.GetMethod('ApplyActivity', $flags).Invoke($model, @($days, [datetime]::Today))
        $model.SetActivityRangeCommand.Execute('0')
        Assert-True ($model.ActivityDays.Count -eq 365 -and $model.ActivityScansText -eq '5' -and $model.ActivityHint.Contains('365')) 'Heatmap cap silently truncated all-time totals.'
    }

    Test-Case 'Shared history keeps mode-specific scan cursors and never advances failures' {
        $storage = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended', (Join-Path $testRoot 'cursors')).GetAwaiter().GetResult()
        $now = [datetime]::UtcNow
        foreach ($mode in 'full', 'extended') {
            $row = [LocalSecurityAudit.Models.AuditResult]::new(); $row.Timestamp = $now
            $row.Metadata = [Text.Json.JsonSerializer]::Deserialize('{"Mode":"' + $mode + '","CoverageStatus":"limited","ScanEnd":"' + $now.AddHours(-1).ToString('o') + '"}', [Collections.Generic.Dictionary[string,Text.Json.JsonElement]])
            $storage.SaveAuditResultAsync($row).GetAwaiter().GetResult()
        }
        $full = $storage.GetLatestResultAsync('full').GetAwaiter().GetResult()
        $extended = $storage.GetLatestResultAsync('extended').GetAwaiter().GetResult()
        Assert-True ($full.Metadata['Mode'].GetString() -eq 'full' -and $extended.Metadata['Mode'].GetString() -eq 'extended') 'A mode resumed another scope.'
        $type = $assembly.GetType('LocalSecurityAudit.Services.AuditSchedulerService', $true)
        Assert-True ($type.GetMethod('GetStoredScanEnd', $flags).Invoke($null, @($extended, $now)) -ne [datetime]::MinValue) 'Intentional skip lost the daily cursor.'
        $extended.Metadata['CoverageStatus'] = [Text.Json.JsonDocument]::Parse('"partial"').RootElement.Clone()
        Assert-True ($type.GetMethod('GetStoredScanEnd', $flags).Invoke($null, @($extended, $now)) -eq [datetime]::MinValue) 'Read failure advanced the cursor.'
    }

    Test-Case 'The viewer detects committed WAL changes without polling file timestamps' {
        $fresh = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('assistant', (Join-Path $testRoot 'first-wal-commit')).GetAwaiter().GetResult()
        $recorder = [DatabaseChangeRecorder]::new()
        $action = [Action]::CreateDelegate([Action], $recorder, $recorder.GetType().GetMethod('Record'))
        $cancel = [Threading.CancellationTokenSource]::new()
        $watch = $fresh.WatchForChangesAsync($action, $cancel.Token)
        $writer = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$($fresh.DatabasePath);Pooling=False")
        try {
            Assert-True ($recorder.Count -eq 1) 'The watcher did not establish its initial data version.'
            $writer.Open()
            $command = $writer.CreateCommand(); $command.CommandText = 'PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;'
            $null = $command.ExecuteNonQuery()
            $command.CommandText = "INSERT INTO AuditResults (Timestamp, HealthScore, FindingsJson, MetadataJson) VALUES ('2026-01-01 00:00:00', 100, '[]', @metadata)"
            $null = $command.Parameters.AddWithValue('@metadata', '{"Mode":"assistant","AnalyzedEventCount":0}')
            $null = $command.ExecuteNonQuery()
            $recorder.Changed.Task.WaitAsync([timespan]::FromSeconds(8)).GetAwaiter().GetResult()
            Assert-True ((Test-Path -LiteralPath ($fresh.DatabasePath + '-wal')) -and $recorder.Count -gt 1) 'The first external WAL commit was not visible.'
            $rejected = $false
            try { $null = $fresh.GetAuditRecordCountAsync().GetAwaiter().GetResult() }
            catch { $rejected = $_.Exception.GetBaseException() -is [IO.InvalidDataException] }
            Assert-True ($rejected -and $fresh.RejectedAssistantRecords -eq 1) 'Malformed external metadata entered the shared view.'
        }
        finally {
            $cancel.Cancel()
            try { $watch.GetAwaiter().GetResult() } catch [OperationCanceledException] { }
            $writer.Dispose(); $cancel.Dispose()
        }
    }

    Test-Case 'The build has an asInvoker manifest and includes the external workflow' {
        $exe = Join-Path $directory 'LocalSecurityAudit.exe'
        Assert-True ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($exe)).Contains('level="asInvoker"')) 'The executable still requires administrator privileges.'
            Assert-True ([Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion -eq '0.3.7') 'Product version was not applied.'
        foreach ($relative in 'AGENTS.md','tools/collect-assistant-events.ps1','tools/publish-assistant-audit.py') {
            Assert-True (Test-Path -LiteralPath (Join-Path $directory $relative)) "Missing packaged workflow file: $relative"
            $source = Join-Path (Split-Path $PSScriptRoot -Parent) $relative
            Assert-True ((Get-FileHash -LiteralPath $source).Hash -eq (Get-FileHash -LiteralPath (Join-Path $directory $relative)).Hash) "Outdated packaged workflow file: $relative"
        }
    }
}
finally {
    [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools()
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempBoundary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($tempBoundary, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolvedRoot -Leaf) -notlike 'lsa-mode-test-*') { throw 'Unsafe test cleanup path.' }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}
"$script:passed passed; $script:failed failed. Synthetic temporary files only; no app launch, UAC, real logs or AI calls."
if ($script:failed -gt 0) { exit 1 }
