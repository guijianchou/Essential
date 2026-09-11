# Exercises compiled history/storage code with synthetic data and memory SQLite.
# Never activates WinUI, reads user settings/event logs, or calls AI endpoints.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll"
)

$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$assemblyDirectory = Split-Path -Parent $assembly.Location
$null = [Reflection.Assembly]::LoadFrom((Join-Path $assemblyDirectory 'Microsoft.Data.Sqlite.dll'))
$null = [Reflection.Assembly]::LoadFrom((Join-Path $assemblyDirectory 'SQLitePCLRaw.batteries_v2.dll'))
$sqlitePath = Join-Path $assemblyDirectory 'e_sqlite3.dll'
if (-not (Test-Path -LiteralPath $sqlitePath)) { $sqlitePath = Join-Path $assemblyDirectory 'runtimes/win-x64/native/e_sqlite3.dll' }
$null = [Runtime.InteropServices.NativeLibrary]::Load($sqlitePath)
[SQLitePCL.Batteries_V2]::Init()
$flags = [Reflection.BindingFlags]'NonPublic,Instance,Static'
$storageType = $assembly.GetType('LocalSecurityAudit.Services.DataStorageService', $true)
$trendsType = $assembly.GetType('LocalSecurityAudit.ViewModels.TrendsViewModel', $true)
$script:passed = 0
$script:failed = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Test-Case([string]$Name, [scriptblock]$Action) {
    try {
        $null = & $Action
        $script:passed++
        Write-Output "PASS $Name"
    }
    catch {
        $script:failed++
        Write-Output "FAIL $Name`: $($_.Exception.GetBaseException().Message)"
        Write-Output $_.ScriptStackTrace
    }
}

function Use-HistoryDatabase([scriptblock]$Action) {
    $database = Join-Path ([IO.Path]::GetTempPath()) "lsa-history-$([guid]::NewGuid()).db"
    $connectionString = "Data Source=$database;Pooling=False"
    $keeper = [Microsoft.Data.Sqlite.SqliteConnection]::new($connectionString)
    try {
        $keeper.Open()
        $storage = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($storageType)
        $storageType.GetField('_connectionString', $flags).SetValue($storage, $connectionString)
        $storageType.GetField('_historyPaths', $flags).SetValue($storage, [string[]]@($database, "$database.assistant"))
        $storageType.GetMethod('InitializeDatabaseAsync', $flags).Invoke($storage, @()).GetAwaiter().GetResult()
        & $Action $storage $keeper
    }
    finally { $keeper.Dispose(); [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools(); [IO.File]::Delete($database) }
}

function Add-Record($Connection, [datetime]$Timestamp, [string]$Findings = '[]', [string]$Metadata = '{"EventCount":1}') {
    $command = $Connection.CreateCommand()
    try {
        $command.CommandText = 'INSERT INTO AuditResults (Timestamp, HealthScore, FindingsJson, MetadataJson) VALUES (@time, 85, @findings, @metadata)'
        $null = $command.Parameters.AddWithValue('@time', $Timestamp.ToUniversalTime())
        $null = $command.Parameters.AddWithValue('@findings', $Findings)
        $null = $command.Parameters.AddWithValue('@metadata', $Metadata)
        $null = $command.ExecuteNonQuery()
    }
    finally { $command.Dispose() }
}

function New-TrendsModel($Storage = $null) {
    $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($trendsType)
    $trendsType.GetField('_storageService', $flags).SetValue($model, $Storage)
    $trendsType.GetField('windowDays', $flags).SetValue($model, 7)
    $trendsType.GetField('_findings', $flags).SetValue($model, [Collections.Generic.List[LocalSecurityAudit.ViewModels.HistoryFinding]]::new())
    return $model
}

function New-Scan([datetime]$LocalTime, [string[]]$Severities = @(), [bool]$Assessed = $true) {
    $result = [LocalSecurityAudit.Models.AuditResult]::new()
    $result.Timestamp = $LocalTime.ToUniversalTime()
    foreach ($severity in $Severities) {
        $issue = [LocalSecurityAudit.Models.AuditIssue]::new()
        $issue.Title = 'Repeated finding'
        $issue.Description = 'Synthetic description'
        $issue.RootCause = 'Synthetic cause'
        $issue.Recommendation = 'Synthetic action'
        $issue.Severity = $severity
        $issue.Category = 'Login'
        $issue.EventRecordId = 'same-record'
        $issue.EventDescription = 'Original evidence'
        $result.Findings.Add($issue)
    }
    $result.Metadata = [Collections.Generic.Dictionary[string,System.Text.Json.JsonElement]]::new()
    $result.Metadata['AnalyzedEventCount'] = [System.Text.Json.JsonSerializer]::SerializeToElement([int]$Assessed, [int])
    return $result
}

Test-Case 'Latest audit falls back past malformed rows without changing stored data' {
    Use-HistoryDatabase {
        param($storage, $connection)
        $today = [datetime]::Today
        Add-Record $connection $today '[{"Title":"Last available","Severity":"High"}]'
        foreach ($json in '{', 'null', '[null]', '{}') { Add-Record $connection $today.AddHours(1) $json }
        Add-Record $connection $today.AddHours(2) '[]' '{invalid metadata'
        $latest = $storage.GetLatestResultAsync().GetAwaiter().GetResult()
        Assert-True ($latest.Findings[0].Title -eq 'Last available') 'Latest audit did not recover the last readable record.'
        Assert-True ($latest.Timestamp.Kind -eq 'Utc') 'Stored timestamps lost their UTC kind.'
        Assert-True ($storage.GetAuditRecordCountAsync().GetAwaiter().GetResult() -eq 1) 'Invalid records were counted as readable audits.'
        $check = $connection.CreateCommand()
        $check.CommandText = 'SELECT count(*) FROM AuditResults'
        Assert-True ($check.ExecuteScalar() -eq 6) 'Reading history mutated or deleted rows.'
        $check.Dispose()
        Assert-True ($storage.GetTodayResultAsync().GetAwaiter().GetResult().Findings[0].Title -eq 'Last available') 'Today lookup did not skip malformed rows.'
    }
}

Test-Case 'History and legacy translation skip malformed findings independently' {
    Use-HistoryDatabase {
        param($storage, $connection)
        Add-Record $connection ([datetime]::Today) '[{"Title":"Legacy","Severity":"High"}]'
        foreach ($json in '{', 'null', '[null]') { Add-Record $connection ([datetime]::Today.AddHours(1)) $json }
        Assert-True ($storage.GetTrendsAsync(1).GetAwaiter().GetResult().Count -eq 1) 'One bad row hid readable history.'
        Assert-True ($storage.GetLegacyFindingsAsync().GetAwaiter().GetResult().Count -eq 1) 'One bad row blocked all legacy translations.'
    }
}

Test-Case 'An entirely unreadable database reports failure instead of a clean empty audit' {
    Use-HistoryDatabase {
        param($storage, $connection)
        Assert-True ($null -eq $storage.GetLatestResultAsync().GetAwaiter().GetResult()) 'Empty database was reported as corrupt.'
        Add-Record $connection ([datetime]::Today) '[null]'
        foreach ($task in $storage.GetLatestResultAsync(), $storage.GetTrendsAsync(1)) {
            $threw = $false
            try { $null = $task.GetAwaiter().GetResult() }
            catch {
                $threw = $_.Exception.GetBaseException() -is [IO.InvalidDataException]
            }
            Assert-True $threw 'Corrupt-only data was silently presented as an empty successful audit.'
        }
    }
}

foreach ($days in 1, 7, 30) {
    Test-Case "$days-day query includes first local midnight and excludes both outside boundaries" {
        Use-HistoryDatabase {
            param($storage, $connection)
            $start = [datetime]::Today.AddDays(1 - $days)
            $end = [datetime]::Today.AddDays(1)
            foreach ($time in $start.AddTicks(-1), $start, $end.AddTicks(-1), $end) { Add-Record $connection $time }
            $rows = $storage.GetTrendsAsync($days).GetAwaiter().GetResult()
            Assert-True ($rows.Count -eq 2 -and $rows[0].Timestamp -eq $start.ToUniversalTime() -and $rows[1].Timestamp -eq $end.AddTicks(-1).ToUniversalTime()) 'Query and local calendar boundaries differ.'
        }
    }
}

Test-Case 'Default cleanup retains all 30 calendar days, including the first midnight' {
    Use-HistoryDatabase {
        param($storage, $connection)
        $start = [datetime]::Today.AddDays(-29)
        foreach ($time in $start.AddTicks(-1), $start, [datetime]::Today) { Add-Record $connection $time }
        $storage.CleanupOldDataAsync().GetAwaiter().GetResult()
        Assert-True ($storage.GetAuditRecordCountAsync().GetAwaiter().GetResult() -eq 2) 'Cleanup removed an in-window audit or retained an expired audit.'
    }
}

Test-Case 'Retention migration changes legacy seven days once and preserves later user choices' {
    $type = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
    $normalize = $type.GetMethod('Normalize', $flags)
    Assert-True ([LocalSecurityAudit.Models.AppSettings]::new().RetentionDays -eq 30) 'New settings do not default to 30 days.'
    foreach ($days in 3, 7, 14, 30, 99) {
        $settings = [LocalSecurityAudit.Models.AppSettings]::new()
        $settings.RetentionDays = $days
        $null = $normalize.Invoke($null, @($settings))
        $expected = if ($days -in 7, 99) { 30 } else { $days }
        Assert-True ($settings.RetentionDays -eq $expected -and $settings.RetentionPolicyVersion -eq 1) 'Legacy settings migrated incorrectly.'
        $settings.RetentionDays = 7
        $null = $normalize.Invoke($null, @($settings))
        Assert-True ($settings.RetentionDays -eq 7) 'Normalization overrode a post-migration choice.'
    }
}

foreach ($days in 1, 7, 30) {
    Test-Case "$days-day summary, chart and list include the same reports and preserve evidence" {
        $model = New-TrendsModel
        $today = [datetime]::Today
        $scans = [Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new()
        $scans.Add((New-Scan $today.AddDays(-30) @('High')))
        $scans.Add((New-Scan $today.AddDays(-29) @('Medium')))
        $scans.Add((New-Scan $today.AddDays(-6) @('Low')))
        $scans.Add((New-Scan $today.AddHours(1) @('High')))
        $scans.Add((New-Scan $today.AddHours(1).AddMinutes(1) @('High')))
        $scans.Add((New-Scan $today.AddHours(2) @() $false))
        $scans.Add((New-Scan $today.AddDays(1) @('High')))
        $null = $trendsType.GetMethod('ApplyResults', $flags).Invoke($model, @($scans, $days, $today))
        $expectedFindings = switch ($days) { 1 { 2 } 7 { 3 } 30 { 4 } }
        $expectedBuckets = if ($days -eq 1) { 24 } else { $days }
        Assert-True ($model.TrendDays.Count -eq $expectedBuckets -and [int]$model.FindingCountText -eq $expectedFindings) 'Window selection did not update buckets and totals.'
        Assert-True (($model.TrendDays | Measure-Object Total -Sum).Sum -eq $expectedFindings -and ($model.CategoryTotals | Measure-Object Count -Sum).Sum -eq $expectedFindings) 'Charts and summaries count different reports.'
        Assert-True ($model.VisibleFindings.Count -eq $expectedFindings -and [int]$model.ScansText -eq $expectedFindings + 1) 'Historical details or empty scans disappeared.'
        Assert-True ($model.VisibleFindings[0].Issue.EventDescription -eq 'Original evidence' -and $model.VisibleFindings[0].Issue.Recommendation -eq 'Synthetic action') 'History lost its evidence or solution.'
        Assert-True ($model.VisibleFindings[0].ScanTimestamp -eq $today.AddHours(1).AddMinutes(1).ToUniversalTime()) 'Reports are not ordered by their scan timestamps.'
        if ($days -eq 1) {
            Assert-True ($model.AverageHealthText -eq '85' -and $model.TrendDays[1].Health -eq 85 -and $null -eq $model.TrendDays[2].Health) 'Unassessed scans changed the health average or erased gaps.'
        }
    }
}

Test-Case 'History pagination and severity filtering stay within the selected reports' {
    $model = New-TrendsModel
    $scans = [Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new()
    $scan = New-Scan ([datetime]::Today) (@('High') * 22 + @('Low'))
    $scans.Add($scan)
    $null = $trendsType.GetMethod('ApplyResults', $flags).Invoke($model, @($scans, 1, [datetime]::Today))
    Assert-True ($model.VisibleFindings.Count -eq 20 -and $model.CanGoForward -and -not $model.CanGoBack) 'First page is not bounded.'
    $model.NextPageCommand.Execute($null)
    Assert-True ($model.VisibleFindings.Count -eq 3 -and $model.CanGoBack -and -not $model.CanGoForward) 'Last page is incorrect.'
    $model.SeverityFilterIndex = 3
    Assert-True ($model.VisibleFindings.Count -eq 1 -and $model.VisibleFindings[0].Issue.IsLow -and -not $model.CanGoBack) 'Severity change did not reset pagination.'
    $model.SeverityFilterIndex = 2
    Assert-True (-not $model.HasFindings -and $model.VisibleFindings.Count -eq 0) 'Empty filter retained stale findings.'
}

Test-Case 'Overlapping period loads cannot overwrite the newest selection' {
    Use-HistoryDatabase {
        param($storage, $connection)
        $command = $connection.CreateCommand()
        $command.CommandText = 'WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO AuditResults (Timestamp, HealthScore, FindingsJson) SELECT @time, 85, ''[{"Title":"Older report","Severity":"High"}]'' FROM n'
        $null = $command.Parameters.AddWithValue('@time', [datetime]::Today.AddDays(-29).ToUniversalTime())
        $null = $command.ExecuteNonQuery()
        $command.Dispose()
        Add-Record $connection ([datetime]::Today) '[{"Title":"Current report","Severity":"Low"}]'
        $model = New-TrendsModel $storage
        $load = $trendsType.GetMethod('LoadDataAsync', $flags)
        $trendsType.GetField('windowDays', $flags).SetValue($model, 30)
        $older = $load.Invoke($model, @())
        $trendsType.GetField('windowDays', $flags).SetValue($model, 1)
        $newer = $load.Invoke($model, @())
        $newer.GetAwaiter().GetResult()
        $older.GetAwaiter().GetResult()
        Assert-True ($model.TrendDays.Count -eq 24 -and $model.FindingCountText -eq '1' -and $model.VisibleFindings[0].Issue.Title -eq 'Current report' -and -not $model.IsLoading) 'A stale period load replaced the latest selection.'
    }
}

Test-Case 'Dashboard keeps its last successful display when storage or a scan fails' {
    Use-HistoryDatabase {
        param($storage, $connection)
        Add-Record $connection ([datetime]::Today) '[{"Title":"Available audit","Severity":"High","Recommendation":"Keep evidence"}]'
        $type = $assembly.GetType('LocalSecurityAudit.ViewModels.DashboardViewModel', $true)
        $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
        $type.GetField('_storageService', $flags).SetValue($model, $storage)
        $schedulerType = $assembly.GetType('LocalSecurityAudit.Services.AuditSchedulerService', $true)
        $scheduler = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($schedulerType)
        $settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
        $settings = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
        $settingsType.GetField('<ActiveMode>k__BackingField', $flags).SetValue($settings, 'extended')
        $schedulerType.GetField('_settingsService', $flags).SetValue($scheduler, $settings)
        $type.GetField('_schedulerService', $flags).SetValue($model, $scheduler)
        $type.GetField('_allIssues', $flags).SetValue($model, [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssueEnhanced]]::new())
        $type.GetField('severityFilter', $flags).SetValue($model, 'All')
        $type.GetField('sourceFilter', $flags).SetValue($model, 'All')
        $model.FindingSections = [Collections.ObjectModel.ObservableCollection[LocalSecurityAudit.ViewModels.FindingSection]]::new()
        $model.RecentDays = [Collections.Generic.List[LocalSecurityAudit.ViewModels.DashboardDay]]::new()
        $load = $type.GetMethod('LoadDataAsync', $flags)
        $load.Invoke($model, @()).GetAwaiter().GetResult()
        Assert-True ($model.HasAuditData -and $model.HealthScore -eq 85 -and -not $model.IsLoading) 'Automatic initial load failed.'
        $command = $connection.CreateCommand()
        $command.CommandText = 'UPDATE AuditResults SET FindingsJson=''[null]'''
        $null = $command.ExecuteNonQuery()
        $command.Dispose()
        $load.Invoke($model, @()).GetAwaiter().GetResult()
        Assert-True ($model.HasAuditData -and $model.HealthScore -eq 85 -and $model.PriorityFindings[0].Title -eq 'Available audit' -and $model.IsStatusVisible -and -not $model.IsLoading) 'Storage failure erased the available audit or left loading stuck.'
        $failure = [LocalSecurityAudit.Services.AuditFailedEventArgs]::new('Synthetic scan failure')
        $null = $type.GetMethod('OnAuditFailed', $flags).Invoke($model, @($null, $failure))
        Assert-True ($model.HasAuditData -and $model.HealthScore -eq 85) 'Failed scan replaced the previous audit.'
        Assert-True ($model.IsStatusVisible -and $model.StatusSeverity.ToString() -eq 'Error' -and $model.StatusMessage.Contains($failure.Message)) 'The dashboard did not show the terminal scan error.'
        $command = $connection.CreateCommand()
        $command.CommandText = 'UPDATE AuditResults SET FindingsJson=''[{"Title":"Available audit","Severity":"High","Recommendation":"Keep evidence"}]'''
        $null = $command.ExecuteNonQuery()
        $command.Dispose()
        $load.Invoke($model, @()).GetAwaiter().GetResult()
        Assert-True ($model.IsStatusVisible -and $model.StatusSeverity.ToString() -eq 'Error' -and $model.StatusMessage.Contains($failure.Message)) 'A successful history refresh hid the failed scan.'
        $model.IsStatusVisible = $false
        $load.Invoke($model, @()).GetAwaiter().GetResult()
        Assert-True (-not $model.IsStatusVisible) 'Refreshing history reopened a dismissed scan error.'
        $type.GetField('_isLoadingData', $flags).SetValue($model, $true)
        $null = $type.GetMethod('OnAuditFailed', $flags).Invoke($model, @($null, $failure))
        Assert-True $model.IsLoading 'A scan event incorrectly ended an ongoing data read.'
    }
}

Test-Case 'Unassessed trend reports do not carry an assessed health indicator' {
    $model = New-TrendsModel
    $results = [Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new()
    $results.Add((New-Scan ([datetime]::Today) @('Low') $false))
    $results[0].Metadata['CoverageStatus'] = [System.Text.Json.JsonSerializer]::SerializeToElement('partial', [string])
    $apply = $trendsType.GetMethod('ApplyResults', $flags)
    $null = $apply.Invoke($model, @($results, 7, [datetime]::Today))
    Assert-True ($model.HasData -and -not $model.HasAssessment -and $model.AverageHealthText -eq '--') 'Unassessed history was marked as assessed.'
    $results.Add((New-Scan ([datetime]::Today.AddHours(1)) @('Low') $true))
    $null = $apply.Invoke($model, @($results, 7, [datetime]::Today))
    Assert-True $model.HasAssessment 'An assessed scan did not enable its health indicator.'
}

Test-Case 'Scan completion and history updates reload selected-period reports and bilingual text' {
    Use-HistoryDatabase {
        param($storage, $connection)
        $model = New-TrendsModel $storage
        $language = [LocalSecurityAudit.Services.AppText]::Current.Language
        try {
            $json = '[{"Title":"Saved analysis","Description":"Evidence","RootCause":"Cause","Recommendation":"Action","TitleZh":"\u5206\u6790","DescriptionZh":"\u8bc1\u636e","RootCauseZh":"\u539f\u56e0","RecommendationZh":"\u5efa\u8bae","Severity":"Medium"}]'
            Add-Record $connection ([datetime]::Today) $json
            $latest = $storage.GetLatestResultAsync().GetAwaiter().GetResult()
            $event = [LocalSecurityAudit.Services.AuditCompletedEventArgs]::new($latest)
            $null = $trendsType.GetMethod('OnAuditCompleted', $flags).Invoke($model, @($null, $event))
            $model.LoadDataCommand.ExecutionTask.GetAwaiter().GetResult()
            Assert-True ($model.FindingCountText -eq '1') 'Scan completion did not refresh history.'
            [LocalSecurityAudit.Services.AppText]::Current.SetLanguage('zh-CN')
            Add-Record $connection ([datetime]::Today.AddHours(1)) $json
            $null = $trendsType.GetMethod('OnHistoryChanged', $flags).Invoke($model, @($null, [EventArgs]::Empty))
            $model.LoadDataCommand.ExecutionTask.GetAwaiter().GetResult()
            Assert-True ($model.FindingCountText -eq '2' -and $model.VisibleFindings[0].Issue.Title -eq $latest.Findings[0].TitleZh -and -not $model.VisibleFindings[0].Issue.NeedsTranslation) 'History update did not use stored bilingual results.'
        }
        finally { [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($language) }
    }
}

Test-Case 'Failed refresh preserves only data from the same period' {
    Use-HistoryDatabase {
        param($storage, $connection)
        Add-Record $connection ([datetime]::Today) '[{"Title":"Available report","Severity":"High"}]'
        $model = New-TrendsModel $storage
        $load = $trendsType.GetMethod('LoadDataAsync', $flags)
        $load.Invoke($model, @()).GetAwaiter().GetResult()
        $command = $connection.CreateCommand()
        $command.CommandText = 'UPDATE AuditResults SET FindingsJson=''[null]'''
        $null = $command.ExecuteNonQuery()
        $command.Dispose()
        $load.Invoke($model, @()).GetAwaiter().GetResult()
        Assert-True ($model.HasData -and $model.FindingCountText -eq '1' -and $model.IsStatusVisible) 'Refresh failure erased last available data for this period.'
        $trendsType.GetField('windowDays', $flags).SetValue($model, 1)
        $load.Invoke($model, @()).GetAwaiter().GetResult()
        Assert-True (-not $model.HasData -and $model.FindingCountText -eq '0' -and $model.IsStatusVisible -and -not $model.IsLoading) 'A failed new period displayed old-period data or stayed loading.'
    }
}

Test-Case 'Dashboard source tabs, summary counts and severity filters select the same evidence' {
    $type = $assembly.GetType('LocalSecurityAudit.ViewModels.DashboardViewModel', $true)
    $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
    $type.GetField('_allIssues', $flags).SetValue($model, [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssueEnhanced]]::new())
    $type.GetField('severityFilter', $flags).SetValue($model, 'All')
    $type.GetField('sourceFilter', $flags).SetValue($model, 'All')
    $model.FindingSections = [Collections.ObjectModel.ObservableCollection[LocalSecurityAudit.ViewModels.FindingSection]]::new()
    $audit = [LocalSecurityAudit.Models.AuditResult]::new()
    $audit.Timestamp = [datetime]::UtcNow
    foreach ($log in 'System', 'Application', 'Security', 'Security', 'Setup', '') {
        $issue = [LocalSecurityAudit.Models.AuditIssue]::new()
        $issue.LogName = $log
        $issue.Title = "From $log"
        $issue.Severity = if ($log -eq 'System') { 'High' } else { 'Medium' }
        $issue.Category = 'System'
        $issue.EventDescription = "Original $log evidence"
        $issue.Recommendation = "Review $log record"
        $audit.Findings.Add($issue)
    }
    $type.GetMethod('ApplyResult', $flags).Invoke($model, @($audit))
    Assert-True ($model.TotalFindings -eq 6 -and $model.HighCount -eq 1 -and $model.SecurityLabel.EndsWith('2')) 'Overview or source counts omit findings.'
    foreach ($log in 'Application', 'Security', 'Setup', 'System') {
        $model.SetSourceFilterCommand.Execute($log)
        $expected = if ($log -eq 'Security') { 2 } else { 1 }
        Assert-True ($model.TotalFindings -eq $expected -and $model.PriorityFindings.Count -eq $expected -and ($model.FindingSections | Measure-Object Count -Sum).Sum -eq $expected) "Source $log summary and findings differ."
        Assert-True ($model.PriorityFindings[0].LogName -eq $log -and $model.PriorityFindings[0].EventDescription -eq "Original $log evidence") 'A category name was used in place of the actual source log.'
    }
    $model.SetSeverityFilterCommand.Execute('High')
    Assert-True ($model.PriorityFindings.Count -eq 1 -and $model.PriorityFindings[0].LogName -eq 'System') 'Severity filter ignored the source tab.'
    $model.SetSourceFilterCommand.Execute('Setup')
    Assert-True ($model.TotalFindings -eq 1 -and $model.HighCount -eq 0 -and $model.PriorityFindings.Count -eq 0 -and $model.ShowNoFilterMatches) 'Empty combined filter retained another source.'
    $model.SetSourceFilterCommand.Execute('All')
    $model.SetSeverityFilterCommand.Execute('All')
    Assert-True ($model.TotalFindings -eq 6 -and ($model.FindingSections | Measure-Object Count -Sum).Sum -eq 6) 'Returning to overview lost legacy findings without a source.'
}

Test-Case 'Dashboard days choose the latest readable scan on that local day and keep empty days empty' {
    Use-HistoryDatabase {
        param($storage, $connection)
        $today = [datetime]::Today
        Add-Record $connection $today '[{"Title":"Today","Severity":"Low"}]'
        Add-Record $connection $today.AddDays(-1) '[{"Title":"Yesterday early","Severity":"Medium"}]'
        Add-Record $connection $today.AddDays(-1).AddHours(10) '[{"Title":"Yesterday latest","Severity":"High"}]'
        Add-Record $connection $today.AddDays(-1).AddHours(12) '[null]'
        $type = $assembly.GetType('LocalSecurityAudit.ViewModels.DashboardViewModel', $true)
        $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
        $type.GetField('_storageService', $flags).SetValue($model, $storage)
        $scheduler = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($assembly.GetType('LocalSecurityAudit.Services.AuditSchedulerService', $true))
        $settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
        $settings = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
        $settingsType.GetField('<ActiveMode>k__BackingField', $flags).SetValue($settings, 'extended')
        $scheduler.GetType().GetField('_settingsService', $flags).SetValue($scheduler, $settings)
        $type.GetField('_schedulerService', $flags).SetValue($model, $scheduler)
        $type.GetField('_allIssues', $flags).SetValue($model, [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssueEnhanced]]::new())
        $type.GetField('severityFilter', $flags).SetValue($model, 'All')
        $type.GetField('sourceFilter', $flags).SetValue($model, 'All')
        $model.FindingSections = [Collections.ObjectModel.ObservableCollection[LocalSecurityAudit.ViewModels.FindingSection]]::new()
        $model.RecentDays = [Collections.Generic.List[LocalSecurityAudit.ViewModels.DashboardDay]]::new()
        $model.LoadDataCommand.ExecuteAsync($null).GetAwaiter().GetResult()
        Assert-True ($model.RecentDays.Count -eq 7 -and $model.TotalFindings -eq 3 -and $model.SelectedDayText.StartsWith($today.ToString('yyyy-MM-dd'))) 'Default view lost the shared overview or latest audit date.'
        $week = $model.RecentDays
        $yesterday = $model.RecentDays[5]
        $model.SelectDayCommand.Execute($model.RecentDays[5])
        Assert-True ($model.SelectedAuditLabel -eq [LocalSecurityAudit.Services.AppText]::Format('Audit on {0:d}', $yesterday.Date)) 'Date title did not change with selection.'
        Assert-True ($model.PriorityFindings.Count -eq 0 -or $model.PriorityFindings[0].Title -eq 'Yesterday latest') 'New date temporarily displayed old-date findings.'
        $model.LoadDataCommand.ExecutionTask.GetAwaiter().GetResult()
        Assert-True ($model.PriorityFindings[0].Title -eq 'Yesterday latest' -and $model.HighCount -eq 1 -and $model.RecentDays[5].IsSelected) 'Selected date did not load the latest readable record.'
        Assert-True ([object]::ReferenceEquals($week, $model.RecentDays) -and [object]::ReferenceEquals($yesterday, $model.RecentDays[5])) 'Reloading replaced the date buttons and their keyboard focus.'
        $model.SelectDayCommand.Execute($model.RecentDays[4])
        $model.LoadDataCommand.ExecutionTask.GetAwaiter().GetResult()
        Assert-True (-not $model.HasAuditData -and $model.TotalFindings -eq 0 -and $model.PriorityFindings.Count -eq 0) 'An empty day retained another day findings.'
        $model.SelectDayCommand.Execute($model.RecentDays[5])
        $older = $model.LoadDataCommand.ExecutionTask
        $model.SelectDayCommand.Execute($model.RecentDays[6])
        $newer = $model.LoadDataCommand.ExecutionTask
        $newer.GetAwaiter().GetResult(); $older.GetAwaiter().GetResult()
        Assert-True ($model.PriorityFindings[0].Title -eq 'Today' -and -not $model.IsDateLoading) 'A stale selection overwrote the current day.'
        Add-Record $connection $today.AddDays(-1).AddHours(14) '[{"Title":"Another scan","Severity":"Low"}]'
        $model.LoadDataCommand.ExecuteAsync($null).GetAwaiter().GetResult()
        Assert-True ([object]::ReferenceEquals($yesterday, $model.RecentDays[5]) -and $yesterday.Scans -eq 3) 'Readable date counts did not update on the existing buttons.'
        $model.SelectDayCommand.Execute($yesterday)
        $model.LoadDataCommand.ExecutionTask.GetAwaiter().GetResult()
        $settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
        $settingsService = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
        $settings = [LocalSecurityAudit.Models.AppSettings]::new()
        $settings.Mode = 'extended'
        $settings.FastScanRangeHours = 4
        $settings.DiagnosticLoggingEnabled = $false
        $settingsType.GetProperty('Current').SetValue($settingsService, $settings)
        $settingsType.GetField('<ActiveMode>k__BackingField', $flags).SetValue($settingsService, 'extended')
        $loggerType = $assembly.GetType('LocalSecurityAudit.Services.DiagnosticLogService', $true)
        $logger = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($loggerType)
        $loggerType.GetField('_settingsService', $flags).SetValue($logger, $settingsService)
        # Missing collector deliberately fails before any real event-log or network access.
        $scanScheduler = [LocalSecurityAudit.Services.AuditSchedulerService]::new($null, $null, $storage, $settingsService, $logger)
        $type.GetField('_schedulerService', $flags).SetValue($model, $scanScheduler)
        try {
            $model.RunFastScanCommand.ExecuteAsync($null).GetAwaiter().GetResult()
            $model.LoadDataCommand.ExecutionTask.GetAwaiter().GetResult()
            Assert-True ($model.SelectedAuditLabel -eq [LocalSecurityAudit.Services.AppText]::Get('Latest audit') -and $model.TotalFindings -eq 4 -and $model.RecentDays[6].IsSelected) 'A failed new scan did not restore the shared overview and latest audit date.'
        }
        finally { $scanScheduler.Dispose() }
        $command = $connection.CreateCommand()
        $command.CommandText = 'DROP TABLE AuditResults'
        $null = $command.ExecuteNonQuery()
        $command.Dispose()
        $model.SelectDayCommand.Execute($yesterday)
        $model.LoadDataCommand.ExecutionTask.GetAwaiter().GetResult()
        Assert-True (-not $model.HasAuditData -and $model.IsStatusVisible -and -not $model.IsDateLoading -and $model.SelectedAuditLabel -eq [LocalSecurityAudit.Services.AppText]::Format('Audit on {0:d}', $yesterday.Date)) 'A failed day selection retained another day or stayed loading.'
    }
}

Write-Output "$script:passed passed; $script:failed failed. No app launch, network requests or user-data writes."
if ($script:failed -gt 0) { exit 1 }
