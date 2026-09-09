# Synthetic storage, model precedence, restart and settings regression. No log collection or AI calls.
param([Parameter(Mandatory)][string]$AssemblyPath)
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$directory = Split-Path -Parent $assembly.Location
$null = [Reflection.Assembly]::LoadFrom((Join-Path $directory 'Microsoft.Data.Sqlite.dll'))
$null = [Reflection.Assembly]::LoadFrom((Join-Path $directory 'SQLitePCLRaw.batteries_v2.dll'))
$native = Join-Path $directory 'e_sqlite3.dll'
if (-not (Test-Path -LiteralPath $native)) { $native = Join-Path $directory 'runtimes/win-x64/native/e_sqlite3.dll' }
$null = [Runtime.InteropServices.NativeLibrary]::Load($native)
[SQLitePCL.Batteries_V2]::Init()
$flags = [Reflection.BindingFlags]'NonPublic,Instance,Static'
$root = Join-Path ([IO.Path]::GetTempPath()) "lsa-incremental-$([guid]::NewGuid())"
$null = New-Item -ItemType Directory -Path $root
$script:passed = 0
$script:failed = 0
function Assert-True([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
function Test-Case([string]$name, [scriptblock]$action) {
    try { $null = & $action; $script:passed++; "PASS $name" }
    catch { $script:failed++; "FAIL $name`: $($_.Exception.GetBaseException().Message)"; $_.ScriptStackTrace }
}
function New-Result([datetime]$start, [datetime]$end, [string]$model = 'gpt-5.6-luna', [string]$mode = 'extended', [string]$coverage = 'limited') {
    $channels = foreach ($log in 'Security','System','Application','Setup','ForwardedEvents') {
        $skip = $log -eq 'Security' -and $mode -ne 'full'
        @{LogName=$log; Status=$(if($skip){'skipped'}elseif($coverage -eq 'partial' -and $log -eq 'Setup'){'unavailable'}else{'complete'});
          Reason=$(if($skip){'not_requested'}elseif($coverage -eq 'partial' -and $log -eq 'Setup'){'access_denied'}else{'none'}); EventCount=0}
    }
    $raw = @{Timestamp=$end.AddSeconds(1).ToString('O'); HealthScore=100; Findings=@(); Metadata=@{
        SchemaVersion=2; Mode=$mode; CoverageStatus=$coverage; Channels=@($channels); ScanStart=$start.ToString('O'); ScanEnd=$end.ToString('O');
        AnalysisModels=@($model); AnalysisCompleted=$true; AnalyzedEventCount=1; EventCount=1; FilteredEventCount=0
    }} | ConvertTo-Json -Depth 8 -Compress
    return [Text.Json.JsonSerializer]::Deserialize($raw, [LocalSecurityAudit.Models.AuditResult])
}
function Add-Issue($result, [string]$account = 'A', [string]$record = '1', [string]$model = 'gpt-5.6-luna', [string]$log = 'System') {
    $issue = [LocalSecurityAudit.Models.AuditIssue]::new()
    $issue.Key='restart_pattern'; $issue.Affected=$account; $issue.UserName=$account; $issue.Source='SyntheticProvider'; $issue.LogName=$log
    $issue.Title="Finding $account $model"; $issue.Description='Synthetic description'; $issue.RootCause='Unknown cause'; $issue.Recommendation='Review'
    $issue.TitleZh='Synthetic title zh'; $issue.DescriptionZh='Synthetic description zh'; $issue.RootCauseZh='Unknown cause zh'; $issue.RecommendationZh='Review zh'
    $issue.Category='System'; $issue.Severity='Medium'; $issue.Confidence='High'; $issue.AnalysisModel=$model
    $issue.EventRecordId=$record; $issue.EventId='41'; $issue.EventRef="${log}:$record"; $issue.EventTimestamp=$result.Timestamp.AddHours(-1).ToString('O')
    $issue.FirstSeenUtc=$issue.LastSeenUtc=$result.Timestamp.AddHours(-1); $issue.DetectedAt=$result.Timestamp
    $issue.EventTimes[$issue.EventRef]=$issue.FirstSeenUtc; $issue.RelatedEventRefs.Add($issue.EventRef); $issue.SupportingEventCount=1
    $result.Findings.Add($issue)
    return $issue
}
$end = [datetime]::UtcNow.AddMinutes(-10)
Test-Case 'Restart after partial failure resumes the last eligible scan without losing the gap' {
    $data = Join-Path $root 'restart'
    $storage = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended',$data).GetAwaiter().GetResult()
    $good = New-Result $end.AddHours(-13) $end.AddHours(-12)
    $storage.SaveAuditResultAsync($good).GetAwaiter().GetResult()
    $storage.SaveAuditResultAsync((New-Result $end.AddHours(-12) $end 'gpt-6-astra' 'extended' 'partial')).GetAwaiter().GetResult()
    $restarted = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended',$data).GetAwaiter().GetResult()
    $checkpoint=$restarted.GetScanCheckpointAsync('extended').GetAwaiter().GetResult()
    Assert-True ($checkpoint.Item1 -eq $end.AddHours(-12) -and $checkpoint.Item2 -eq 0) 'Partial result advanced the cursor or model rank.'
}
Test-Case 'Model rank keeps higher analysis across downgrades and empty-finding responses' {
    $records=[Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new()
    $records.Add((New-Result $end.AddDays(-1) $end.AddHours(-2) 'gpt-5.6-sol'))
    $records.Add((New-Result $end.AddHours(-2) $end 'gpt-5.6-luna'))
    $checkpoint=[LocalSecurityAudit.Services.AuditHistory]::Checkpoint($records,'extended')
    Assert-True ($checkpoint.Item1 -eq $end -and $checkpoint.Item2 -eq 2) 'A downgrade erased the stronger model or empty findings lost provenance.'
    Assert-True ([LocalSecurityAudit.Services.AuditHistory]::Checkpoint($records,'full').Item1 -eq [datetime]::MinValue) 'Skipped Security advanced full scope.'
}
Test-Case 'History cleanup preserves scan end and the highest completed model' {
    $storage=[LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended',(Join-Path $root 'retention')).GetAwaiter().GetResult()
    $old = New-Result $end.AddDays(-91) $end.AddDays(-90) 'gpt-6-astra'
    $storage.SaveAuditResultAsync($old).GetAwaiter().GetResult()
    $storage.CleanupOldDataAsync(1).GetAwaiter().GetResult()
    Assert-True ($storage.GetAuditRecordCountAsync().GetAwaiter().GetResult() -eq 0) 'Old audit was retained instead of its checkpoint.'
    $checkpoint=$storage.GetScanCheckpointAsync('extended').GetAwaiter().GetResult()
    Assert-True ($checkpoint.Item1 -eq $end.AddDays(-90) -and $checkpoint.Item2 -eq 3) 'Cleanup lost progress.'
}
Test-Case 'Stronger shared results replace covered lower-model findings and retain Security and other subjects' {
    $low=New-Result $end.AddDays(-1) $end 'gpt-5.6-luna' 'full' 'complete'
    $null=Add-Issue $low 'A' '1'; $null=Add-Issue $low 'B' '2'; $null=Add-Issue $low 'security' '3' 'gpt-5.6-luna' 'Security'
    $high=New-Result $end.AddDays(-1) $end 'gpt-6-astra' 'assistant'
    $null=Add-Issue $high 'A' '1' 'gpt-6-astra'
    $rows=[Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new(); $rows.Add($low); $rows.Add($high)
    $merged=[LocalSecurityAudit.Services.AuditHistory]::EffectiveFindings($rows)
    Assert-True ($merged.Count -eq 2 -and @($merged | Where-Object AnalysisModel -eq 'gpt-6-astra').Count -eq 1 -and @($merged | Where-Object LogName -eq 'Security').Count -eq 1) 'Cross-mode replacement or coverage isolation failed.'
    $high.Metadata['CoverageStatus']=[Text.Json.JsonSerializer]::SerializeToElement('partial',[string])
    Assert-True ([LocalSecurityAudit.Services.AuditHistory]::EffectiveFindings($rows).Count -eq 3) 'Partial analysis cleared unassessed old findings.'
}
Test-Case 'Same pattern for two accounts stays separate and overlapping evidence is counted once' {
    $first=New-Result $end.AddDays(-1) $end
    $null=Add-Issue $first 'A' '1'; $null=Add-Issue $first 'B' '2'
    $again=[Text.Json.JsonSerializer]::Deserialize([Text.Json.JsonSerializer]::Serialize($first,[LocalSecurityAudit.Models.AuditResult]),[LocalSecurityAudit.Models.AuditResult])
    $rows=[Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new(); $rows.Add($first); $rows.Add($again)
    $merged=[LocalSecurityAudit.Services.AuditHistory]::EffectiveFindings($rows)
    Assert-True ($merged.Count -eq 2 -and $merged[0].Occurrences -eq 1 -and $merged[1].EventTimes.Count -eq 1) 'Subject separation or event deduplication failed.'
    $type=$assembly.GetType('LocalSecurityAudit.Services.AiAnalysisService')
    $native=$type.GetMethod('MergeDuplicateIssues',$flags).Invoke($null,[object[]](,$first.Findings))
    Assert-True ($native.Count -eq 2) 'Batch merger mixed different accounts.'
}
Test-Case 'Incomplete weekly baseline does not promote its model or skip a missing daily batch' {
    $rows=[Collections.Generic.List[LocalSecurityAudit.Models.AuditResult]]::new()
    foreach($day in 0,2) {
        $part=New-Result $end.AddDays(-7+$day) $end.AddDays(-6+$day) 'gpt-6-astra' 'assistant'
        $part.Metadata['BaselineStart']=[Text.Json.JsonSerializer]::SerializeToElement($end.AddDays(-7).ToString('O'),[string])
        $part.Metadata['BaselineEnd']=[Text.Json.JsonSerializer]::SerializeToElement($end.ToString('O'),[string]); $rows.Add($part)
    }
    $checkpoint=[LocalSecurityAudit.Services.AuditHistory]::Checkpoint($rows,'extended')
    Assert-True ($checkpoint.Item1 -eq $end.AddDays(-6) -and $checkpoint.Item2 -eq -1) 'An incomplete baseline advanced beyond its gap.'
    foreach($day in 1,3,4,5,6) {
        $part=New-Result $end.AddDays(-7+$day) $end.AddDays(-6+$day) 'gpt-6-astra' 'assistant'
        $part.Metadata['BaselineStart']=$rows[0].Metadata['BaselineStart']; $part.Metadata['BaselineEnd']=$rows[0].Metadata['BaselineEnd']; $rows.Add($part)
    }
    $checkpoint=[LocalSecurityAudit.Services.AuditHistory]::Checkpoint($rows,'extended')
    Assert-True ($checkpoint.Item1 -eq $end -and $checkpoint.Item2 -eq 3) 'Completed baseline did not promote its model.'
}
Test-Case 'Policy write failure is reported, while unchanged read-only policy permits language save' {
    $type=$assembly.GetType('LocalSecurityAudit.Services.SettingsService')
    $service=[Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
    $policy=Join-Path $root 'policy.md'; $config=Join-Path $root 'synthetic-settings.json'
    $type.GetField('_settingsPath',$flags).SetValue($service,$config); $type.GetField('_agentInstructionsPath',$flags).SetValue($service,$policy)
    $settings=[LocalSecurityAudit.Models.AppSettings]::new(); $settings.AgentInstructions='Original synthetic policy'; $settings.Language='en-US'
    $service.Save($settings); [IO.File]::SetAttributes($policy,[IO.FileAttributes]::ReadOnly)
    try {
        $settings.Language='zh-CN'; $service.Save($settings)
        $settings.AgentInstructions='New synthetic policy'; $failed=$false
        try { $service.Save($settings) } catch { $failed=$true }
        Assert-True $failed 'Changed policy reported success even though it could not be persisted.'
        Assert-True ((Get-Content -LiteralPath $config -Raw | ConvertFrom-Json).AgentInstructions -eq 'Original synthetic policy') 'Failed save changed persistent settings.'
    } finally { [IO.File]::SetAttributes($policy,[IO.FileAttributes]::Normal) }
}
"$script:passed passed; $script:failed failed. Synthetic fixtures: $root"
if($script:failed){exit 1}
