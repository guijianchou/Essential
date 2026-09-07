# Run after an x64 build. Uses the built assembly, synthetic events and memory
# streams and an in-memory database; does not load user settings, open event logs
# or call an AI endpoint.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\bin\x64\Debug\net8.0-windows10.0.19041.0\LocalSecurityAudit.dll"
)

$ErrorActionPreference = 'Stop'
$assembly = [System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$serviceType = $assembly.GetType('LocalSecurityAudit.Services.AiAnalysisService', $true)
$privateFlags = [System.Reflection.BindingFlags]'NonPublic,Instance,Static'
$settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
$settingsService = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
$settings = [LocalSecurityAudit.Models.AppSettings]::new()
$settings.DiagnosticLoggingEnabled = $false
$settingsType.GetProperty('Current').SetValue($settingsService, $settings)
$loggerType = $assembly.GetType('LocalSecurityAudit.Services.DiagnosticLogService', $true)
$logger = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($loggerType)
$loggerType.GetField('_settingsService', $privateFlags).SetValue($logger, $settingsService)
$analysis = [Activator]::CreateInstance($serviceType, [object[]]@($settingsService, $logger))
$target = [LocalSecurityAudit.Models.AiTargetSettings]::new()
$target.BaseUrl = 'https://unused.invalid'
$script:passed = 0
$script:failed = 0

function Invoke-AnalysisMethod([string]$Name, [object[]]$Arguments) {
    $method = $serviceType.GetMethod($Name, $privateFlags)
    if ($null -eq $method) { throw "Method not found: $Name" }
    return ,$method.Invoke($analysis, $Arguments)
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Throws([scriptblock]$Action, [type]$ExceptionType) {
    try { $null = & $Action }
    catch {
        $errorObject = $_.Exception
        while ($errorObject) {
            if ($ExceptionType.IsInstanceOfType($errorObject)) { return }
            $errorObject = $errorObject.InnerException
        }
        throw
    }
    throw "Expected $($ExceptionType.Name) but the operation succeeded."
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

function New-TestEvent {
    $event = [LocalSecurityAudit.Models.SecurityEvent]::new()
    $event.EventId = 4625
    $event.EventRecordId = 101
    $event.Timestamp = [datetime]::new(2026, 9, 6, 1, 0, 0, [DateTimeKind]::Utc)
    $event.LogName = 'Security'
    $event.Source = 'SyntheticProvider'
    $event.Severity = 'Error'
    $event.Description = ('A' * 240) + "`nOriginal event tail"
    $event.AdditionalData = "TargetUserName=test-account`nIpAddress=192.0.2.10"
    return $event
}

function Get-BatchKey($Events, [string]$Prompt = 'Synthetic policy') {
    return Invoke-AnalysisMethod 'CalculateBatchCacheKey' @($Events, $Prompt, $target)
}

function New-BilingualFinding([string]$Key = 'legacy_0') {
    $payload = '{"issues":[{"title":"Failed logon","description":"Logon failed for test-account.","rootCause":"The password was incorrect; intent is unknown.","recommendation":"Confirm the source 192.0.2.10 with the account owner.","titleZh":"\u767b\u5f55\u5931\u8d25","descriptionZh":"test-account \u767b\u5f55\u5931\u8d25\u3002","rootCauseZh":"\u5bc6\u7801\u9519\u8bef\uff0c\u610f\u56fe\u672a\u77e5\u3002","recommendationZh":"\u4e0e\u8d26\u53f7\u6240\u6709\u8005\u786e\u8ba4\u6765\u6e90 192.0.2.10\u3002"}]}'
    $finding = (Invoke-AnalysisMethod 'ParseIssuesPayload' @($payload))[0]
    $finding.Key = $Key
    return $finding
}

function New-LegacyGroups {
    $groups = [System.Collections.Generic.List[System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]]::new()
    foreach ($index in 0, 1) {
        $group = [System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
        foreach ($copy in 0, 1) {
            $finding = [LocalSecurityAudit.Models.AuditIssue]::new()
            $finding.Key = "stored-$index-$copy"
            $finding.Title = "Stored title $index"
            $finding.EventRecordId = "record-$copy"
            $finding.EventDescription = "original`nevidence-$copy"
            $finding.Severity = 'High'
            $group.Add($finding)
        }
        $groups.Add($group)
    }
    return ,$groups
}

Test-Case 'Both analysis languages survive parsing, cache cloning, persistence and display switching' {
    $finding = New-BilingualFinding
    $finding.EventDescription = "original`nevidence"
    $copy = Invoke-AnalysisMethod 'CloneIssue' @($finding)
    $json = [System.Text.Json.JsonSerializer]::Serialize($copy, $copy.GetType(), [System.Text.Json.JsonSerializerOptions]::new())
    $restored = [System.Text.Json.JsonSerializer]::Deserialize($json, $copy.GetType(), [System.Text.Json.JsonSerializerOptions]::new())
    Assert-True $restored.HasBilingualText 'The persisted finding lost a language.'
    Assert-True ($restored.TitleZh -eq $finding.TitleZh) 'The Chinese title changed during cloning or persistence.'
    $previousLanguage = [LocalSecurityAudit.Services.AppText]::Current.Language
    try {
        foreach ($language in 'zh-CN', 'en') {
            [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($language)
            $display = [LocalSecurityAudit.Services.IssueCategorizer]::CategorizeIssue($restored)
            foreach ($field in 'Title', 'Description', 'RootCause', 'Recommendation') {
                $storedField = if ($language -eq 'zh-CN') { $field + 'Zh' } else { $field }
                Assert-True ($display.$field -eq $finding.$storedField) "Incorrect $field in $language."
            }
            Assert-True (-not $display.NeedsTranslation -and $display.EventDescription -eq $finding.EventDescription) 'Language switching altered source evidence or marked complete text as legacy.'
        }
    }
    finally { [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($previousLanguage) }
}

Test-Case 'Incomplete bilingual findings retain legacy text and remain eligible for translation' {
    $previousLanguage = [LocalSecurityAudit.Services.AppText]::Current.Language
    try {
        [LocalSecurityAudit.Services.AppText]::Current.SetLanguage('zh-CN')
        foreach ($field in 'Title', 'Description', 'RootCause', 'Recommendation', 'TitleZh', 'DescriptionZh', 'RootCauseZh', 'RecommendationZh') {
            $finding = New-BilingualFinding
            $finding.$field = ' '
            Assert-True (-not $finding.HasBilingualText) "Missing $field was accepted as complete."
            $display = [LocalSecurityAudit.Services.IssueCategorizer]::CategorizeIssue($finding)
            Assert-True ($display.NeedsTranslation -and $display.Description -eq $finding.Description) 'Incomplete translation was shown instead of the stored analysis.'
        }
    }
    finally { [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($previousLanguage) }
}

Test-Case 'Historical translations match keys regardless of response order and preserve evidence' {
    $groups = New-LegacyGroups
    $translated = [System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
    $translated.Add((New-BilingualFinding 'legacy_8'))
    $translated.Add((New-BilingualFinding 'legacy_3'))
    $translated[0].Title = 'Translated second group'
    $translated[1].Title = 'Translated first group'
    $null = Invoke-AnalysisMethod 'ApplyLegacyTranslations' @($groups, $translated, [int[]]@(3, 8))
    foreach ($index in 0, 1) {
        foreach ($copy in 0, 1) {
            $finding = $groups[$index][$copy]
            Assert-True ($finding.HasBilingualText -and $finding.Title -eq $translated[1 - $index].Title) 'Translation was not applied to every duplicate of the matching key.'
            Assert-True ($finding.Key -eq "stored-$index-$copy" -and $finding.Severity -eq 'High' -and $finding.EventRecordId -eq "record-$copy" -and $finding.EventDescription -eq "original`nevidence-$copy") 'Translation changed finding identity or event evidence.'
        }
    }
}

foreach ($invalid in 'missing', 'duplicate', 'unknown', 'incomplete', 'extra') {
    Test-Case "Historical translation rejects $invalid results before changing stored findings" {
        $groups = New-LegacyGroups
        $translated = [System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
        $translated.Add((New-BilingualFinding 'legacy_3'))
        $translated.Add((New-BilingualFinding 'legacy_8'))
        switch ($invalid) {
            'missing' { $translated.RemoveAt(1) }
            'duplicate' { $translated[1].Key = 'legacy_3' }
            'unknown' { $translated[1].Key = 'legacy_99' }
            'incomplete' { $translated[1].RootCauseZh = '' }
            'extra' { $translated.Add((New-BilingualFinding 'legacy_99')) }
        }
        Assert-Throws { Invoke-AnalysisMethod 'ApplyLegacyTranslations' @($groups, $translated, [int[]]@(3, 8)) } ([System.Text.Json.JsonException])
        Assert-True ($groups[0][0].Title -eq 'Stored title 0' -and $groups[1][1].TitleZh -eq '') 'Rejected output partially overwrote history.'
    }
}

Test-Case 'Historical database upgrade preserves non-text JSON and refuses stale or incomplete writes' {
    $assemblyDirectory = Split-Path -Parent $assembly.Location
    $null = [System.Reflection.Assembly]::LoadFrom((Join-Path $assemblyDirectory 'Microsoft.Data.Sqlite.dll'))
    $null = [System.Reflection.Assembly]::LoadFrom((Join-Path $assemblyDirectory 'SQLitePCLRaw.batteries_v2.dll'))
    $null = [System.Runtime.InteropServices.NativeLibrary]::Load((Join-Path $assemblyDirectory 'runtimes/win-x64/native/e_sqlite3.dll'))
    [SQLitePCL.Batteries_V2]::Init()
    $connectionString = "Data Source=analysis-regression-$([guid]::NewGuid());Mode=Memory;Cache=Shared;Pooling=False"
    $keeper = [Microsoft.Data.Sqlite.SqliteConnection]::new($connectionString)
    try {
        $keeper.Open()
        $storageType = $assembly.GetType('LocalSecurityAudit.Services.DataStorageService', $true)
        $storage = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($storageType)
        $storageType.GetField('_connectionString', $privateFlags).SetValue($storage, $connectionString)
        $storageType.GetMethod('InitializeDatabaseAsync', $privateFlags).Invoke($storage, @()).GetAwaiter().GetResult()
        $original = '[{"Key":"stored-key","Title":"Stored title","Description":"Stored description","RootCause":"Stored cause","Recommendation":"Stored action","EventRecordId":"101","EventDescription":"original\nevidence","Severity":"High","DetectedAt":"2026-09-06T01:00:00Z","UnknownLegacyField":{"value":42}}]'
        $insert = $keeper.CreateCommand()
        $insert.CommandText = 'INSERT INTO AuditResults (Timestamp, HealthScore, FindingsJson, MetadataJson) VALUES (''2026-09-06 01:00:00'', 73, @findings, ''{"EventCount":4}'')'
        $null = $insert.Parameters.AddWithValue('@findings', $original)
        $null = $insert.ExecuteNonQuery()
        $insert.Dispose()
        $records = $storage.GetLegacyFindingsAsync().GetAwaiter().GetResult()
        Assert-True ($records.Count -eq 1 -and $records[0].Item2 -eq $original) 'Legacy lookup did not retain the original JSON.'
        $recordId = $records[0].Item1
        $findings = $records[0].Item3
        Assert-True (-not $storage.UpdateTranslatedFindingsAsync($recordId, $original, $findings).GetAwaiter().GetResult()) 'Incomplete translation was written.'
        $groups = [System.Collections.Generic.List[System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]]::new()
        $groups.Add($findings)
        $translated = [System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
        $translated.Add((New-BilingualFinding))
        $null = Invoke-AnalysisMethod 'ApplyLegacyTranslations' @($groups, $translated, [int[]]@(0))
        $findings[0].Severity = 'Low'
        $findings[0].EventDescription = 'Must never overwrite source evidence'
        Assert-True ($storage.UpdateTranslatedFindingsAsync($recordId, $original, $findings).GetAwaiter().GetResult()) 'Complete translation was not written.'
        Assert-True (-not $storage.UpdateTranslatedFindingsAsync($recordId, $original, $findings).GetAwaiter().GetResult()) 'A stale snapshot overwrote a newer row.'
        $select = $keeper.CreateCommand()
        $select.CommandText = 'SELECT Timestamp, HealthScore, FindingsJson, MetadataJson FROM AuditResults WHERE Id=@id'
        $null = $select.Parameters.AddWithValue('@id', $recordId)
        $reader = $select.ExecuteReader()
        try {
            Assert-True ($reader.Read()) 'The historical row disappeared.'
            Assert-True ($reader.GetString(0) -eq '2026-09-06 01:00:00' -and $reader.GetInt32(1) -eq 73 -and $reader.GetString(3) -eq '{"EventCount":4}') 'Upgrade changed timestamp, health score or metadata.'
            $before = ($original | ConvertFrom-Json -AsHashtable -NoEnumerate)[0]
            $after = ($reader.GetString(2) | ConvertFrom-Json -AsHashtable -NoEnumerate)[0]
            $textFields = @('Title', 'Description', 'RootCause', 'Recommendation', 'TitleZh', 'DescriptionZh', 'RootCauseZh', 'RecommendationZh')
            foreach ($field in $textFields) {
                Assert-True ($after[$field] -eq $translated[0].$field) "Stored $field did not match the translation."
                $null = $before.Remove($field)
                $null = $after.Remove($field)
            }
            Assert-True (($before | ConvertTo-Json -Compress -Depth 8) -eq ($after | ConvertTo-Json -Compress -Depth 8)) 'Upgrade added, dropped or changed non-text JSON fields.'
        }
        finally { $reader.Dispose(); $select.Dispose() }
        Assert-True ($storage.GetLegacyFindingsAsync().GetAwaiter().GetResult().Count -eq 0) 'Already bilingual history was queued for translation again.'
    }
    finally { $keeper.Dispose() }
}

foreach ($field in @('Timestamp', 'EventRecordId', 'LogName', 'Description', 'AdditionalData')) {
    Test-Case "Cache distinguishes changed $field" {
        $original = New-TestEvent
        $changed = New-TestEvent
        switch ($field) {
            'Timestamp' { $changed.Timestamp = $changed.Timestamp.AddHours(1) }
            'EventRecordId' { $changed.EventRecordId++ }
            'LogName' { $changed.LogName = 'System' }
            'Description' { $changed.Description += ' changed beyond character 200' }
            'AdditionalData' { $changed.AdditionalData += ' changed' }
        }
        $before = Get-BatchKey ([LocalSecurityAudit.Models.SecurityEvent[]]@($original))
        $after = Get-BatchKey ([LocalSecurityAudit.Models.SecurityEvent[]]@($changed))
        Assert-True ($before -ne $after) 'Different evidence reused the same cache key.'
    }
}

Test-Case 'Cache is stable, order-sensitive and policy-sensitive' {
    $first = New-TestEvent
    $second = New-TestEvent
    $second.EventRecordId++
    $events = [LocalSecurityAudit.Models.SecurityEvent[]]@($first, $second)
    $key = Get-BatchKey $events
    Assert-True ($key -eq (Get-BatchKey $events)) 'Same batch did not reuse its key.'
    Assert-True ($key -ne (Get-BatchKey ([LocalSecurityAudit.Models.SecurityEvent[]]@($second, $first)))) 'Reordered batch reused local references.'
    Assert-True ($key -ne (Get-BatchKey $events 'Changed policy')) 'Policy change did not invalidate the cache.'
    $target.Effort = 'high'
    try { Assert-True ($key -ne (Get-BatchKey $events)) 'Effort change did not invalidate the cache.' }
    finally { $target.Effort = 'medium' }
}

Test-Case 'Cached findings are cloned before global reference mapping' {
    $events = [System.Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
    $events.Add((New-TestEvent))
    $issues = Invoke-AnalysisMethod 'ParseIssuesPayload' @('{"issues":[{"eventRef":"event-0","title":"Synthetic finding","relatedEventRefs":["event-0"]}]}')
    $issues = Invoke-AnalysisMethod 'NormalizeIssues' @($issues, $events)
    $cachedType = $serviceType.GetNestedType('CachedBatchAnalysis', 'NonPublic')
    $cached = [Activator]::CreateInstance($cachedType, $true)
    $cachedType.GetProperty('Issues').SetValue($cached, $issues)
    $cache = $serviceType.GetField('_analysisCache', $privateFlags).GetValue($analysis)
    $cache.Set((Get-BatchKey $events), $cached)
    $routeType = $serviceType.GetNestedType('AnalysisRouteState', 'NonPublic')
    $routeState = [Activator]::CreateInstance($routeType, $true)
    $task = Invoke-AnalysisMethod 'AnalyzeBatchWithCacheAsync' @(
        [LocalSecurityAudit.Models.AiTargetSettings[]]@($target), $events, 'Synthetic policy', 20000,
        $routeState, $null, [System.Threading.CancellationToken]::None
    )
    $result = $task.GetAwaiter().GetResult()
    $mapped = Invoke-AnalysisMethod 'RemapIssuesToIndexes' @($result, [int[]]@(50))
    Assert-True ($mapped[0].EventRef -eq 'event-50') 'Global reference was not remapped.'
    $result[0].RelatedEventRefs.Clear()
    Assert-True ($issues[0].RelatedEventRefs.Count -eq 1) 'A cache hit mutated stored evidence.'
    Assert-True ($issues[0].EventRef -eq 'event-0') 'Global reference leaked into the cache.'
}

Test-Case 'Same-provider findings preserve latest evidence, both event references and original text' {
    $allIssues = [System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
    foreach ($index in 0, 1) {
        $events = [System.Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
        $event = New-TestEvent
        $event.Timestamp = $event.Timestamp.AddMinutes($index)
        $event.EventRecordId += $index
        $event.Description += "`nSample $index"
        $events.Add($event)
        $issues = Invoke-AnalysisMethod 'ParseIssuesPayload' @('{"issues":[{"key":"test_failure","eventRef":"event-0","title":"Synthetic failure","description":"Test description","rootCause":"Test cause","recommendation":"Test action","relatedEventRefs":["event-0"]}]}')
        $issues = Invoke-AnalysisMethod 'NormalizeIssues' @($issues, $events)
        $issues = Invoke-AnalysisMethod 'RemapIssuesToIndexes' @($issues, [int[]]@($index * 50))
        $allIssues.AddRange($issues)
    }
    $merged = Invoke-AnalysisMethod 'MergeDuplicateIssues' (,$allIssues)
    Assert-True ($merged.Count -eq 1) 'One pattern was not merged.'
    $finding = $merged[0]
    Assert-True ($finding.EventRecordId -eq '102' -and $finding.Source -eq 'SyntheticProvider' -and $finding.EventDescription.EndsWith('Sample 1')) 'Latest evidence was lost.'
    Assert-True ($finding.SupportingEventCount -eq 2 -and $finding.RelatedEventRefs.Contains('event-50')) 'Cross-batch evidence references collided.'
    Assert-True (($finding.LastSeenUtc - $finding.FirstSeenUtc).TotalMinutes -eq 1) 'Observation range was lost.'
    Assert-True ($finding.EventDescription.Contains("`n") -and $finding.EventAdditionalData.Contains("`n")) 'Original formatting was lost.'
    $json = [System.Text.Json.JsonSerializer]::Serialize($finding, $finding.GetType(), [System.Text.Json.JsonSerializerOptions]::new())
    $restored = [System.Text.Json.JsonSerializer]::Deserialize($json, $finding.GetType(), [System.Text.Json.JsonSerializerOptions]::new())
    $display = [LocalSecurityAudit.Services.IssueCategorizer]::CategorizeIssue($restored)
    Assert-True ($display.EventDescription -eq $finding.EventDescription -and $display.Recommendation -eq 'Test action') 'Evidence or action was lost during persistence or presentation.'
}

Test-Case 'Evidence text stays bounded and explicitly marks truncation' {
    $events = [System.Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
    $event = New-TestEvent
    $event.Description = 'X' * 10000
    $event.AdditionalData = 'Y' * 10000
    $events.Add($event)
    $issues = Invoke-AnalysisMethod 'ParseIssuesPayload' @('{"issues":[{"eventRef":"event-0","title":"Large event"}]}')
    $issues = Invoke-AnalysisMethod 'NormalizeIssues' @($issues, $events)
    Assert-True ($issues[0].EventDescription.Length -eq 4096 -and $issues[0].EventDescription.Contains('[truncated]')) 'Description truncation was not explicit.'
    Assert-True ($issues[0].EventAdditionalData.Length -eq 4096) 'Additional data was not bounded.'
}

Test-Case 'Event XML field names determine account and IP regardless of order' {
    $event = New-TestEvent
    $xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="ProcessName">test.exe</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="SubjectUserName">service-account</Data><Data Name="TargetUserName">target-account</Data></EventData></Event>'
    $parser = $assembly.GetType('LocalSecurityAudit.Helpers.EventLogParser', $true)
    $parser.GetMethod('ApplyEventData', $privateFlags).Invoke($null, @($event, $xml))
    Assert-True ($event.UserName -eq 'target-account' -and $event.IpAddress -eq '192.0.2.10') 'Named source fields were misread.'
    Assert-True ($event.AdditionalData.Contains('test.exe')) 'Raw event fields were not captured.'
}

foreach ($payload in @('', 'not JSON', '{}', '{"issues":', '{"issues":{}}', '{"issues":[false]}')) {
    Test-Case "Invalid findings are rejected: $payload" {
        Assert-Throws { Invoke-AnalysisMethod 'ParseIssuesPayload' @($payload) } ([System.Text.Json.JsonException])
    }
}

Test-Case 'Valid empty results and legacy JSON forms remain accepted' {
    foreach ($payload in @('{"issues":[]}', '[]', ('```json' + "`n" + '{"issues":[]}' + "`n" + '```'))) {
        $issues = Invoke-AnalysisMethod 'ParseIssuesPayload' @($payload)
        Assert-True ($issues.Count -eq 0) 'Empty result was rejected.'
    }
}

if (-not ('AnalysisRegressionStream' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

public sealed class AnalysisRegressionStream : Stream
{
    private readonly MemoryStream source;
    public AnalysisRegressionStream(byte[] data) { source = new MemoryStream(data); }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => source.Length;
    public override long Position { get => source.Position; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => source.Read(buffer, offset, count);
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
    {
        if (source.Position < source.Length) return source.Read(buffer.Span);
        await Task.Delay(Timeout.Infinite, token);
        return 0;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
        => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) source.Dispose(); base.Dispose(disposing); }
}
'@
}

function Read-TestStream([object[]]$Events, [string]$Mode = 'responses', [switch]$HoldOpen) {
    $sse = ($Events | ForEach-Object { 'data: ' + ($_ | ConvertTo-Json -Compress -Depth 8) + "`n`n" }) -join ''
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($sse)
    $stream = if ($HoldOpen) { [AnalysisRegressionStream]::new($bytes) } else { [System.IO.MemoryStream]::new($bytes) }
    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
    $response.Content = [System.Net.Http.StreamContent]::new($stream)
    $response.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('text/event-stream')
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(3))
    try {
        $task = Invoke-AnalysisMethod 'ReadAnalysisResponseAsync' @($response, $Mode, 'Synthetic', $null, $timeout.Token)
        return $task.GetAwaiter().GetResult()
    }
    finally { $response.Dispose(); $timeout.Dispose() }
}

Test-Case 'Complete output_text.done returns without waiting for response.completed or socket close' {
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Read-TestStream @(
        @{type='response.output_text.delta'; delta='{"issues":[]}'},
        @{type='response.output_text.done'; text='{"issues":[]}'}
    ) -HoldOpen
    Assert-True ($result.Text -eq '{"issues":[]}' -and $timer.Elapsed.TotalSeconds -lt 2) 'Complete text did not finish promptly.'
}

Test-Case 'Complete JSON at EOF remains accepted without a terminal marker' {
    $result = Read-TestStream @(@{type='response.output_text.delta'; delta='{"issues":[]}'})
    Assert-True ($result.Text -eq '{"issues":[]}') 'Valid EOF result was rejected.'
}

Test-Case 'Truncated JSON stays a failure even when the stream reports completion' {
    Assert-Throws {
        Read-TestStream @(@{type='response.output_text.done'; text='{"issues":['}, @{type='response.completed'})
    } ([System.Net.Http.HttpRequestException])
}

Test-Case 'Incomplete response status is rejected' {
    Assert-Throws {
        Read-TestStream @(@{type='response.output_text.delta'; delta='{"issues":[]}'}, @{type='response.incomplete'})
    } ([System.Net.Http.HttpRequestException])
}

Test-Case 'Chat stop succeeds and token-limit termination fails' {
    $result = Read-TestStream @(@{choices=@(@{delta=@{content='{"issues":[]}'}; finish_reason='stop'})}) -Mode 'chat'
    Assert-True ($result.Text -eq '{"issues":[]}') 'Complete chat result was rejected.'
    Assert-Throws {
        Read-TestStream @(@{choices=@(@{delta=@{content='{"issues":[]}'}; finish_reason='length'})}) -Mode 'chat'
    } ([System.Net.Http.HttpRequestException])
}

Test-Case 'Filtering retains distinct evidence and accounts for every event' {
    $events = [System.Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
    foreach ($severity in 'Error', 'Critical', 'Warning', 'Information', 'Unknown') {
        foreach ($index in 0..8) {
            $event = New-TestEvent
            $event.Severity = $severity
            $event.EventRecordId = $events.Count + 1
            $event.Description = "Distinct $severity evidence $index"
            $events.Add($event)
        }
    }
    $arguments = [object[]]@($events, $null)
    $kept = $serviceType.GetMethod('ApplySmartFiltering', $privateFlags).Invoke($analysis, $arguments)
    Assert-True ($kept.Count -eq $events.Count -and $arguments[1].Count -eq 0) 'Distinct low-severity evidence was sampled away.'
    foreach ($index in 1..10) {
        $event = New-TestEvent
        $event.Severity = 'Information'
        $event.Timestamp = $event.Timestamp.AddSeconds($index)
        $events.Add($event)
    }
    $arguments = [object[]]@($events, $null)
    $kept = $serviceType.GetMethod('ApplySmartFiltering', $privateFlags).Invoke($analysis, $arguments)
    Assert-True ($kept.Count -eq 46 -and $arguments[1].Count -eq 9) 'Repeated informational events were not reduced to one representative.'
    Assert-True ($kept.Count + $arguments[1].Count -eq $events.Count) 'Filter counts do not reconcile.'
    Assert-True ($kept.Contains($events[$events.Count - 1])) 'Filtering did not retain the latest representative.'
}

Test-Case 'Workflow progress stays monotonic and retranslates without parsing UI text' {
    $step = [LocalSecurityAudit.ViewModels.ScanStep]::new([LocalSecurityAudit.Services.AuditStage]::Analyze)
    $progress = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Active', 'Analyzing ({0}/{1})... {2} issues found', [object[]]@(2, 3, 4))
    $progress.CompletedBatches = 2
    $progress.TotalBatches = 3
    $step.Update($progress)
    $stale = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Active', 'old', [object[]]@())
    $stale.CompletedBatches = 1
    $stale.TotalBatches = 3
    $step.Update($stale)
    Assert-True ($step.Percent -gt 66 -and $step.IsActive) 'A delayed parallel report moved progress backwards.'
    $oldLanguage = [LocalSecurityAudit.Services.AppText]::Current.Language
    try {
        [LocalSecurityAudit.Services.AppText]::Current.SetLanguage('en')
        $english = $step.Detail
        [LocalSecurityAudit.Services.AppText]::Current.SetLanguage('zh-CN')
        Assert-True ($step.Detail -ne $english -and $step.Percent -gt 66) 'Language switching lost progress or retained stale text.'
    }
    finally { [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($oldLanguage) }
    $step.Update([LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Failed', 'Scan failed', [object[]]@()))
    Assert-True ($step.IsFailed -and -not $step.IsActive) 'Failure left a spinning node.'
    $step.Reset()
    Assert-True ($step.IsInactive -and $step.Percent -eq 0 -and -not $step.HasBatchProgress) 'A new scan retained previous batch state.'
}

Test-Case 'Empty or fully filtered audits are not health assessments' {
    $result = [LocalSecurityAudit.Models.AuditResult]::new()
    Assert-True (-not $result.HasAssessment) 'Missing evidence was treated as an assessment.'
    $result.Metadata = [System.Collections.Generic.Dictionary[string,System.Text.Json.JsonElement]]::new()
    $result.Metadata['EventCount'] = [System.Text.Json.JsonSerializer]::SerializeToElement(100, [int])
    $result.Metadata['AnalyzedEventCount'] = [System.Text.Json.JsonSerializer]::SerializeToElement(0, [int])
    Assert-True (-not $result.HasAssessment) 'Fully filtered events earned a health assessment.'
    $result.Metadata['AnalyzedEventCount'] = [System.Text.Json.JsonSerializer]::SerializeToElement(20, [int])
    Assert-True $result.HasAssessment 'A valid AI assessment with no findings was dropped.'
    $null = $result.Metadata.Remove('AnalyzedEventCount')
    Assert-True $result.HasAssessment 'A legacy audit with recorded events became unreadable.'
}

Test-Case 'Missing event references cannot assign unrelated same-ID evidence' {
    $events = [System.Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
    $events.Add((New-TestEvent))
    $newer = New-TestEvent
    $newer.Timestamp = $newer.Timestamp.AddMinutes(2)
    $newer.EventRecordId = 202
    $events.Add($newer)
    $issue = New-BilingualFinding
    $issue.EventId = '4625'
    $issue.EventDescription = 'unverified model-supplied evidence'
    $issues = [System.Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
    $issues.Add($issue)
    $normalized = Invoke-AnalysisMethod 'NormalizeIssues' @($issues, $events)
    Assert-True ([string]::IsNullOrEmpty($normalized[0].EventRef) -and [string]::IsNullOrEmpty($normalized[0].EventDescription)) 'An ambiguous ID was linked to an arbitrary source.'
    $issue.EventTimestamp = $newer.Timestamp.ToString('O')
    $normalized = Invoke-AnalysisMethod 'NormalizeIssues' @($issues, $events)
    Assert-True ($normalized[0].EventRef -eq 'event-1' -and $normalized[0].EventRecordId -eq '202') 'A unique ID and exact timestamp did not recover the correct evidence.'
}

Test-Case 'Late streaming updates cannot reopen a terminal workflow node' {
    foreach ($state in 'Done', 'Failed', 'Skipped') {
        $step = [LocalSecurityAudit.ViewModels.ScanStep]::new('Analyze')
        $null = $step.Update([LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', $state, 'terminal', [object[]]@()))
        $late = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Active', 'late output', [object[]]@())
        Assert-True (-not $step.Update($late) -and $step.State.ToString() -eq $state) 'Late output reopened a finished node.'
        $step.Reset()
        Assert-True ($step.Update($late) -and $step.IsActive) 'A new scan did not reopen its node.'
    }
}

Test-Case 'Concurrent stream details identify their batch without moving aggregate progress' {
    $step = [LocalSecurityAudit.ViewModels.ScanStep]::new('Analyze')
    $detail = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Active', 'Waiting for {0} ({1:0}s)', [object[]]@('Main', 15))
    $detail.BatchNumber = 2
    $null = $step.Update($detail)
    Assert-True ($step.Detail.Contains('2') -and $step.Detail.Contains('Main') -and $step.Percent -eq 0) 'Request-local details were confused with completed batches.'
    $height = $step.RowHeight
    $completed = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Active', 'batch completed', [object[]]@())
    $completed.CompletedBatches = 1
    $completed.TotalBatches = 3
    Assert-True ($step.Update($completed) -and $step.Percent -gt 33 -and $step.RowHeight -eq $height) 'Throttling dropped a batch completion or changed row height.'
    $step.ShowText = $false
    Assert-True ($step.IsActive -and $step.Percent -gt 33 -and -not $step.HasBatchProgress) 'Collapsing the sidebar lost scan state.'
}

Test-Case 'The sidebar stays hidden until a scan starts and retains its saved result afterward' {
    # Construct the state model without activating WinUI or loading user services.
    $viewModelType = $assembly.GetType('LocalSecurityAudit.ViewModels.MainViewModel', $true)
    $viewModel = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($viewModelType)
    $steps = [System.Collections.Generic.List[LocalSecurityAudit.ViewModels.ScanStep]]::new()
    foreach ($stage in [Enum]::GetValues([LocalSecurityAudit.Services.AuditStage])) {
        $steps.Add([LocalSecurityAudit.ViewModels.ScanStep]::new($stage))
    }
    $viewModelType.GetField('<Steps>k__BackingField', $privateFlags).SetValue($viewModel, $steps)
    $viewModel.IsPaneOpen = $true
    Assert-True (-not $viewModel.IsWorkflowVisible -and -not $viewModel.HasSavedResult) 'An idle launch displayed scan progress or a stale save notice.'
    $viewModel.IsPaneOpen = $false
    $viewModel.IsPaneOpen = $true
    $null = $viewModelType.GetMethod('OnLanguageChanged', $privateFlags).Invoke($viewModel, @($null, [EventArgs]::Empty))
    Assert-True (-not $viewModel.IsWorkflowVisible) 'Navigation or language changes displayed an unstarted scan.'
    $apply = $viewModelType.GetMethod('ApplyProgress', $privateFlags)
    $start = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Collect', 'Active', 'Reading', [object[]]@())
    $start.StartsScan = $true
    $null = $apply.Invoke($viewModel, @($start))
    Assert-True ($viewModel.IsWorkflowVisible -and $steps[0].IsActive) 'A real scan did not reveal progress.'
    $saved = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Save', 'Done', 'Saved at {0:t}', [object[]]@([datetime]::Now))
    $null = $apply.Invoke($viewModel, @($saved))
    $complete = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Complete', 'Done', 'Scan complete', [object[]]@())
    $null = $apply.Invoke($viewModel, @($complete))
    Assert-True ($viewModel.IsWorkflowVisible -and $viewModel.HasSavedResult) 'Finishing the scan hid its confirmation.'
    $null = $apply.Invoke($viewModel, @($start))
    Assert-True (-not $viewModel.HasSavedResult -and $steps[5].IsInactive) 'A new scan retained the old completion state.'
}

Test-Case 'Every workflow node uses equal spacing in expanded and compact modes' {
    $previousLanguage = [LocalSecurityAudit.Services.AppText]::Current.Language
    try {
        foreach ($language in 'en', 'zh-CN') {
            [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($language)
            foreach ($expanded in $true, $false) {
                $heights = @(foreach ($stage in [Enum]::GetValues([LocalSecurityAudit.Services.AuditStage])) {
                    $step = [LocalSecurityAudit.ViewModels.ScanStep]::new($stage)
                    $step.ShowText = $expanded
                    foreach ($state in 'Pending', 'Active', 'Done', 'Failed', 'Skipped') {
                        $step.Reset()
                        $null = $step.Update([LocalSecurityAudit.Services.AuditProgressEventArgs]::new($stage, $state, 'Detail', [object[]]@()))
                        $step.RowHeight
                    }
                })
                Assert-True (@($heights | Select-Object -Unique).Count -eq 1) 'Stage, state or language changes produced unequal node spacing.'
            }
        }
    }
    finally { [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($previousLanguage) }
}

foreach ($language in 'zh-CN', 'en') {
    Test-Case "Chart fonts cover localized day labels, categories and tooltip text in $language" {
        $assemblyDirectory = Split-Path -Parent $assembly.Location
        $null = [System.Runtime.InteropServices.NativeLibrary]::Load((Join-Path $assemblyDirectory 'runtimes/win-x64/native/libSkiaSharp.dll'))
        $previousLanguage = [LocalSecurityAudit.Services.AppText]::Current.Language
        $paint = $null
        $numbers = $null
        try {
            [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($language)
            $paint = [LocalSecurityAudit.Helpers.ChartPalette]::TextPaint([SkiaSharp.SKColors]::Black, $true)
            $numbers = [LocalSecurityAudit.Helpers.ChartPalette]::TextPaint([SkiaSharp.SKColors]::Black, $false)
            $labels = @([LocalSecurityAudit.Services.AppText]::Get('Today'))
            foreach ($offset in 0..6) {
                $labels += ([datetime]::new(2026, 9, 1).AddDays($offset)).ToString('ddd d', [LocalSecurityAudit.Services.AppText]::Culture)
            }
            foreach ($category in [Enum]::GetValues([LocalSecurityAudit.Models.IssueCategory])) {
                $labels += [LocalSecurityAudit.Services.AppText]::Get([LocalSecurityAudit.Models.AuditIssueEnhanced]::GetCategoryLabel($category))
            }
            foreach ($label in 'High', 'Medium', 'Low', 'Health', 'Findings') {
                $labels += [LocalSecurityAudit.Services.AppText]::Get($label)
            }
            foreach ($label in $labels) {
                Assert-True ($paint.SKTypeface.ContainsGlyphs($label)) "Chart typeface $($paint.SKTypeface.FamilyName) lacks glyphs for $label."
            }
            Assert-True ($numbers.SKTypeface.ContainsGlyphs('0123456789') -and $numbers.SKTypeface.FamilyName -eq 'Segoe UI Variable Small') 'Numeric chart labels lost the requested typeface.'
            if ($language -eq 'en') {
                Assert-True ($paint.SKTypeface.FamilyName -eq 'Segoe UI Variable Small') 'Switching back to English retained the Chinese fallback.'
            }
        }
        finally {
            if ($paint) { $paint.Dispose() }
            if ($numbers) { $numbers.Dispose() }
            [LocalSecurityAudit.Services.AppText]::Current.SetLanguage($previousLanguage)
        }
    }
}

Test-Case 'Failure-level query includes Kernel-Power Critical events and excludes information' {
    $type = $assembly.GetType('LocalSecurityAudit.Services.EventLogService', $true)
    $predicate = $type.GetField('FailureLevels', $privateFlags).GetRawConstantValue()
    foreach ($level in 1..5) {
        [xml]$eventXml = "<Event><System><Provider Name='Microsoft-Windows-Kernel-Power'/><EventID>41</EventID><Level>$level</Level></System></Event>"
        $selected = $null -ne $eventXml.SelectSingleNode("*[System[$predicate]]")
        Assert-True ($selected -eq ($level -le 3)) "Wrong selection for level $level."
    }
    $from = [datetime]::new(2026, 9, 6, 0, 0, 0, [DateTimeKind]::Utc)
    $query = $type.GetMethod('BuildQuery', $privateFlags).Invoke($null, @($from, $from.AddDays(1), $predicate))
    Assert-True ($query.Contains($from.ToString('O')) -and $query.Contains($from.AddDays(1).ToString('O')) -and $query.Contains($predicate)) 'Failure predicate or UTC bounds were lost.'
}

Test-Case 'Security allowlist covers audit changes and splits XPath queries within Windows limits' {
    $type = $assembly.GetType('LocalSecurityAudit.Services.EventLogService', $true)
    $securityIds = $type.GetField('SecurityEventIds', $privateFlags).GetValue($null)
    $firewallIds = $type.GetField('FirewallEventIds', $privateFlags).GetValue($null)
    foreach ($id in 1102, 4719, 4728, 4732, 4756, 4697, 4907) { Assert-True ($id -in $securityIds) "Missing Security audit ID $id." }
    foreach ($id in 4946, 5025, 5152, 5157) { Assert-True ($id -in $firewallIds) "Missing firewall audit ID $id." }
    Assert-True (@($securityIds | Where-Object { $_ -in $firewallIds }).Count -eq 0) 'Firewall reads duplicate Security records.'
    $now = [datetime]::UtcNow
    foreach ($ids in (,$securityIds), (,$firewallIds)) {
        [xml]$query = $type.GetMethod('BuildEventIdQuery', $privateFlags).Invoke($null, @('Security', $now.AddDays(-1), $now, [int[]]$ids[0]))
        $selectors = @($query.QueryList.Query.Select)
        $seen = @(foreach ($select in $selectors) {
            Assert-True ($select.Path -eq 'Security') 'Firewall or Security query targets the wrong channel.'
            $matches = [regex]::Matches($select.InnerText, 'EventID=(\d+)')
            Assert-True ($matches.Count -le 16) 'An XPath selector exceeds its expression budget.'
            foreach ($match in $matches) { [int]$match.Groups[1].Value }
        })
        Assert-True ($seen.Count -eq $ids[0].Count -and @($seen | Select-Object -Unique).Count -eq $seen.Count) 'Structured query lost or duplicated event IDs.'
    }
}

Test-Case 'Full scans remain exactly 24 hours while fast scans retain their existing range' {
    $type = $assembly.GetType('LocalSecurityAudit.Services.AuditSchedulerService', $true)
    $method = $type.GetMethod('GetScanStart', $privateFlags)
    $now = [datetime]::new(2026, 9, 7, 12, 0, 0, [DateTimeKind]::Utc)
    $config = [LocalSecurityAudit.Models.AppSettings]::new()
    $config.RetentionDays = 30
    $config.ScanIntervalHours = 4
    $config.FastScanRangeHours = 2
    $last = $now.AddMinutes(-20)
    Assert-True ($method.Invoke($null, @($false, $now, $last, $config)) -eq $now.AddHours(-24)) 'Full scan range changed with history retention or fast-scan settings.'
    Assert-True ($method.Invoke($null, @($true, $now, $last, $config)) -eq $now.AddHours(-2)) 'Fixed fast range changed.'
    $config.FastScanRangeHours = 0
    Assert-True ($method.Invoke($null, @($true, $now, $last, $config)) -eq $last) 'Incremental fast range changed.'
}

Test-Case 'Kernel-Power survives filtering and leads analysis before routine events' {
    $configFiltering = $settings.EnableSmartFiltering
    try {
        $settings.EnableSmartFiltering = $true
        $events = [Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
        $routine = New-TestEvent
        $routine.Severity = 'Information'
        $events.Add($routine)
        $kernel = New-TestEvent
        $kernel.EventId = 41
        $kernel.LogName = 'System'
        $kernel.Source = 'Microsoft-Windows-Kernel-Power'
        $kernel.Severity = 'Critical'
        $kernel.AdditionalData = '<EventData><Data Name="BugcheckCode">0</Data></EventData>'
        $events.Add($kernel)
        $sameIdOtherLog = New-TestEvent
        $sameIdOtherLog.EventId = 5156
        $sameIdOtherLog.LogName = 'System'
        $events.Add($sameIdOtherLog)
        $arguments = [object[]]@($events, $null)
        $filtered = $serviceType.GetMethod('ApplySmartFiltering', $privateFlags).Invoke($analysis, $arguments)
        Assert-True ($filtered[0] -eq $kernel -and $filtered.Count -eq 3) 'Critical evidence was sampled away or a different log was excluded by an unrelated event ID.'
        $issue = New-BilingualFinding
        $issue.EventRef = 'event-0'
        $issue.Category = 'Login'
        $normalized = Invoke-AnalysisMethod 'NormalizeIssues' @([LocalSecurityAudit.Models.AuditIssue[]]@($issue), $filtered)
        Assert-True ($normalized[0].Category -eq 'System' -and $normalized[0].LogName -eq 'System' -and $normalized[0].EventId -eq '41' -and $normalized[0].EventAdditionalData -eq $kernel.AdditionalData) 'Kernel-Power classification or original evidence was lost.'
    }
    finally { $settings.EnableSmartFiltering = $configFiltering }
}

Test-Case 'Bugcheck and application event 1001 use their own log and provider namespaces' {
    foreach ($case in @(
        @('System', 'Microsoft-Windows-WER-SystemErrorReporting', 'System'),
        @('System', 'BugCheck', 'System'),
        @('Application', 'Windows Error Reporting', 'Application'),
        @('Setup', 'Microsoft-Windows-Servicing', 'System')
    )) {
        $evt = New-TestEvent
        $evt.EventId = 1001
        $evt.LogName = $case[0]
        $evt.Source = $case[1]
        $events = [Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
        $events.Add($evt)
        $finding = New-BilingualFinding
        $finding.EventRef = 'event-0'
        $finding.Category = 'Login'
        $normalized = Invoke-AnalysisMethod 'NormalizeIssues' @([LocalSecurityAudit.Models.AuditIssue[]]@($finding), $events)
        Assert-True ($normalized[0].Category -eq $case[2]) "Incorrect category for $($case[0])/$($case[1])."
        $normalized[0].Category = 'Login'
        $display = [LocalSecurityAudit.Services.IssueCategorizer]::CategorizeIssue($normalized[0])
        Assert-True ($display.CategoryLabel -eq [LocalSecurityAudit.Services.AppText]::Get($case[2])) 'Stored findings retained an incorrect legacy category.'
    }
}

Test-Case 'Pattern merging cannot hide a finding from another log or provider' {
    $issues = [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
    foreach ($origin in @(@('System', 'SharedProvider'), @('Setup', 'SharedProvider'), @('System', 'OtherProvider'))) {
        $issue = New-BilingualFinding 'same-key'
        $issue.Category = 'System'
        $issue.LogName = $origin[0]
        $issue.Source = $origin[1]
        $issues.Add($issue)
    }
    $merged = Invoke-AnalysisMethod 'MergeDuplicateIssues' (,$issues)
    Assert-True ($merged.Count -eq 3 -and @($merged.LogName | Select-Object -Unique).Count -eq 2) 'A merged issue erased another log or provider.'
}

Test-Case 'Workflow exposes confirmed percentages and resets only on a new scan' {
    $type = $assembly.GetType('LocalSecurityAudit.ViewModels.MainViewModel', $true)
    $model = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
    $steps = [Collections.Generic.List[LocalSecurityAudit.ViewModels.ScanStep]]::new()
    foreach ($stage in [Enum]::GetValues([LocalSecurityAudit.Services.AuditStage])) { $steps.Add([LocalSecurityAudit.ViewModels.ScanStep]::new($stage)) }
    $type.GetField('<Steps>k__BackingField', $privateFlags).SetValue($model, $steps)
    $apply = $type.GetMethod('ApplyProgress', $privateFlags)
    $start = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Collect', 'Active', 'Reading', [object[]]@())
    $start.StartsScan = $true
    $null = $apply.Invoke($model, @($start))
    foreach ($completed in 0..4) {
        $reading = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Collect', 'Active', 'Reading group', [object[]]@())
        $reading.CompletedUnits = $completed
        $reading.TotalUnits = 5
        $null = $apply.Invoke($model, @($reading))
        Assert-True ($steps[0].Percent -eq 20 * $completed -and $steps[0].PercentText.Contains('%')) 'Read-group percentage is incorrect.'
    }
    foreach ($stage in 'Collect', 'Route') {
        $null = $apply.Invoke($model, @([LocalSecurityAudit.Services.AuditProgressEventArgs]::new($stage, 'Done', 'Done', [object[]]@())))
    }
    $batch = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Active', 'Batch complete', [object[]]@())
    $batch.CompletedBatches = 2
    $batch.TotalBatches = 4
    $null = $apply.Invoke($model, @($batch))
    Assert-True ($steps[2].PercentText -eq '50%' -and $model.WorkflowPercent -eq 41) 'Batch percentage or overall stage completion is incorrect.'
    $lateRead = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Collect', 'Active', 'Late read', [object[]]@())
    $lateRead.TotalUnits = 5
    $null = $apply.Invoke($model, @($lateRead))
    Assert-True ($steps[2].Percent -eq 50 -and $model.WorkflowPercent -eq 41) 'A late read progress event reset the workflow.'
    foreach ($stage in 'Analyze', 'Save', 'Translate', 'Complete') {
        $null = $apply.Invoke($model, @([LocalSecurityAudit.Services.AuditProgressEventArgs]::new($stage, 'Done', 'Done', [object[]]@())))
    }
    Assert-True ($model.WorkflowPercentText -eq '100%') 'Completed workflow did not reach 100 percent.'
    $null = $apply.Invoke($model, @($start))
    Assert-True ($model.WorkflowPercent -eq 0 -and -not $model.HasSavedResult) 'New scan retained completion progress.'
    $null = $apply.Invoke($model, @([LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Collect', 'Failed', 'Failure', [object[]]@())))
    Assert-True ($model.WorkflowPercent -lt 100) 'Failed scan was presented as complete.'
}

Write-Output "$script:passed passed; $script:failed failed. No network requests or user-data writes."
if ($script:failed -gt 0) { exit 1 }
