# External-agent helper only. The display application never invokes this script.
# Read-only event collection; no elevation, AI calls, system changes, or database writes.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$FromUtc = '',
    [string]$ToUtc = '',
    [switch]$IncludeSecurity,
    [ValidateRange(1, 5000)][int]$MaxEventsPerChannel = 2000
)
$ErrorActionPreference = 'Stop'

function Read-UtcArgument([string]$Value) {
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$') {
        throw 'Time arguments must be ISO-8601 UTC timestamps ending in Z.'
    }
    try { return [datetimeoffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() }
    catch { throw 'A time argument is invalid.' }
}

function Protect-AuditText([string]$Value, [int]$Limit) {
    $safe = [regex]::Replace($Value, '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '[REDACTED PRIVATE KEY]')
    $safe = [regex]::Replace($safe, '\bsk-[A-Za-z0-9_-]{20,}', '[REDACTED]')
    $safe = [regex]::Replace($safe, '(?i)\b(Bearer|Basic)\s+[A-Za-z0-9_+/=-]{16,}', '$1 [REDACTED]')
    $safe = [regex]::Replace($safe, '(?i)\b(api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|password|passwd|pwd|secret|cookie|set-cookie|authorization)\s*[:=]\s*("[^"]*"|''[^'']*''|[^\s,;<>]+)', '$1=[REDACTED]')
    $safe = [regex]::Replace($safe, '(?i)(?:--?|/)(password|passwd|pwd|token|secret)(?:\s+|[:=])("[^"]*"|''[^'']*''|[^\s]+)', '$1=[REDACTED]')
    $safe = $safe.Replace([string][char]0, '')
    if ($safe.Length -gt $Limit) { return $safe.Substring(0, $Limit - 12) + ' [truncated]' }
    return $safe
}

$auditOutputPath = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $auditOutputPath) { throw 'The output file already exists. Use a new filename; evidence is never overwritten.' }
$auditEnd = if ($ToUtc) { Read-UtcArgument $ToUtc } else { [datetimeoffset]::UtcNow }
$auditStart = if ($FromUtc) { Read-UtcArgument $FromUtc } else { $auditEnd.AddHours(-24) }
if ($auditStart -ge $auditEnd -or ($auditEnd - $auditStart).TotalHours -gt 24 -or $auditEnd -gt [datetimeoffset]::UtcNow) {
    throw 'Use a positive collection window of at most 24 hours that ends no later than now.'
}
$auditTimer = [Diagnostics.Stopwatch]::StartNew()
$auditRunId = [guid]::NewGuid().ToString()
$securityIds = @(1102,1104,1108,4616,4624,4625,4634,4647,4648,4657,4663,4672,4673,4674,4688,4697,4698,4702,4719,4720,4722,4723,4724,4728,4732,4738,4739,4740,4756,4776,4778,4779,4817,4902,4907,4946,4947,4948,4950,5024,5025,5031,5152,5157)
$allowedFields = @('SubjectUserName','SubjectDomainName','TargetUserName','TargetDomainName','LogonType','AuthenticationPackageName',
    'WorkstationName','IpAddress','IpPort','SourceAddress','ProcessName','NewProcessName','ParentProcessName','ServiceName',
    'ServiceFileName','ServiceType','StartType','AccountName','Status','SubStatus','FailureReason','TargetServerName','ObjectName',
    'ObjectType','PrivilegeList','MemberName','GroupName','RuleName','RuleId','Application','Direction','SourcePort','DestAddress',
    'DestPort','Protocol','param1','param2','param3','BugcheckCode','BugcheckParameter1','BugcheckParameter2')
$auditEvents = [Collections.Generic.List[object]]::new()
$auditChannels = [Collections.Generic.List[object]]::new()
$fromText = $auditStart.UtcDateTime.ToString('o')
$toText = $auditEnd.UtcDateTime.ToString('o')
$timeFilter = "TimeCreated[@SystemTime &gt;= '$fromText' and @SystemTime &lt; '$toText']"

foreach ($logName in 'Security', 'System', 'Application', 'Setup', 'ForwardedEvents') {
    if ($logName -eq 'Security' -and -not $IncludeSecurity) {
        $auditChannels.Add([ordered]@{ LogName = $logName; Status = 'skipped'; EventCount = 0; Reason = 'not_requested' })
        continue
    }
    $records = @()
    $channelEvents = [Collections.Generic.List[object]]::new()
    $channelStatus, $reason = 'complete', 'none'
    try {
        $selects = [Collections.Generic.List[string]]::new()
        if ($logName -eq 'Security') {
            # Stay below Windows Event Log's per-expression complexity limit.
            for ($offset = 0; $offset -lt $securityIds.Count; $offset += 16) {
                $last = [Math]::Min($offset + 15, $securityIds.Count - 1)
                $ids = ($securityIds[$offset..$last] | ForEach-Object { "EventID=$_" }) -join ' or '
                $selects.Add("<Select Path='Security'>*[System[$timeFilter and ($ids)]]</Select>")
            }
        }
        else { $selects.Add("<Select Path='$logName'>*[System[$timeFilter and (Level=1 or Level=2 or Level=3)]]</Select>") }
        $query = "<QueryList><Query Id='0' Path='$logName'>$($selects -join '')</Query></QueryList>"
        $records = @(Get-WinEvent -FilterXml $query -MaxEvents ($MaxEventsPerChannel + 1) -ErrorAction Stop)
        if ($records.Count -gt $MaxEventsPerChannel) { $channelStatus, $reason = 'truncated', 'limit' }
        foreach ($record in ($records | Select-Object -First $MaxEventsPerChannel)) {
            if ($null -eq $record.TimeCreated -or $null -eq $record.RecordId) { throw 'Missing event identity.' }
            $eventTime = $record.TimeCreated.ToUniversalTime()
            if ($eventTime -lt $auditStart.UtcDateTime -or $eventTime -ge $auditEnd.UtcDateTime) { throw 'Event outside requested window.' }
            [xml]$eventXml = $record.ToXml()
            $data = [ordered]@{}
            foreach ($field in @($eventXml.Event.EventData.Data)) {
                if ($null -ne $field -and $field.Name -in $allowedFields) {
                    $data[$field.Name] = Protect-AuditText ([string]$field.InnerText) 512
                }
            }
            # Message text is redacted too; no raw XML, command line, or credential fields are retained.
            $description = Protect-AuditText ([string]$record.Message) 4096
            $account = if ($data.Contains('TargetUserName')) { $data['TargetUserName'] }
                elseif ($data.Contains('SubjectUserName')) { $data['SubjectUserName'] } else { '' }
            $address = if ($data.Contains('IpAddress')) { $data['IpAddress'] }
                elseif ($data.Contains('SourceAddress')) { $data['SourceAddress'] } else { '' }
            $channelEvents.Add([ordered]@{
                EventRef = "$logName`:$($record.RecordId)"
                EventId = [string]$record.Id
                EventTimestamp = $eventTime.ToString('o')
                Source = Protect-AuditText ([string]$record.ProviderName) 512
                LogName = $logName
                EventRecordId = [string]$record.RecordId
                EventDescription = $description
                EventAdditionalData = Protect-AuditText ($data | ConvertTo-Json -Depth 4 -Compress) 8192
                UserName = Protect-AuditText ([string]$account) 256
                IpAddress = Protect-AuditText ([string]$address) 128
            })
        }
    }
    catch {
        $channelEvents.Clear()
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $channelStatus, $reason = 'complete', 'none' }
        else {
            $channelStatus = 'unavailable'
            $reason = if ($_.Exception -is [UnauthorizedAccessException] -or $_.CategoryInfo.Category -eq 'PermissionDenied') { 'access_denied' }
                elseif ($_.FullyQualifiedErrorId -match 'NoMatchingLogsFound|EventLogNotFound') { 'not_found' } else { 'query_failed' }
        }
    }
    finally { foreach ($record in $records) { $record.Dispose() } }
    $auditEvents.AddRange($channelEvents)
    $auditChannels.Add([ordered]@{ LogName = $logName; Status = $channelStatus; EventCount = $channelEvents.Count; Reason = $reason })
}

$document = [ordered]@{
    SchemaVersion = 2
    RunId = $auditRunId
    ScanStart = $fromText
    ScanEnd = $toText
    CollectedAt = [datetime]::UtcNow.ToString('o')
    DurationMs = $auditTimer.ElapsedMilliseconds
    Channels = $auditChannels.ToArray()
    Events = $auditEvents.ToArray()
}
$null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($auditOutputPath))
$stream = [IO.File]::Open($auditOutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    try { $writer.Write(($document | ConvertTo-Json -Depth 8 -Compress)) }
    finally { $writer.Dispose() }
}
finally { $stream.Dispose() }
[ordered]@{ RunId = $auditRunId; OutputPath = $auditOutputPath; EventCount = $auditEvents.Count; Channels = $auditChannels.ToArray() } | ConvertTo-Json -Depth 4 -Compress
