# Loopback HTTP only. Does not load user settings, write logs or call remote AI.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\bin\x64\Debug\LocalSecurityAudit-0.3.8\net8.0-windows10.0.19041.0\LocalSecurityAudit.dll"
)
$ErrorActionPreference = 'Stop'
$assembly = [System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$flags = [System.Reflection.BindingFlags]'NonPublic,Instance,Static'
$script:passed = 0
$script:failed = 0

Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class TransportReply
{
    public int Status = 200;
    public string ReasonPhrase = "Test";
    public string Body = "{\"object\":\"response\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"{\\\"issues\\\":[]}\"}]}]}";
    public string Tail = "";
    public int TailDelayMilliseconds;
    public string RequestId = "req_0123456789abcdef0123456789abcdef";
    public string ContentType = "application/json";
    public bool HoldHeaders;
    public bool HoldOpen;
    public bool Disconnect;
    public int DelayMilliseconds;
    public int WaitForRequests;
}

public sealed class AnalysisModelCapture
{
    public string[] Models = Array.Empty<string>();
    public Action<IReadOnlyList<string>> Callback => models => Models = models.ToArray();
}

public sealed class TransportProgress<T> : IProgress<T>
{
    public ConcurrentQueue<T> Events { get; } = new ConcurrentQueue<T>();
    public void Report(T value) => Events.Enqueue(value);
}

public sealed class TransportEndpoint : IDisposable
{
    private readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new CancellationTokenSource();
    private readonly List<Task> clients = new List<Task>();
    private readonly Task worker;
    private int requestCount;
    public int RequestCount => Volatile.Read(ref requestCount);
    public ConcurrentQueue<string> RequestBodies { get; } = new ConcurrentQueue<string>();
    public ConcurrentQueue<string> RequestPaths { get; } = new ConcurrentQueue<string>();
    public TaskCompletionSource<bool> FirstRequest { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    public string Url { get; }

    public TransportEndpoint(TransportReply[] replies)
    {
        listener.Start();
        Url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = RunAsync(replies);
    }

    private async Task RunAsync(TransportReply[] replies)
    {
        try
        {
            while (!stop.IsCancellationRequested)
                clients.Add(HandleAsync(await listener.AcceptTcpClientAsync(stop.Token), replies));
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (SocketException) when (stop.IsCancellationRequested) { }
    }

    private async Task HandleAsync(TcpClient client, TransportReply[] replies)
    {
        using (client)
        {
            try
            {
                using var stream = client.GetStream();
                var header = new List<byte>();
                var one = new byte[1];
                while (header.Count < 16384)
                {
                    if (await stream.ReadAsync(one, stop.Token) == 0) return;
                    header.Add(one[0]);
                    if (header.Count >= 4 && header.TakeLast(4).SequenceEqual(new byte[] {13, 10, 13, 10})) break;
                }
                string headerText = Encoding.ASCII.GetString(header.ToArray());
                RequestPaths.Enqueue(headerText.Split("\r\n")[0].Split(' ')[1]);
                string lengthLine = headerText.Split("\r\n")
                    .First(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                int remaining = int.Parse(lengthLine.Split(':')[1]);
                if (remaining > 1048576) throw new InvalidOperationException("Unexpected test request size.");
                var buffer = new byte[4096];
                using var requestBody = new MemoryStream();
                while (remaining > 0)
                {
                    int read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(remaining, buffer.Length)), stop.Token);
                    if (read == 0) return;
                    requestBody.Write(buffer, 0, read);
                    remaining -= read;
                }
                RequestBodies.Enqueue(Encoding.UTF8.GetString(requestBody.ToArray()));

                int index = Interlocked.Increment(ref requestCount) - 1;
                FirstRequest.TrySetResult(true);
                var reply = replies[Math.Min(index, replies.Length - 1)];
                while (RequestCount < reply.WaitForRequests) await Task.Delay(10, stop.Token);
                if (reply.Disconnect) return;
                if (reply.HoldHeaders) await Task.Delay(Timeout.Infinite, stop.Token);
                if (reply.DelayMilliseconds > 0) await Task.Delay(reply.DelayMilliseconds, stop.Token);
                byte[] body = Encoding.UTF8.GetBytes(reply.Body);
                byte[] tail = Encoding.UTF8.GetBytes(reply.Tail);
                string contentLength = reply.HoldOpen ? "" : "Content-Length: " + (body.Length + tail.Length) + "\r\n";
                byte[] responseHeader = Encoding.ASCII.GetBytes("HTTP/1.1 " + reply.Status + " " + reply.ReasonPhrase + "\r\nContent-Type: "
                    + reply.ContentType + "\r\nx-request-id: " + reply.RequestId + "\r\n" + contentLength + "Connection: close\r\n\r\n");
                await stream.WriteAsync(responseHeader, stop.Token);
                await stream.WriteAsync(body, stop.Token);
                if (reply.TailDelayMilliseconds > 0) await Task.Delay(reply.TailDelayMilliseconds, stop.Token);
                await stream.WriteAsync(tail, stop.Token);
                if (reply.HoldOpen) await Task.Delay(Timeout.Infinite, stop.Token);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (IOException) { } // Client cancellation closes outstanding requests.
        }
    }

    public void Dispose()
    {
        stop.Cancel();
        listener.Stop();
        worker.GetAwaiter().GetResult();
        Task.WhenAll(clients).GetAwaiter().GetResult();
        stop.Dispose();
    }
}
'@

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Test-Case([string]$Name, [scriptblock]$Action) {
    try { $null = & $Action; $script:passed++; Write-Output "PASS $Name" }
    catch { $script:failed++; Write-Output "FAIL $Name`: $($_.Exception.GetBaseException().Message)" }
}

function New-Analysis($Main, $Fallback = $null, [int]$Parallel = 1, [string]$MainModel = 'gpt-5.6-luna', [string]$FallbackModel = 'gpt-5.6-luna') {
    $settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
    $settingsService = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
    $settings = [LocalSecurityAudit.Models.AppSettings]::new()
    $settings.Mode = 'extended'
    $settingsType.GetField('<ActiveMode>k__BackingField', $flags).SetValue($settingsService, 'extended')
    $settings.MaxConcurrentAnalysis = $Parallel
    $settings.EnableSmartFiltering = $false
    $settings.EnableCaching = $false
    $settings.DiagnosticLoggingEnabled = $false
    $settings.AgentInstructions = 'Synthetic test policy.'
    foreach ($endpoint in @($Main, $Fallback)) {
        if ($null -eq $endpoint) { continue }
        $target = [LocalSecurityAudit.Models.AiTargetSettings]::new()
        $target.Name = if ($endpoint -eq $Main) { 'Main' } else { 'Fallback' }
        $target.BaseUrl = $endpoint.Url
        $target.Model = if ($endpoint -eq $Main) { $MainModel } else { $FallbackModel }
        $settings.AiTargets.Add($target)
    }
    $settingsType.GetProperty('Current').SetValue($settingsService, $settings)
    $loggerType = $assembly.GetType('LocalSecurityAudit.Services.DiagnosticLogService', $true)
    $logger = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($loggerType)
    $loggerType.GetField('_settingsService', $flags).SetValue($logger, $settingsService)
    return [LocalSecurityAudit.Services.AiAnalysisService]::new($settingsService, $logger)
}

function New-Events([int]$Count = 1) {
    $events = [System.Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
    for ($index = 0; $index -lt $Count; $index++) {
        $event = [LocalSecurityAudit.Models.SecurityEvent]::new()
        $event.EventId = 41
        $event.LogName = 'System'
        $event.Severity = 'Critical'
        $event.Description = 'Synthetic unexpected restart.'
        $events.Add($event)
    }
    return ,$events
}

function Assert-TaskThrows($Task, [type]$ExceptionType) {
    try { $null = $Task.GetAwaiter().GetResult() }
    catch {
        $errorObject = $_.Exception
        while ($errorObject) {
            if ($ExceptionType.IsInstanceOfType($errorObject)) { return }
            $errorObject = $errorObject.InnerException
        }
        throw
    }
    throw "Expected $($ExceptionType.Name)."
}

function New-ResponsesBody([string]$Text = '{"issues":[]}') {
    return @{id='resp_0123456789abcdef0123456789abcdef'; object='response'; status='completed'; output=@(
        @{type='message'; role='assistant'; status='completed'; content=@(@{type='output_text'; text=$Text})}
    )} | ConvertTo-Json -Compress -Depth 8
}

function New-ResponsesCompleted([string]$Text = '{"issues":[]}') {
    $response = New-ResponsesBody $Text | ConvertFrom-Json
    $event = @{type='response.completed'; sequence_number=4; response=$response} | ConvertTo-Json -Compress -Depth 10
    return "event: response.completed`r`ndata: $event`r`n`r`n"
}

Test-Case 'Responses requests separate instructions and input and use a standard v1 base URL' {
    $endpoint = [TransportEndpoint]::new(@([TransportReply]::new()))
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $service = New-Analysis $endpoint
        $settingsService = $service.GetType().GetField('_settingsService', $flags).GetValue($service)
        $settingsService.Current.AiTargets[0].BaseUrl = $endpoint.Url + '/gateway/v1/'
        $null = $service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token).GetAwaiter().GetResult()
        $request = @($endpoint.RequestBodies)[0] | ConvertFrom-Json
        Assert-True (@($endpoint.RequestPaths)[0] -eq '/gateway/v1/responses') 'The endpoint lost its prefix or duplicated v1.'
        Assert-True ($request.instructions.Contains('Synthetic test policy.')) 'Policy is not a separate instructions field.'
        Assert-True ($request.input -is [string] -and $request.input.Contains('Synthetic unexpected restart.')) 'User event input is missing.'
        Assert-True (-not $request.input.Contains('Synthetic test policy.')) 'System instructions were embedded in user input.'
        Assert-True ($request.stream -eq $true -and $request.store -eq $false -and $request.max_output_tokens -eq 8000) 'Streaming, storage or output limit changed.'
        Assert-True ($null -eq $request.messages -and $null -eq $request.max_tokens) 'Chat Completions fields leaked into Responses.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Test-Case 'Text done waits for delayed response.completed and uses the final response snapshot' {
    $reply = [TransportReply]::new()
    $reply.ContentType = 'text/event-stream'
    $reply.Body = "data: {`"type`":`"response.output_text.done`",`"text`":`"{\`"issues\`":[]}`"}`n`n"
    $reply.Tail = New-ResponsesCompleted
    $reply.TailDelayMilliseconds = 300
    $reply.HoldOpen = $true
    $endpoint = [TransportEndpoint]::new(@($reply))
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $result = (New-Analysis $endpoint).AnalyzeEventsAsync((New-Events), $null, $timeout.Token).GetAwaiter().GetResult()
        Assert-True ($result.Item1.Count -eq 0 -and $timer.ElapsedMilliseconds -ge 250 -and $timer.Elapsed.TotalSeconds -lt 3) 'The client closed early or waited for socket close.'
        Assert-True ($endpoint.RequestCount -eq 1) 'Successful SSE was retried.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Test-Case 'Text done followed by delayed incomplete is not saved as success or retried' {
    $reply = [TransportReply]::new()
    $reply.ContentType = 'text/event-stream'
    $reply.Body = "data: {`"type`":`"response.output_text.done`",`"text`":`"{\`"issues\`":[]}`"}`n`n"
    $reply.Tail = "data: {`"type`":`"response.incomplete`",`"response`":{`"status`":`"incomplete`",`"incomplete_details`":{`"reason`":`"max_output_tokens`"}}}`n`n"
    $reply.TailDelayMilliseconds = 100
    $main = [TransportEndpoint]::new(@($reply))
    $fallback = [TransportEndpoint]::new(@([TransportReply]::new()))
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        Assert-TaskThrows ((New-Analysis $main $fallback).AnalyzeEventsAsync((New-Events), $null, $timeout.Token)) ([Net.Http.HttpRequestException])
        Assert-True ($main.RequestCount -eq 1 -and $fallback.RequestCount -eq 0) 'Incomplete response was retried or failed over.'
    }
    finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
}

Test-Case 'A Responses stream with valid JSON but no completion retries within the existing bound' {
    $reply = [TransportReply]::new()
    $reply.ContentType = 'text/event-stream'
    $reply.Body = "data: {`"type`":`"response.output_text.delta`",`"delta`":`"{\`"issues\`":[]}`"}`n`n"
    $endpoint = [TransportEndpoint]::new(@($reply))
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        Assert-TaskThrows ((New-Analysis $endpoint).AnalyzeEventsAsync((New-Events), $null, $timeout.Token)) ([Net.Http.HttpRequestException])
        Assert-True ($endpoint.RequestCount -eq 2) 'Unfinished response was accepted or retried without a bound.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Test-Case 'Standard HTTP errors retain a safe code but not provider message text' {
    $reply = [TransportReply]::new()
    $reply.Status = 400
    $reply.ReasonPhrase = 'synthetic-private-reason'
    $reply.Body = '{"error":{"code":"unsupported_value","type":"invalid_request_error","param":"reasoning.effort","message":"synthetic-private-value"}}'
    $endpoint = [TransportEndpoint]::new(@($reply))
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    $testLogPath = Join-Path ([IO.Path]::GetTempPath()) ('lsa-responses-test-' + [guid]::NewGuid().ToString('N') + '.log')
    try {
        $service = New-Analysis $endpoint
        $settingsService = $service.GetType().GetField('_settingsService', $flags).GetValue($service)
        $settingsService.Current.DiagnosticLoggingEnabled = $true
        $logger = $service.GetType().GetField('_diagnosticLogService', $flags).GetValue($service)
        $logger.GetType().GetField('_logPath', $flags).SetValue($logger, $testLogPath)
        $logger.GetType().GetField('_writeLock', $flags).SetValue($logger, [object]::new())
        $failure = $null
        try { $null = $service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token).GetAwaiter().GetResult() }
        catch { $failure = $_.Exception.ToString() }
        Assert-True ($failure -and $failure.Contains('unsupported_value') -and -not $failure.Contains('synthetic-private-value')) 'Error diagnostics lost the code or leaked provider data.'
        Assert-True (-not $failure.Contains('synthetic-private-reason')) 'An untrusted HTTP reason phrase leaked into the exception.'
        $logText = Get-Content -LiteralPath $testLogPath -Raw
        Assert-True ($logText.Contains($reply.RequestId) -and $logText.Contains('unsupported_value')) 'Safe request ID or error code was not logged.'
        Assert-True (-not $logText.Contains('synthetic-private-value') -and -not $logText.Contains('Synthetic unexpected restart.')) 'Diagnostics leaked provider text or event data.'
        Assert-True ($endpoint.RequestCount -eq 1) 'A permanent HTTP error was retried.'
    }
    finally {
        $timeout.Dispose(); $endpoint.Dispose()
        if (Test-Path -LiteralPath $testLogPath -PathType Leaf) { Remove-Item -LiteralPath $testLogPath }
    }
}

Test-Case 'An unfinished HTTP error body cannot stall failover for the full analysis timeout' {
    $reply = [TransportReply]::new()
    $reply.Status = 502
    $reply.Body = '{"error":'
    $reply.HoldOpen = $true
    $main = [TransportEndpoint]::new(@($reply))
    $fallback = [TransportEndpoint]::new(@([TransportReply]::new()))
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(9))
    try {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $result = (New-Analysis $main $fallback).AnalyzeEventsAsync((New-Events), $null, $timeout.Token).GetAwaiter().GetResult()
        Assert-True ($result.Item1.Count -eq 0 -and $timer.Elapsed.TotalSeconds -lt 8) 'Error details blocked a known-failed route.'
        Assert-True ($main.RequestCount -eq 1 -and $fallback.RequestCount -eq 1) 'Error-body timeout changed retry limits.'
    }
    finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
}

foreach ($mode in 'sse', 'json') {
    Test-Case "Remote cancellation and incomplete $mode results stop without retry or fallback" {
        foreach ($status in 'cancelled', 'incomplete') {
            $reply = [TransportReply]::new()
            $payload = @{type="response.$status"; response=@{status=$status}; status=$status; output_text='{"issues":[]}'} | ConvertTo-Json -Compress
            $reply.Body = if ($mode -eq 'sse') { "data: $payload`n`n" } else { $payload }
            $reply.ContentType = if ($mode -eq 'sse') { 'text/event-stream' } else { 'application/json' }
            $reply.HoldOpen = $mode -eq 'sse'
            $main = [TransportEndpoint]::new(@($reply))
            $fallback = [TransportEndpoint]::new(@([TransportReply]::new()))
            $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(4))
            try {
                $service = New-Analysis $main $fallback
                Assert-TaskThrows ($service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token)) ([System.Net.Http.HttpRequestException])
                Assert-True ($main.RequestCount -eq 1 -and $fallback.RequestCount -eq 0) 'Terminal response was retried or failed over.'
            }
            finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
        }
    }
}

Test-Case 'A failed provider can use the fallback once' {
    $reply = [TransportReply]::new()
    $reply.ContentType = 'text/event-stream'
    $reply.Body = "data: {`"type`":`"response.failed`",`"response`":{`"status`":`"failed`"}}`n`n"
    $main = [TransportEndpoint]::new(@($reply))
    $fallback = [TransportEndpoint]::new(@([TransportReply]::new()))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $service = New-Analysis $main $fallback
        $result = $service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token).GetAwaiter().GetResult()
        Assert-True ($result.Item1.Count -eq 0 -and $main.RequestCount -eq 1 -and $fallback.RequestCount -eq 1) 'Fallback did not recover once.'
    }
    finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
}

Test-Case 'A dropped connection retries once and reports the delay' {
    $drop = [TransportReply]::new()
    $drop.Disconnect = $true
    $endpoint = [TransportEndpoint]::new(@($drop, [TransportReply]::new()))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    $progress = [TransportProgress[LocalSecurityAudit.Services.AuditProgressEventArgs]]::new()
    try {
        $service = New-Analysis $endpoint
        $result = $service.AnalyzeEventsAsync((New-Events), $progress, $timeout.Token).GetAwaiter().GetResult()
        Assert-True ($result.Item1.Count -eq 0 -and $endpoint.RequestCount -eq 2) 'Transport recovery did not use exactly two attempts.'
        Assert-True (@($progress.Events | Where-Object MessageKey -Like '*retry in*').Count -eq 1) 'Retry delay was not reported.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Test-Case 'Persistent server errors stop after two attempts' {
    $reply = [TransportReply]::new()
    $reply.Status = 503
    $endpoint = [TransportEndpoint]::new(@($reply))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $service = New-Analysis $endpoint
        Assert-TaskThrows ($service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token)) ([System.Net.Http.HttpRequestException])
        Assert-True ($endpoint.RequestCount -eq 2) 'Persistent failure sent more than two requests.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Test-Case 'A failed batch cancels active siblings and prevents queued requests' {
    $hold = [TransportReply]::new()
    $hold.HoldHeaders = $true
    $failure = [TransportReply]::new()
    $failure.Status = 503
    $failure.WaitForRequests = 2
    $endpoint = [TransportEndpoint]::new(@($hold, $failure, $hold, $failure))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $service = New-Analysis $endpoint -Parallel 3
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        Assert-TaskThrows ($service.AnalyzeEventsAsync((New-Events 250), $null, $timeout.Token)) ([System.Net.Http.HttpRequestException])
        Assert-True ($endpoint.RequestCount -eq 4 -and $timer.Elapsed.TotalSeconds -lt 4) 'Failed scan kept sending queued batches or waiting on siblings.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Test-Case 'Caller cancellation interrupts header waits without retry or fallback' {
    $reply = [TransportReply]::new()
    $reply.HoldHeaders = $true
    $main = [TransportEndpoint]::new(@($reply))
    $fallback = [TransportEndpoint]::new(@([TransportReply]::new()))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $service = New-Analysis $main $fallback
        $task = $service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token)
        Assert-True ($main.FirstRequest.Task.Wait([TimeSpan]::FromSeconds(3))) 'Request did not start.'
        $timeout.Cancel()
        Assert-TaskThrows $task ([System.OperationCanceledException])
        Assert-True ($main.RequestCount -eq 1 -and $fallback.RequestCount -eq 0) 'Cancelled request was retried.'
    }
    finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
}

Test-Case 'Slow headers show elapsed progress and still complete normally' {
    $reply = [TransportReply]::new()
    $reply.DelayMilliseconds = 5300
    $endpoint = [TransportEndpoint]::new(@($reply))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(9))
    $progress = [TransportProgress[LocalSecurityAudit.Services.AuditProgressEventArgs]]::new()
    try {
        $service = New-Analysis $endpoint
        $result = $service.AnalyzeEventsAsync((New-Events), $progress, $timeout.Token).GetAwaiter().GetResult()
        Assert-True ($result.Item1.Count -eq 0) 'Slow response failed.'
        Assert-True (@($progress.Events | Where-Object MessageKey -Like '*headers*').Count -ge 1) 'Header wait had no elapsed progress.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

function New-ReviewPayload([int]$Count = 1, [string]$Prefix = 'event-') {
    $issues = @(for ($index = 0; $index -lt $Count; $index++) {
        @{key="$Prefix$index"; eventRef="event-$index"; title='Reviewed finding'; description='Synthetic evidence'; rootCause='Cause uncertain'; recommendation='Verify evidence';
          titleZh='Reviewed zh'; descriptionZh='Evidence zh'; rootCauseZh='Cause zh'; recommendationZh='Action zh'; severity='Low'; confidence='Medium'; category='System'}
    })
    return @{issues=$issues} | ConvertTo-Json -Compress -Depth 6
}

Test-Case 'Every supported model is sent as selected and labels generated findings' {
    $reply = [TransportReply]::new()
    $reply.Body = New-ResponsesBody (New-ReviewPayload)
    $endpoint = [TransportEndpoint]::new(@($reply))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(8))
    try {
        foreach ($model in [LocalSecurityAudit.Models.AiModelCatalog]::Models) {
            $service = New-Analysis $endpoint -MainModel $model
            $result = $service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token).GetAwaiter().GetResult()
            Assert-True ($result.Item1.Count -eq 1 -and $result.Item1[0].AnalysisModel -eq $model -and $result.Item1[0].OriginalAnalysisModel -eq $model) 'Generated finding was labelled with another model.'
        }
        $requests = @($endpoint.RequestBodies | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-True (($requests.model -join ',') -eq ([LocalSecurityAudit.Models.AiModelCatalog]::Models -join ',')) 'Dispatch changed a selected model.'
        Assert-True (@($requests | Where-Object { $_.reasoning.effort -ne 'medium' }).Count -eq 0) 'Dispatch changed reasoning effort.'
    }
    finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Test-Case 'Findings record the actual fallback model when Main does not support its model' {
    $notFound = [TransportReply]::new()
    $notFound.Status = 404
    $reply = [TransportReply]::new()
    $reply.Body = New-ResponsesBody (New-ReviewPayload)
    $main = [TransportEndpoint]::new(@($notFound))
    $fallback = [TransportEndpoint]::new(@($reply))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $service = New-Analysis $main $fallback -MainModel 'gpt-5.6-sol' -FallbackModel 'gpt-5.6-terra'
        $result = $service.AnalyzeEventsAsync((New-Events), $null, $timeout.Token).GetAwaiter().GetResult()
        Assert-True ($result.Item1[0].AnalysisModel -eq 'gpt-5.6-terra' -and $main.RequestCount -eq 1 -and $fallback.RequestCount -eq 1) 'Fallback ownership was attributed to Main.'
    }
    finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
}

Test-Case 'Optimization forces the selected model on fallback and blocks downward requests before dispatch' {
    $notFound = [TransportReply]::new()
    $notFound.Status = 404
    $reply = [TransportReply]::new()
    $reply.Body = New-ResponsesBody (New-ReviewPayload -Prefix 'optimize_')
    $main = [TransportEndpoint]::new(@($notFound))
    $fallback = [TransportEndpoint]::new(@($reply))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
    try {
        $service = New-Analysis $main $fallback
        $originals = [Collections.Generic.List[LocalSecurityAudit.Models.AuditIssue]]::new()
        $issue = [LocalSecurityAudit.Models.AuditIssue]::new()
        $issue.AnalysisModel = 'gpt-5.6-sol'
        $issue.EventDescription = 'Original evidence'
        $originals.Add($issue)
        Assert-TaskThrows ($service.OptimizeFindingsAsync($originals, 'gpt-5.6-luna', $null, $timeout.Token)) ([InvalidOperationException])
        Assert-True ($main.RequestCount -eq 0) 'A downward optimization reached the endpoint.'
        $result = $service.OptimizeFindingsAsync($originals, 'gpt-6-astra', $null, $timeout.Token).GetAwaiter().GetResult()
        Assert-True ($result[0].AnalysisModel -eq 'gpt-6-astra' -and $result[0].OriginalAnalysisModel -eq 'gpt-5.6-sol' -and $result[0].EventDescription -eq 'Original evidence') 'Optimization lost model or evidence.'
        $requests = @($main.RequestBodies) + @($fallback.RequestBodies)
        Assert-True (@($requests | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.model -ne 'gpt-6-astra' }).Count -eq 0) 'Fallback downgraded the selected optimization model.'
    }
    finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
}

Test-Case 'Cancelling history optimization retains completed batches and a scan can resume' {
    $directory = Split-Path -Parent $assembly.Location
    $null = [Reflection.Assembly]::LoadFrom((Join-Path $directory 'Microsoft.Data.Sqlite.dll'))
    $null = [Reflection.Assembly]::LoadFrom((Join-Path $directory 'SQLitePCLRaw.batteries_v2.dll'))
    $sqlitePath = Join-Path $directory 'e_sqlite3.dll'
    if (-not (Test-Path -LiteralPath $sqlitePath)) { $sqlitePath = Join-Path $directory 'runtimes/win-x64/native/e_sqlite3.dll' }
    $null = [Runtime.InteropServices.NativeLibrary]::Load($sqlitePath)
    [SQLitePCL.Batteries_V2]::Init()
    $reply = [TransportReply]::new()
    $reply.Body = New-ResponsesBody (New-ReviewPayload -Count 8 -Prefix 'optimize_')
    $hold = [TransportReply]::new()
    $hold.HoldHeaders = $true
    $endpoint = [TransportEndpoint]::new(@($reply, $hold))
    $timeout = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(8))
    $database = Join-Path ([IO.Path]::GetTempPath()) "lsa-optimization-$([guid]::NewGuid()).db"
    $connectionString = "Data Source=$database;Pooling=False"
    $keeper = [Microsoft.Data.Sqlite.SqliteConnection]::new($connectionString)
    $scheduler = $null
    try {
        $keeper.Open()
        $storageType = $assembly.GetType('LocalSecurityAudit.Services.DataStorageService', $true)
        $storage = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($storageType)
        $storageType.GetField('_connectionString', $flags).SetValue($storage, $connectionString)
        $storageType.GetField('_historyPaths', $flags).SetValue($storage, [string[]]@($database, "$database.assistant"))
        $storageType.GetMethod('InitializeDatabaseAsync', $flags).Invoke($storage, @()).GetAwaiter().GetResult()
        $audit = [LocalSecurityAudit.Models.AuditResult]::new()
        $audit.Timestamp = [datetime]::UtcNow
        foreach ($index in 0..9) {
            $finding = [LocalSecurityAudit.Models.AuditIssue]::new()
            $finding.Key = "source-$index"; $finding.Title = "Original $index"; $finding.AnalysisModel = 'gpt-5.6-luna'
            $finding.EventRecordId = "$index"; $finding.Severity = 'High'
            $audit.Findings.Add($finding)
        }
        $storage.SaveAuditResultAsync($audit).GetAwaiter().GetResult()
        $service = New-Analysis $endpoint
        $serviceType = $service.GetType()
        $settingsService = $serviceType.GetField('_settingsService', $flags).GetValue($service)
        $logger = $serviceType.GetField('_diagnosticLogService', $flags).GetValue($service)
        $scheduler = [LocalSecurityAudit.Services.AuditSchedulerService]::new($null, $service, $storage, $settingsService, $logger)
        $task = $scheduler.OptimizeHistoryAsync('gpt-5.6-sol', $null, $timeout.Token)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ($endpoint.RequestCount -lt 2 -and $timer.Elapsed.TotalSeconds -lt 4) { Start-Sleep -Milliseconds 20 }
        Assert-True ($endpoint.RequestCount -eq 2) 'Optimization did not start its second batch.'
        $timeout.Cancel()
        Assert-TaskThrows $task ([OperationCanceledException])
        $latest = $storage.GetLatestResultAsync().GetAwaiter().GetResult()
        Assert-True (@($latest.Findings | Where-Object AnalysisModel -EQ 'gpt-5.6-sol').Count -eq 8) 'Completed optimization batches were lost or unfinished ones saved.'
        Assert-True ($latest.Findings[9].Title -eq 'Original 9' -and $latest.Findings[0].EventRecordId -eq '0') 'Cancellation changed unreviewed text or source evidence.'
        $scheduler.GetType().GetMethod('PauseHistoryTranslationAsync', $flags).Invoke($scheduler, @()).GetAwaiter().GetResult()
    }
    finally {
        if ($scheduler) { $scheduler.StopAsync([Threading.CancellationToken]::None).GetAwaiter().GetResult(); $scheduler.Dispose() }
        $timeout.Dispose(); $endpoint.Dispose(); $keeper.Dispose(); [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools(); [IO.File]::Delete($database)
    }
}

Test-Case 'Empty successful findings retain the actual fallback model and cached primary model' {
    $failure=[TransportReply]::new(); $failure.Status=500
    $main=[TransportEndpoint]::new(@($failure)); $fallback=[TransportEndpoint]::new(@([TransportReply]::new()))
    $capture=[AnalysisModelCapture]::new()
    $timeout=[Threading.CancellationTokenSource]::new([timespan]::FromSeconds(8))
    try {
        $service=New-Analysis $main $fallback -MainModel 'gpt-6-astra' -FallbackModel 'gpt-5.6-luna'
        $result=$service.AnalyzeEventsAsync((New-Events),$null,$timeout.Token,$capture.Callback).GetAwaiter().GetResult()
        Assert-True ($result.Item1.Count -eq 0 -and $capture.Models.Count -eq 1 -and $capture.Models[0] -eq 'gpt-5.6-luna') 'Empty fallback response was labelled with the requested higher model.'
    } finally { $timeout.Dispose(); $main.Dispose(); $fallback.Dispose() }
    $endpoint=[TransportEndpoint]::new(@([TransportReply]::new()))
    $timeout=[Threading.CancellationTokenSource]::new([timespan]::FromSeconds(8))
    try {
        $service=New-Analysis $endpoint -MainModel 'gpt-5.6-sol'
        $config=$service.GetType().GetField('_settingsService',$flags).GetValue($service).Current
        $config.EnableCaching=$true; $events=New-Events
        foreach($attempt in 1..2) {
            $capture.Models=@()
            $null=$service.AnalyzeEventsAsync($events,$null,$timeout.Token,$capture.Callback).GetAwaiter().GetResult()
            Assert-True ($capture.Models.Count -eq 1 -and $capture.Models[0] -eq 'gpt-5.6-sol') 'Cache hit lost model provenance.'
        }
        Assert-True ($endpoint.RequestCount -eq 1) 'Cached success called the endpoint again.'
    } finally { $timeout.Dispose(); $endpoint.Dispose() }
}

Write-Output "$script:passed passed; $script:failed failed. Loopback HTTP only; no user-data writes."
if ($script:failed -gt 0) { exit 1 }
