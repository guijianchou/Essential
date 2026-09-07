# Loopback HTTP only. Does not load user settings, write logs or call remote AI.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\bin\x64\Debug\net8.0-windows10.0.19041.0\LocalSecurityAudit.dll"
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
    public string Body = "{\"output_text\":\"{\\\"issues\\\":[]}\"}";
    public string ContentType = "application/json";
    public bool HoldHeaders;
    public bool HoldOpen;
    public bool Disconnect;
    public int DelayMilliseconds;
    public int WaitForRequests;
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
                string lengthLine = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n")
                    .First(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                int remaining = int.Parse(lengthLine.Split(':')[1]);
                if (remaining > 1048576) throw new InvalidOperationException("Unexpected test request size.");
                var buffer = new byte[4096];
                while (remaining > 0)
                {
                    int read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(remaining, buffer.Length)), stop.Token);
                    if (read == 0) return;
                    remaining -= read;
                }

                int index = Interlocked.Increment(ref requestCount) - 1;
                FirstRequest.TrySetResult(true);
                var reply = replies[Math.Min(index, replies.Length - 1)];
                while (RequestCount < reply.WaitForRequests) await Task.Delay(10, stop.Token);
                if (reply.Disconnect) return;
                if (reply.HoldHeaders) await Task.Delay(Timeout.Infinite, stop.Token);
                if (reply.DelayMilliseconds > 0) await Task.Delay(reply.DelayMilliseconds, stop.Token);
                byte[] body = Encoding.UTF8.GetBytes(reply.Body);
                string contentLength = reply.HoldOpen ? "" : "Content-Length: " + body.Length + "\r\n";
                byte[] responseHeader = Encoding.ASCII.GetBytes("HTTP/1.1 " + reply.Status + " Test\r\nContent-Type: "
                    + reply.ContentType + "\r\n" + contentLength + "Connection: close\r\n\r\n");
                await stream.WriteAsync(responseHeader, stop.Token);
                await stream.WriteAsync(body, stop.Token);
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

function New-Analysis($Main, $Fallback = $null, [int]$Parallel = 1) {
    $settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
    $settingsService = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
    $settings = [LocalSecurityAudit.Models.AppSettings]::new()
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

Write-Output "$script:passed passed; $script:failed failed. Loopback HTTP only; no user-data writes."
if ($script:failed -gt 0) { exit 1 }
