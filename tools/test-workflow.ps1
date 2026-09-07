# Synthetic loopback AI and an in-memory database. No real settings or event logs.
param([string]$AssemblyPath = "$PSScriptRoot\..\bin\x64\Debug\net8.0-windows10.0.19041.0\LocalSecurityAudit.dll")
$ErrorActionPreference = 'Stop'
$assembly = [System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$directory = Split-Path -Parent $assembly.Location
foreach ($dependency in 'Microsoft.Data.Sqlite.dll', 'SQLitePCLRaw.batteries_v2.dll') {
    $null = [System.Reflection.Assembly]::LoadFrom((Join-Path $directory $dependency))
}
$null = [System.Runtime.InteropServices.NativeLibrary]::Load((Join-Path $directory 'runtimes/win-x64/native/e_sqlite3.dll'))
[SQLitePCL.Batteries_V2]::Init()
$flags = [System.Reflection.BindingFlags]'NonPublic,Instance,Static'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class AuditLoopbackEndpoint : IDisposable
{
    private readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new CancellationTokenSource();
    private readonly Task worker;
    public TaskCompletionSource<bool> Waiting { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    public string Url { get; }
    public AuditLoopbackEndpoint(string reply)
    {
        listener.Start();
        Url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = RunAsync(reply);
    }
    private async Task RunAsync(string reply)
    {
        for (int index = 0; index < 2; index++)
        {
            using var client = await listener.AcceptTcpClientAsync(stop.Token);
            using var stream = client.GetStream();
            var header = new List<byte>();
            var one = new byte[1];
            while (header.Count < 16384)
            {
                if (await stream.ReadAsync(one, stop.Token) == 0) throw new IOException("Incomplete request");
                header.Add(one[0]);
                if (header.Count >= 4 && header.TakeLast(4).SequenceEqual(new byte[] {13, 10, 13, 10})) break;
            }
            string lengthLine = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n")
                .First(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
            int remaining = int.Parse(lengthLine.Split(':')[1]);
            var buffer = new byte[4096];
            while (remaining > 0)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(remaining, buffer.Length)), stop.Token);
                if (read == 0) throw new IOException("Incomplete request body");
                remaining -= read;
            }
            if (index == 1)
            {
                Waiting.TrySetResult(true);
                await Task.Delay(Timeout.Infinite, stop.Token);
            }
            byte[] body = Encoding.UTF8.GetBytes(reply);
            byte[] responseHeader = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(responseHeader, stop.Token);
            await stream.WriteAsync(body, stop.Token);
        }
    }
    public void Dispose()
    {
        stop.Cancel();
        listener.Stop();
        try { worker.GetAwaiter().GetResult(); } catch (OperationCanceledException) { }
        stop.Dispose();
    }
}
'@

$settingsType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
$settingsService = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
$settings = [LocalSecurityAudit.Models.AppSettings]::new()
$settings.MaxConcurrentAnalysis = 1
$settings.DiagnosticLoggingEnabled = $false
$settingsType.GetProperty('Current').SetValue($settingsService, $settings)
$loggerType = $assembly.GetType('LocalSecurityAudit.Services.DiagnosticLogService', $true)
$logger = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($loggerType)
$loggerType.GetField('_settingsService', $flags).SetValue($logger, $settingsService)
$storageType = $assembly.GetType('LocalSecurityAudit.Services.DataStorageService', $true)
$storage = [System.Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($storageType)
$connectionString = "Data Source=workflow-$([guid]::NewGuid());Mode=Memory;Cache=Shared;Pooling=False"
$storageType.GetField('_connectionString', $flags).SetValue($storage, $connectionString)
$keeper = [Microsoft.Data.Sqlite.SqliteConnection]::new($connectionString)
$endpoint = $null
$scheduler = $null
try {
    $keeper.Open()
    $storageType.GetMethod('InitializeDatabaseAsync', $flags).Invoke($storage, @()).GetAwaiter().GetResult()
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
    $storage.SaveAuditResultAsync($result).GetAwaiter().GetResult()
    $translated = @(foreach ($index in 0..7) {
        @{key="legacy_$index"; title="Translated $index"; description='Description'; rootCause='Cause'; recommendation='Action';
          titleZh='Chinese title'; descriptionZh='Chinese description'; rootCauseZh='Chinese cause'; recommendationZh='Chinese action'}
    })
    $payload = @{issues=$translated} | ConvertTo-Json -Depth 8 -Compress
    $reply = @{output_text=$payload} | ConvertTo-Json -Compress
    $endpoint = [AuditLoopbackEndpoint]::new($reply)
    $route = [LocalSecurityAudit.Models.AiTargetSettings]::new()
    $route.BaseUrl = $endpoint.Url
    $settings.AiTargets.Add($route)
    $analysis = [LocalSecurityAudit.Services.AiAnalysisService]::new($settingsService, $logger)
    $scheduler = [LocalSecurityAudit.Services.AuditSchedulerService]::new($null, $analysis, $storage, $settingsService, $logger)
    $schedulerType = $scheduler.GetType()
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $schedulerType.GetMethod('StartHistoryTranslation', $flags).Invoke($scheduler, @())
    if ($timer.Elapsed.TotalSeconds -gt 1) { throw 'Starting history translation blocked the caller.' }
    $endpoint.Waiting.Task.WaitAsync([timespan]::FromSeconds(15)).GetAwaiter().GetResult() | Out-Null
    $history = [System.Threading.Tasks.Task]$schedulerType.GetField('_historyTask', $flags).GetValue($scheduler)
    if ($history.IsCompleted) { throw 'The mock second batch should still be waiting.' }
    $schedulerType.GetMethod('PauseHistoryTranslationAsync', $flags).Invoke($scheduler, @()).WaitAsync([timespan]::FromSeconds(5)).GetAwaiter().GetResult()
    $saved = $storage.GetLatestResultAsync().GetAwaiter().GetResult()
    $complete = @($saved.Findings | Where-Object HasBilingualText)
    if ($complete.Count -ne 8) { throw "Expected 8 completed translations to survive cancellation; found $($complete.Count)." }
    if ($saved.Findings[8].HasBilingualText -or $saved.HealthScore -ne 72) { throw 'The interrupted finding or health score changed.' }
    foreach ($index in 0..8) {
        if ($saved.Findings[$index].EventDescription -ne "Original source $index") { throw 'Translation changed original evidence.' }
    }
    $pending = $storage.GetLegacyFindingsAsync().GetAwaiter().GetResult()
    if ($pending.Count -ne 1) { throw 'The partially translated record was not eligible for the next scan.' }
    Write-Output 'PASS Background translation returns immediately; cancellation saves 8 completed findings and retains the pending finding and original evidence.'
}
finally {
    if ($scheduler) { $scheduler.StopAsync([System.Threading.CancellationToken]::None).GetAwaiter().GetResult(); $scheduler.Dispose() }
    if ($endpoint) { $endpoint.Dispose() }
    $keeper.Dispose()
}
