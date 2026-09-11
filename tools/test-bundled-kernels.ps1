# Real bundled CLI executables against synthetic loopback Responses and Chat endpoints.
# No remote AI, user settings, stored credentials, event logs or application window.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll",
    [ValidateSet('codex','pi')][string[]]$Kernels = @('codex','pi'),
    [string]$PiInstallationPath = ''
)
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
. "$PSScriptRoot\kernel-test-support.ps1"
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
public sealed class KernelLoopback : IDisposable
{
    readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    readonly CancellationTokenSource stop = new CancellationTokenSource();
    readonly Task worker;
    public string Url;
    public string Path = "";
    public string Model = "";
    public string Effort = "";
    public bool KeyMatches;
    public int Requests;
    public int DropResponses;
    public bool SawAuditPolicy;
    public bool SawPolicyEnd;
    public bool SawAuditContract;
    public string LiteHeader = "";
    public string ReasoningContext = "";
    public bool RejectLite = true;
    public KernelLoopback() {
        listener.Start();
        Url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = Task.Run(RunAsync);
    }
    async Task RunAsync() {
        while (!stop.IsCancellationRequested) {
            using var client = await listener.AcceptTcpClientAsync(stop.Token);
            using var stream = client.GetStream();
            var bytes = new List<byte>(); var one = new byte[1];
            while (bytes.Count < 32768) {
                await stream.ReadExactlyAsync(one, stop.Token); bytes.Add(one[0]);
                if (bytes.Count >= 4 && bytes.TakeLast(4).SequenceEqual(new byte[] {13,10,13,10})) break;
            }
            string headers = Encoding.ASCII.GetString(bytes.ToArray());
            LiteHeader = headers.Split("\r\n").FirstOrDefault(line => line.StartsWith("X-OpenAI-Internal-Codex-Responses-Lite:", StringComparison.OrdinalIgnoreCase)) ?? "";
            Path = headers.Split(' ')[1];
            KeyMatches = headers.Split("\r\n").Any(line => line.Equals("Authorization: Bearer synthetic-secret", StringComparison.OrdinalIgnoreCase));
            string length = headers.Split("\r\n").First(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)).Split(':')[1];
            int size = int.Parse(length); if (size > 1048576) throw new InvalidDataException("Unexpected test request size.");
            var body = new byte[size]; await stream.ReadExactlyAsync(body, stop.Token);
            if (headers.Contains("Content-Encoding: gzip", StringComparison.OrdinalIgnoreCase)) {
                using var zipped = new GZipStream(new MemoryStream(body), CompressionMode.Decompress);
                using var unzipped = new MemoryStream(); zipped.CopyTo(unzipped); body = unzipped.ToArray();
            }
            using var request = JsonDocument.Parse(body);
            SawAuditPolicy |= Encoding.UTF8.GetString(body).Contains("Synthetic security-audit policy marker", StringComparison.Ordinal);
            SawPolicyEnd |= Encoding.UTF8.GetString(body).Contains("End-of-security-audit-policy", StringComparison.Ordinal);
            SawAuditContract |= Encoding.UTF8.GetString(body).Contains("Required shape:", StringComparison.Ordinal);
            Model = request.RootElement.GetProperty("model").GetString();
            if (request.RootElement.TryGetProperty("reasoning", out var reasoning) && reasoning.TryGetProperty("effort", out var effort)) Effort = effort.GetString();
            if (request.RootElement.TryGetProperty("reasoning", out reasoning) && reasoning.TryGetProperty("context", out var reasoningContext)) ReasoningContext = reasoningContext.GetString();
            if (request.RootElement.TryGetProperty("reasoning_effort", out var chatEffort)) Effort = chatEffort.GetString();
            Interlocked.Increment(ref Requests);
            // Simulate a public gateway that cannot forward the internal Lite contract.
            if (RejectLite && LiteHeader.Length > 0) {
                var error = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { error = new {
                    message = "X-OpenAI-Internal-Codex-Responses-Lite requires reasoning.context to be all_turns.",
                    type = "invalid_request_error", code = "unsupported_value" } }));
                var rejected = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + error.Length + "\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(rejected, stop.Token); await stream.WriteAsync(error, stop.Token);
                continue;
            }
            var text = new { type="output_text", text="{\"issues\":[]}", annotations=Array.Empty<object>() };
            var item = new { type="message", id="msg_synthetic", role="assistant", status="completed", content=new[] { text } };
            var response = new { id="resp_synthetic", @object="response", created_at=1788900000, status="completed", model=Model, output=new[] {item}, usage=new { input_tokens=120, output_tokens=30, total_tokens=150, input_tokens_details=new {cached_tokens=20}, output_tokens_details=new {reasoning_tokens=0} } };
            object[] events = {
                new { type="response.created", sequence_number=0, response=new { id="resp_synthetic", @object="response", created_at=1788900000, status="in_progress", model=Model, output=Array.Empty<object>() } },
                new { type="response.output_item.added", sequence_number=1, output_index=0, item=new { type="message", id="msg_synthetic", role="assistant", status="in_progress", content=Array.Empty<object>() } },
                new { type="response.content_part.added", sequence_number=2, output_index=0, content_index=0, item_id="msg_synthetic", part=new {type="output_text", text="", annotations=Array.Empty<object>()} },
                new { type="response.output_text.delta", sequence_number=3, output_index=0, content_index=0, item_id="msg_synthetic", delta="{\"issues\":[]}" },
                new { type="response.output_text.done", sequence_number=4, output_index=0, content_index=0, item_id="msg_synthetic", text="{\"issues\":[]}" },
                new { type="response.content_part.done", sequence_number=5, output_index=0, content_index=0, item_id="msg_synthetic", part=text },
                new { type="response.output_item.done", sequence_number=6, output_index=0, item },
                new { type="response.completed", sequence_number=7, response }
            };
            string sse = string.Concat(events.Select(value => "data: " + JsonSerializer.Serialize(value) + "\n\n"));
            if (DropResponses < 0 || Requests <= DropResponses)
                sse = string.Concat(events.Take(events.Length - 1).Select(value => "data: " + JsonSerializer.Serialize(value) + "\n\n"));
            if (Path == "/v1/chat/completions") {
                object[] chunks = {
                    new { id="chat_synthetic", @object="chat.completion.chunk", created=1788900000, model=Model,
                        choices=new[] { new { index=0, delta=new { role="assistant", content="{\"issues\":[]}" }, finish_reason=(string)null } } },
                    new { id="chat_synthetic", @object="chat.completion.chunk", created=1788900000, model=Model,
                        choices=new[] { new { index=0, delta=new {}, finish_reason="stop" } },
                        usage=new { prompt_tokens=120, completion_tokens=30, total_tokens=150, prompt_tokens_details=new { cached_tokens=20 } } }
                };
                sse = string.Concat(chunks.Select(value => "data: " + JsonSerializer.Serialize(value) + "\n\n")) + "data: [DONE]\n\n";
            }
            var data = Encoding.UTF8.GetBytes(sse);
            var head = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + data.Length + "\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(head, stop.Token); await stream.WriteAsync(data, stop.Token);
        }
    }
    public void Dispose() { stop.Cancel(); listener.Stop(); try { worker.GetAwaiter().GetResult(); } catch (OperationCanceledException) {} stop.Dispose(); }
}
'@
$fixture = New-KernelFixture $assembly
$flags = [Reflection.BindingFlags]'NonPublic,Static'
$managerType = $fixture.Manager.GetType()
$bundledRoot = Join-Path $fixture.Root 'bundled'
$managerType.GetField('_kernelRoot', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($fixture.Manager, $bundledRoot)
try {
    foreach ($kernel in $Kernels) {
        $name = if ($kernel -eq 'codex') { 'codex-x86_64-pc-windows-msvc.exe.zip' } else { 'pi-windows-x64.zip' }
        $archivePath = Join-Path (Split-Path -Parent $PSScriptRoot) $name
        $expected = $managerType.GetMethod('BundledArchiveSha256', $flags).Invoke($null, @($kernel))
        if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $expected) { throw "Bundled $kernel SHA-256 mismatch." }
        $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
        try {
            $entry = $managerType.GetMethod('FindExecutableEntry', $flags).Invoke($null, @($kernel, $archive.Entries))
            if (-not $entry -or $entry.Name -match 'sandbox|command-runner') { throw 'Incorrect kernel executable selected.' }
            $destination = Join-Path $bundledRoot $kernel
            $null = $managerType.GetMethod('ExtractKernelArchive', $flags).Invoke($null, @([string]$kernel, $archive, [string]$destination))
        }
        finally { $archive.Dispose() }
        $status = $fixture.Manager.GetStatusAsync($kernel, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
        $moved = $destination + '-verified'
        $boundary = [IO.Path]::GetFullPath($bundledRoot).TrimEnd('\') + '\'
        if (-not [IO.Path]::GetFullPath($destination).StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase) -or
            -not [IO.Path]::GetFullPath($moved).StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Version probe move escaped its test directory.' }
        $move = $managerType.GetMethod('MoveKernelDirectoryAsync', $flags)
        $null = $move.Invoke($null, [object[]]@([string]$destination, [string]$moved, [Threading.CancellationToken]::None)).GetAwaiter().GetResult()
        $null = $move.Invoke($null, [object[]]@([string]$moved, [string]$destination, [Threading.CancellationToken]::None)).GetAwaiter().GetResult()
        "PASS $kernel CLI version $($status.Version); its temporary installation can be moved after verification."
        if ($kernel -eq 'pi' -and $PiInstallationPath) {
            $installed = [IO.Path]::GetFullPath($PiInstallationPath).TrimEnd('\')
            if ((Split-Path -Leaf $installed) -ne 'pi') { throw 'PiInstallationPath must identify a pi installation directory.' }
            $managerType.GetField('_kernelRoot', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($fixture.Manager, (Split-Path -Parent $installed))
            $status = $fixture.Manager.GetStatusAsync('pi', [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            if (-not $status.Installed -or $status.Path -ne (Join-Path $installed 'pi.exe')) { throw 'The requested Pi executable was not selected.' }
            "Testing installed Pi $($status.Version) with temporary configuration and loopback endpoints only."
        }
        $modes = if ($kernel -eq 'pi') { 'responses', 'chat' } else { 'responses' }
        foreach ($mode in $modes) {
            $endpoint = [KernelLoopback]::new()
            try {
                $target = [LocalSecurityAudit.Models.AiTarget]::new()
                $target.Name='Synthetic'; $target.BaseUrl=$endpoint.Url; $target.ApiKey='synthetic-secret'
                $target.Model='gpt-5.6-luna'; $target.Mode=$mode; $target.Effort='medium'
                $progress = [KernelProgress[LocalSecurityAudit.Services.AuditProgressEventArgs]]::new()
                $result = $fixture.Analysis.TestConnectionAsync($target, $kernel, $progress, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
                if (-not $result.Item1) { throw $result.Item2 }
                if ($endpoint.LiteHeader.Length -gt 0) { throw 'Public Responses gateway received an internal Lite header.' }
                "Protocol probe: kernel=$kernel, liteHeader=$($endpoint.LiteHeader), reasoning.context=$($endpoint.ReasoningContext)"
                $expectedPath = if ($mode -eq 'chat') { '/v1/chat/completions' } else { '/v1/responses' }
                if ($endpoint.Requests -ne 1 -or $endpoint.Path -ne $expectedPath -or $endpoint.Model -ne $target.Model -or -not $endpoint.KeyMatches -or $endpoint.Effort -ne 'medium') {
                    throw "$kernel/$mode generated unexpected request parameters: requests=$($endpoint.Requests), path=$($endpoint.Path), model=$($endpoint.Model), effort=$($endpoint.Effort), keyMatched=$($endpoint.KeyMatches)"
                }
                $usage = @($progress.Events.ToArray() | Where-Object HasTokenUsage)[-1]
                if ($usage.InputTokens -ne 120 -or $usage.OutputTokens -ne 30) { throw "$kernel usage was not parsed." }
                "PASS Bundled $kernel/$mode SHA-256, executable selection, isolated provider config, reasoning effort, loopback response and token usage."
                $fixture.Settings.SecurityAuditInstructions = "Synthetic security-audit policy marker`n" + ('规则' * 15000) + "`nEnd-of-security-audit-policy"
                $fixture.Settings.AiKernel = $kernel
                $fixture.Settings.AiTargets.Clear()
                $route = [LocalSecurityAudit.Models.AiTargetSettings]::new()
                $route.BaseUrl = $endpoint.Url; $route.ApiKey = 'synthetic-secret'; $route.Mode = $mode
                $fixture.Settings.AiTargets.Add($route)
                $events = [Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
                $event = [LocalSecurityAudit.Models.SecurityEvent]::new()
                $event.LogName = 'System'; $event.Source = 'SyntheticProvider'; $event.EventId = 41
                $event.Timestamp = [datetime]::UtcNow; $event.Description = 'Synthetic restart'
                $events.Add($event)
                $audit = $fixture.Analysis.AnalyzeEventsAsync($events, $null, [Threading.CancellationToken]::None, $null).GetAwaiter().GetResult()
                if ($audit.Item2 -ne 1 -or -not $endpoint.SawAuditPolicy -or -not $endpoint.SawPolicyEnd -or -not $endpoint.SawAuditContract) { throw "$kernel truncated the security-audit policy or output contract in its actual request." }
                "PASS Bundled $kernel/$mode loads the complete 30,000-character Chinese policy and output contract."
                if ($kernel -eq 'codex') {
                    foreach ($drops in 1, -1) {
                        $broken = [KernelLoopback]::new()
                        try {
                            $broken.DropResponses = $drops
                            $target.BaseUrl = $broken.Url
                            $progress = [KernelProgress[LocalSecurityAudit.Services.AuditProgressEventArgs]]::new()
                            $result = $fixture.Analysis.TestConnectionAsync($target, $kernel, $progress, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
                            $streamUpdates = @($progress.Events.ToArray() | Where-Object { $_.Message.Contains('response.completed') })
                            "Codex stream-drop fixture: drops=$drops, requests=$($broken.Requests), succeeded=$($result.Item1), streamUpdates=$($streamUpdates.Count)"
                            if ($drops -eq 1 -and (-not $result.Item1 -or $broken.Requests -ne 2)) { throw 'Codex did not recover with its native stream retry.' }
                            if ($drops -eq -1 -and ($result.Item1 -or -not $result.Item2.Contains('response.completed'))) { throw 'A stream without response.completed was accepted or lost its failure reason.' }
                            if ($streamUpdates.Count -eq 0) { throw 'Codex stream failures were hidden until process exit.' }
                        }
                        finally { $broken.Dispose() }
                    }
                }
            }
            finally { $endpoint.Dispose() }
        }
        $managerType.GetField('_kernelRoot', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($fixture.Manager, $bundledRoot)
    }
}
finally { Remove-KernelFixture $fixture }
