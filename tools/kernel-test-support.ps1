# Process-level fixtures only: generated executables, synthetic responses and temporary files.
# No installed kernel, user profile, event log or remote endpoint is used.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
public sealed class KernelProgress<T> : IProgress<T>
{
    public ConcurrentQueue<T> Events = new ConcurrentQueue<T>();
    public void Report(T value) { Events.Enqueue(value); }
}
public sealed class KernelModelCapture
{
    public string[] Models = Array.Empty<string>();
    public Action<IReadOnlyList<string>> Callback => models => Models = models.ToArray();
}
public sealed class KernelWorkflowRecorder
{
    public ConcurrentQueue<EventArgs> Events = new ConcurrentQueue<EventArgs>();
    public void Record(object sender, EventArgs value) { Events.Enqueue(value); }
}
'@

function New-KernelFixture($Assembly) {
    $root = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ('lsa-kernel-regression-' + [guid]::NewGuid().ToString('N'))))
    $null = [IO.Directory]::CreateDirectory($root)
    $source = Join-Path $root 'kernel.cs'
    @'
using System;
using System.IO;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
class SyntheticKernel
{
    static JavaScriptSerializer json = new JavaScriptSerializer();
    static string Arg(string[] args, string key) { int i = Array.IndexOf(args, key); return i >= 0 && i + 1 < args.Length ? args[i + 1] : ""; }
    static string Text(Dictionary<string,object> map, string key) { return map.ContainsKey(key) ? Convert.ToString(map[key]) : ""; }
    static bool Flag(Dictionary<string,object> map, string key) { return map.ContainsKey(key) && Convert.ToBoolean(map[key]); }
    static void Emit(object value) { Console.WriteLine(json.Serialize(value)); Console.Out.Flush(); }
    static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (args.Contains("--version")) { Console.WriteLine("synthetic-kernel 1.0"); return 0; }
        if (args.Contains("--bundled"))
        {
            Emit(new { models = new[] { new { slug = "gpt-5.6-luna", use_responses_lite = true } } });
            return 0;
        }
        var plan = json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Environment.GetEnvironmentVariable("LSA_TEST_PLAN")));
        bool codex = args.FirstOrDefault() == "exec";
        string home = Environment.GetEnvironmentVariable(codex ? "CODEX_HOME" : "PI_CODING_AGENT_DIR");
        string config = File.ReadAllText(Path.Combine(home, codex ? "config.toml" : "models.json"));
        string model = codex ? Regex.Match(config, "(?m)^model = \"([^\"]+)\"").Groups[1].Value : Arg(args, "--model");
        string input = codex ? Console.In.ReadToEnd() : File.ReadAllText(args.Last().Substring(1));
        string policy = File.ReadAllText(codex ? Path.Combine(Environment.CurrentDirectory, "AGENTS.md") : Arg(args, "--append-system-prompt"));
        string captures = Text(plan, "CaptureDir");
        Directory.CreateDirectory(captures);
        File.WriteAllText(Path.Combine(captures, "request-" + Process.GetCurrentProcess().Id + ".json"), json.Serialize(new {
            Kernel = codex ? "codex" : "pi", Model = model, Home = home, Config = config,
            Pid = Process.GetCurrentProcess().Id, Input = input, Policy = policy,
            SecretInArguments = args.Any(arg => arg.Contains("synthetic-secret")),
            KeyMatches = Environment.GetEnvironmentVariable(codex ? "LOCAL_SECURITY_AUDIT_API_KEY" : "OPENAI_API_KEY") == "synthetic-secret"
        }));
        if (plan.ContainsKey("DelayMs")) Thread.Sleep(Convert.ToInt32(plan["DelayMs"]));
        if (Flag(plan, "Reconnect"))
        {
            Emit(new { type = "turn.started" });
            Emit(new { type = "error", message = "Reconnecting... 1/5: stream closed before response.completed synthetic-secret" });
            for (int i = 0; i < 1500 && !File.Exists(Path.Combine(captures, "continue")); i++) Thread.Sleep(20);
        }
        string block = Text(plan, "BlockInput");
        if (block.Length > 0 && input.Contains(block))
        {
            File.WriteAllText(Path.Combine(captures, "blocked"), "waiting");
            for (int i = 0; i < 1500 && !File.Exists(Path.Combine(captures, "continue")); i++) Thread.Sleep(20);
        }
        if (Flag(plan, "FailureAll") || Flag(plan, "FailureMain") && config.Contains("primary.invalid"))
        {
            string message = "Synthetic rejection synthetic-secret";
            if (codex) Emit(new { type = "turn.failed", error = new { message = message } });
            else Emit(new { type = "message_end", message = new { role = "assistant", stopReason = "error", errorMessage = message } });
            return Flag(plan, "ZeroExitFailure") ? 0 : 1;
        }
        string payload = plan.ContainsKey("Payload") ? Text(plan, "Payload") : "{\"issues\":[]}";
        if (Flag(plan, "Translate"))
        {
            var data = json.Deserialize<Dictionary<string,object>>(input);
            var translated = new List<object>();
            foreach (Dictionary<string,object> item in (IEnumerable)data["issues"])
                translated.Add(new { key = Text(item, "key"), title = "Translated finding", description = "Synthetic description", rootCause = "Unknown cause", recommendation = "Review the source", titleZh = "测试问题", descriptionZh = "合成描述", rootCauseZh = "原因未知", recommendationZh = "核对来源" });
            payload = json.Serialize(new { issues = translated });
        }
        string actual = Text(plan, "ActualModel");
        if (actual.Length == 0) actual = model;
        if (codex)
        {
            Emit(new { type = "item.completed", item = new { type = "agent_message", text = payload } });
            File.WriteAllText(Arg(args, "--output-last-message"), payload);
            if (!Flag(plan, "Incomplete")) Emit(new { type = "turn.completed", model = actual, usage = new { input_tokens = 120, cached_input_tokens = 20, output_tokens = 30 } });
        }
        else
        {
            Emit(new { type = "message_end", message = new { role = "assistant", model = actual, stopReason = Flag(plan, "Incomplete") ? "length" : "stop", content = new[] { new { type = "text", text = payload } }, usage = new { input = 100, cacheRead = 20, cacheWrite = 0, output = 30 } } });
            Emit(new { type = "agent_end", messages = new object[0] });
        }
        return 0;
    }
}
'@ | Set-Content -LiteralPath $source -Encoding utf8BOM
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $executable = Join-Path $root 'kernel.exe'
    $compilerOutput = & $compiler /nologo /target:exe /reference:System.Web.Extensions.dll "/out:$executable" $source 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Synthetic kernel compilation failed: $compilerOutput" }
    foreach ($kernel in 'codex', 'pi') {
        $destination = Join-Path $root "kernels\$kernel"
        $null = [IO.Directory]::CreateDirectory($destination)
        Copy-Item -LiteralPath $executable -Destination (Join-Path $destination "$kernel.exe")
        if ($kernel -eq 'pi') {
            $null = [IO.Directory]::CreateDirectory((Join-Path $destination 'theme'))
            foreach ($file in 'package.json','theme/dark.json','theme/light.json') {
                '{}' | Set-Content -LiteralPath (Join-Path $destination $file) -Encoding utf8
            }
        }
    }
    $flags = [Reflection.BindingFlags]'NonPublic,Instance,Static'
    $settingsType = $Assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
    $settingsService = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($settingsType)
    $settings = [LocalSecurityAudit.Models.AppSettings]::new()
    $settings.AutoScanEnabled = $false
    $settings.EnableCaching = $false
    $settings.EnableSmartFiltering = $false
    $settings.MaxConcurrentAnalysis = 1
    $settingsType.GetProperty('Current').SetValue($settingsService, $settings)
    $settingsType.GetField('<ActiveMode>k__BackingField', $flags).SetValue($settingsService, 'extended')
    $loggerType = $Assembly.GetType('LocalSecurityAudit.Services.DiagnosticLogService', $true)
    $logger = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($loggerType)
    $loggerType.GetField('_settingsService', $flags).SetValue($logger, $settingsService)
    $managerType = $Assembly.GetType('LocalSecurityAudit.Services.KernelManagerService', $true)
    $manager = [Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($managerType)
    $managerType.GetField('_kernelRoot', $flags).SetValue($manager, (Join-Path $root 'kernels'))
    $analysis = [LocalSecurityAudit.Services.AiAnalysisService]::new($settingsService, $logger, $manager)
    return [pscustomobject]@{ Root=$root; Settings=$settings; SettingsService=$settingsService; Logger=$logger; Analysis=$analysis; Manager=$manager; PreviousPlan=$env:LSA_TEST_PLAN }
}

function Set-KernelPlan($Fixture, [hashtable]$Plan = @{}) {
    $capture = Join-Path $Fixture.Root ([guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($capture)
    $Plan.CaptureDir = $capture
    $env:LSA_TEST_PLAN = Join-Path $Fixture.Root 'plan.json'
    $Plan | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $env:LSA_TEST_PLAN -Encoding utf8
    return $capture
}

function Remove-KernelFixture($Fixture) {
    $env:LSA_TEST_PLAN = $Fixture.PreviousPlan
    $root = [IO.Path]::GetFullPath($Fixture.Root)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $root.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $root) -notmatch '^lsa-kernel-regression-[a-f0-9]{32}$') {
        throw 'Refusing cleanup outside the generated kernel test directory.'
    }
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}
