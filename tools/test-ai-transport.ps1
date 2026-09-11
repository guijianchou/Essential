# Synthetic executable integration; no real kernels, settings, event logs or network.
param([string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll")
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
. "$PSScriptRoot\kernel-test-support.ps1"
$fixture = New-KernelFixture $assembly
$directory = Split-Path -Parent $assembly.Location
foreach ($dependency in 'Microsoft.Data.Sqlite.dll', 'SQLitePCLRaw.batteries_v2.dll') {
    $null = [Reflection.Assembly]::LoadFrom((Join-Path $directory $dependency))
}
$sqlitePath = Join-Path $directory 'e_sqlite3.dll'
if (-not (Test-Path -LiteralPath $sqlitePath)) { $sqlitePath = Join-Path $directory 'runtimes/win-x64/native/e_sqlite3.dll' }
$null = [Runtime.InteropServices.NativeLibrary]::Load($sqlitePath)
$storage = [LocalSecurityAudit.Services.DataStorageService]::CreateAsync('extended', $fixture.Root).GetAwaiter().GetResult()
$flags = [Reflection.BindingFlags]'NonPublic,Instance,Static'
$script:passed = 0; $script:failed = 0
function Assert-True([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Test-Case([string]$Name, [scriptblock]$Action) {
    try { $null = & $Action; $script:passed++; "PASS $Name" }
    catch { $script:failed++; "FAIL $Name`: $($_.Exception.GetBaseException().Message)"; $_.ScriptStackTrace }
}
function Set-Routes([string]$Model = 'gpt-5.6-luna', [string]$Fallback = '') {
    $fixture.Settings.AiTargets.Clear(); $fixture.Analysis.ClearCache()
    $fixture.Settings.EnableCaching = $false; $fixture.Settings.MaxConcurrentAnalysis = 1
    foreach ($name in 'Main', 'Fallback') {
        if ($name -eq 'Fallback' -and -not $Fallback) { continue }
        $route = [LocalSecurityAudit.Models.AiTargetSettings]::new()
        $route.Name = $name; $route.ApiKey = 'synthetic-secret'
        $route.BaseUrl = if ($name -eq 'Main') { 'https://primary.invalid' } else { 'https://fallback.invalid/v1' }
        $route.Model = if ($name -eq 'Main') { $Model } else { $Fallback }
        $fixture.Settings.AiTargets.Add($route)
    }
}
function New-Target {
    $target = [LocalSecurityAudit.Models.AiTarget]::new()
    $target.Name = 'Main'; $target.BaseUrl = 'https://primary.invalid'; $target.ApiKey = 'synthetic-secret'
    $target.Model = 'gpt-5.6-luna'; $target.Mode = 'responses'; $target.Effort = 'medium'
    return $target
}
function New-Events([int]$Count = 1) {
    $events = [Collections.Generic.List[LocalSecurityAudit.Models.SecurityEvent]]::new()
    for ($i=0; $i -lt $Count; $i++) {
        $event = [LocalSecurityAudit.Models.SecurityEvent]::new()
        $event.LogName='System'; $event.Source='SyntheticProvider'; $event.EventId=41
        $event.EventRecordId=100+$i; $event.Timestamp=[datetime]::UtcNow.AddMinutes(-1)
        $event.Description='Synthetic interruption'; $event.Severity='Critical'; $events.Add($event)
    }
    return ,$events
}
function Wait-Capture([string]$Directory) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (@(Get-ChildItem -LiteralPath $Directory -Filter 'request-*.json').Count -eq 0 -and $watch.Elapsed.TotalSeconds -lt 5) { Start-Sleep -Milliseconds 20 }
    Assert-True (@(Get-ChildItem -LiteralPath $Directory -Filter 'request-*.json').Count -gt 0) 'The synthetic process never started.'
}
$finding = '{"issues":[{"key":"synthetic_restart","eventRef":"event-0","relatedEventRefs":["event-0"],"title":"Synthetic restart","description":"A supplied synthetic event describes a restart.","rootCause":"The cause is unknown.","recommendation":"Review the supplied record.","titleZh":"合成重启","descriptionZh":"合成事件描述了一次重启。","rootCauseZh":"原因未知。","recommendationZh":"核对提供的记录。","severity":"Low","confidence":"High","category":"System","affected":"synthetic-host"}]}'
try {
    foreach ($kernel in 'codex','pi') {
        Test-Case "$kernel tests the selected kernel and isolates configuration" {
            Set-Routes
            $fixture.Settings.AiKernel = if ($kernel -eq 'codex') { 'pi' } else { 'codex' }
            $capture = Set-KernelPlan $fixture
            $progress = [KernelProgress[LocalSecurityAudit.Services.AuditProgressEventArgs]]::new()
            $result = $fixture.Analysis.TestConnectionAsync((New-Target), $kernel, $progress, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
            Assert-True $result.Item1 $result.Item2
            $request = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $capture -Filter 'request-*.json')[0].FullName -Raw | ConvertFrom-Json
            Assert-True ($request.Kernel -eq $kernel -and $request.KeyMatches -and -not $request.SecretInArguments) 'Selected kernel or isolated credentials were lost.'
            Assert-True (-not (Test-Path -LiteralPath $request.Home)) 'Temporary configuration survived completion.'
            $usage = @($progress.Events.ToArray() | Where-Object HasTokenUsage)[-1]
            Assert-True ($usage.InputTokens -eq 120 -and $usage.OutputTokens -eq 30) 'Token usage did not reach progress.'
        }
        Test-Case "$kernel consumes completed text and preserves the actual model" {
            Set-Routes; $fixture.Settings.AiKernel = $kernel
            $capture = Set-KernelPlan $fixture @{Payload=$finding;ActualModel='gpt-5.6-terra'}
            $models = [KernelModelCapture]::new()
            $result = $fixture.Analysis.AnalyzeEventsAsync((New-Events), $null, [Threading.CancellationToken]::None, $models.Callback).GetAwaiter().GetResult()
            Assert-True ($result.Item1.Count -eq 1 -and $result.Item2 -eq 1 -and $result.Item1[0].AnalysisModel -eq 'gpt-5.6-terra') 'Kernel text or model ownership was incorrect.'
            Assert-True ($models.Models.Count -eq 1 -and $models.Models[0] -eq 'gpt-5.6-terra') 'Actual model was not recorded.'
        }
        Test-Case "$kernel rejects incomplete output, invalid JSON and failure with exit code zero" {
            foreach ($plan in @(@{Incomplete=$true}, @{FailureAll=$true;ZeroExitFailure=$true}, @{Payload='not json'})) {
                $null = Set-KernelPlan $fixture $plan
                $result = $fixture.Analysis.TestConnectionAsync((New-Target), $kernel, $null, [Threading.CancellationToken]::None).GetAwaiter().GetResult()
                Assert-True (-not $result.Item1 -and -not $result.Item2.Contains('synthetic-secret')) 'Invalid output passed or exposed credentials.'
            }
        }
    }
    Test-Case 'A zero-finding fallback retains its actual lower model' {
        Set-Routes 'gpt-6-astra' 'gpt-5.6-luna'; $fixture.Settings.AiKernel='codex'
        $capture = Set-KernelPlan $fixture @{FailureMain=$true}; $models=[KernelModelCapture]::new()
        $result = $fixture.Analysis.AnalyzeEventsAsync((New-Events), $null, [Threading.CancellationToken]::None, $models.Callback).GetAwaiter().GetResult()
        Assert-True ($result.Item1.Count -eq 0 -and $models.Models.Count -eq 1 -and $models.Models[0] -eq 'gpt-5.6-luna') 'Fallback promoted the requested model.'
        Assert-True (@(Get-ChildItem -LiteralPath $capture -Filter 'request-*.json').Count -eq 2) 'Fallback did not use one process per route.'
    }
    Test-Case 'Codex publishes redacted reconnect status before exit and accepts native recovery' {
        Set-Routes
        $capture = Set-KernelPlan $fixture @{Reconnect=$true}
        $progress = [KernelProgress[LocalSecurityAudit.Services.AuditProgressEventArgs]]::new()
        $task = $fixture.Analysis.TestConnectionAsync((New-Target), 'codex', $progress, [Threading.CancellationToken]::None)
        try {
            $watch = [Diagnostics.Stopwatch]::StartNew()
            do {
                $updates = @($progress.Events.ToArray() | Where-Object { $_.Message.Contains('response.completed') })
                if ($updates.Count -eq 0) { Start-Sleep -Milliseconds 20 }
            } while ($updates.Count -eq 0 -and $watch.Elapsed.TotalSeconds -lt 5)
            Assert-True ($updates.Count -gt 0 -and -not $task.IsCompleted) 'Reconnect status arrived only after completion.'
            Assert-True ($updates[-1].State -eq 'Active' -and -not $updates[-1].Message.Contains('synthetic-secret')) 'Reconnect prematurely failed the stage or exposed the key.'
        }
        finally { 'continue' | Set-Content -LiteralPath (Join-Path $capture 'continue') }
        $result = $task.GetAwaiter().GetResult()
        Assert-True $result.Item1 $result.Item2
    }
    Test-Case 'Cached empty findings retain the completed model rather than the requested model' {
        Set-Routes 'gpt-6-astra'; $fixture.Settings.AiKernel='codex'; $fixture.Settings.EnableCaching=$true
        $capture=Set-KernelPlan $fixture @{ActualModel='gpt-5.6-terra'}; $events=New-Events
        foreach ($iteration in 1,2) {
            $models=[KernelModelCapture]::new()
            $result=$fixture.Analysis.AnalyzeEventsAsync($events,$null,[Threading.CancellationToken]::None,$models.Callback).GetAwaiter().GetResult()
            Assert-True ($result.Item1.Count -eq 0 -and $models.Models.Count -eq 1 -and $models.Models[0] -eq 'gpt-5.6-terra') 'Cache changed the completed model.'
        }
        Assert-True (@(Get-ChildItem -LiteralPath $capture -Filter 'request-*.json').Count -eq 1) 'The same completed batch was not cached.'
    }
    Test-Case 'Incomplete Pi installations require a new download' {
        $theme=Join-Path $fixture.Root 'kernels/pi/theme/dark.json'
        [IO.File]::Delete($theme)
        try { Assert-True (-not $fixture.Manager.GetStatus('pi').Installed) 'A resource-less Pi executable was marked installed.' }
        finally { '{}' | Set-Content -LiteralPath $theme -Encoding utf8 }
    }
    Test-Case 'Cancellation kills the child and removes temporary settings without failover' {
        Set-Routes 'gpt-6-astra' 'gpt-5.6-luna'
        $capture=Set-KernelPlan $fixture @{DelayMs=10000}; $cancel=[Threading.CancellationTokenSource]::new()
        try {
            $task=$fixture.Analysis.AnalyzeEventsAsync((New-Events), $null, $cancel.Token, $null)
            Wait-Capture $capture
            $request=Get-Content -LiteralPath (Get-ChildItem -LiteralPath $capture -Filter 'request-*.json')[0].FullName -Raw | ConvertFrom-Json
            $cancel.Cancel(); $canceled=$false
            try { $null=$task.WaitAsync([timespan]::FromSeconds(5)).GetAwaiter().GetResult() }
            catch { $canceled=$_.Exception.GetBaseException() -is [OperationCanceledException] }
            Assert-True $canceled 'Cancellation did not propagate.'
            Assert-True (-not (Test-Path -LiteralPath $request.Home)) 'Canceled configuration survived.'
            Assert-True (@(Get-Process -Id $request.Pid -ErrorAction SilentlyContinue).Count -eq 0) 'The canceled process survived.'
            Assert-True (@(Get-ChildItem -LiteralPath $capture -Filter 'request-*.json').Count -eq 1) 'Cancellation started fallback.'
        }
        finally { $cancel.Dispose() }
    }
    Test-Case 'Switching kernels does not reuse another kernel response; clearing cache forces a fresh request' {
        Set-Routes; $fixture.Settings.EnableCaching = $true
        $events = New-Events
        $capture = Set-KernelPlan $fixture
        $fixture.Settings.AiKernel = 'codex'
        $null = $fixture.Analysis.AnalyzeEventsAsync($events, $null, [Threading.CancellationToken]::None, $null).GetAwaiter().GetResult()
        $null = $fixture.Analysis.AnalyzeEventsAsync($events, $null, [Threading.CancellationToken]::None, $null).GetAwaiter().GetResult()
        Assert-True (@(Get-ChildItem -LiteralPath $capture -Filter 'request-*.json').Count -eq 1) 'An identical request did not use the cache.'
        $fixture.Settings.AiKernel = 'pi'
        $null = $fixture.Analysis.AnalyzeEventsAsync($events, $null, [Threading.CancellationToken]::None, $null).GetAwaiter().GetResult()
        $requests = @(Get-ChildItem -LiteralPath $capture -Filter 'request-*.json' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json })
        Assert-True ($requests.Count -eq 2 -and @($requests | Where-Object Kernel -eq 'pi').Count -eq 1) 'Pi reused a cached Codex result instead of running.'
        $fixture.Analysis.ClearCache()
        $null = $fixture.Analysis.AnalyzeEventsAsync($events, $null, [Threading.CancellationToken]::None, $null).GetAwaiter().GetResult()
        Assert-True (@(Get-ChildItem -LiteralPath $capture -Filter 'request-*.json').Count -eq 3) 'Reanalysis cache reset failed to make a fresh request.'
        $fixture.Settings.EnableCaching = $false
    }
    Test-Case 'Stopping or disposing the scheduler cancels and drains an active connection test' {
        foreach ($shutdown in 'stop', 'dispose') {
            Set-Routes
            $capture=Set-KernelPlan $fixture @{DelayMs=10000}
            $scheduler=[LocalSecurityAudit.Services.AuditSchedulerService]::new($null,$fixture.Analysis,$storage,$fixture.SettingsService,$fixture.Logger)
            try {
                $task=$scheduler.TestConnectionAsync((New-Target),'codex')
                Wait-Capture $capture
                $request=Get-Content -LiteralPath (Get-ChildItem -LiteralPath $capture -Filter 'request-*.json')[0].FullName -Raw | ConvertFrom-Json
                if ($shutdown -eq 'stop') {
                    $null=$scheduler.StopAsync([Threading.CancellationToken]::None).WaitAsync([timespan]::FromSeconds(5)).GetAwaiter().GetResult()
                }
                else { $scheduler.Dispose() }
                $result=$task.WaitAsync([timespan]::FromSeconds(5)).GetAwaiter().GetResult()
                Assert-True (-not $result.Item1 -and -not $scheduler.IsScanning) 'Shutdown reported success or left the scheduler busy.'
                Assert-True (-not (Test-Path -LiteralPath $request.Home)) 'Shutdown left temporary connection settings.'
                Assert-True (@(Get-Process -Id $request.Pid -ErrorAction SilentlyContinue).Count -eq 0) 'Shutdown left the kernel running.'
                $retry=$scheduler.TestConnectionAsync((New-Target),'codex').GetAwaiter().GetResult()
                Assert-True (-not $retry.Item1 -and @(Get-ChildItem -LiteralPath $capture -Filter 'request-*.json').Count -eq 1) 'A stopping scheduler accepted a new connection test.'
            }
            finally { if ($shutdown -eq 'stop') { $scheduler.Dispose() } }
        }
    }
    Test-Case 'Settings tests show progress, tokens and success or failure without saving an audit' {
        Set-Routes; $null=Set-KernelPlan $fixture
        $scheduler=[LocalSecurityAudit.Services.AuditSchedulerService]::new($null,$fixture.Analysis,$storage,$fixture.SettingsService,$fixture.Logger)
        try {
            $recorder=[KernelWorkflowRecorder]::new(); $event=$scheduler.GetType().GetEvent('AuditProgress')
            $handler=[Delegate]::CreateDelegate($event.EventHandlerType,$recorder,$recorder.GetType().GetMethod('Record'))
            $event.AddEventHandler($scheduler,$handler)
            $result=$scheduler.TestConnectionAsync((New-Target),'pi').GetAwaiter().GetResult()
            Assert-True $result.Item1 $result.Item2
            $type=$assembly.GetType('LocalSecurityAudit.ViewModels.MainViewModel',$true)
            $view=[Runtime.CompilerServices.RuntimeHelpers]::GetUninitializedObject($type)
            $type.GetField('_scheduler',$flags).SetValue($view,$scheduler)
            $steps=[Collections.Generic.List[LocalSecurityAudit.ViewModels.ScanStep]]::new()
            foreach ($stage in [Enum]::GetValues([LocalSecurityAudit.Services.AuditStage])) { $steps.Add([LocalSecurityAudit.ViewModels.ScanStep]::new($stage)) }
            $type.GetField('<Steps>k__BackingField',$flags).SetValue($view,$steps)
            foreach ($progress in $recorder.Events.ToArray()) { $null=$type.GetMethod('ApplyProgress',$flags).Invoke($view,@($progress)) }
            Assert-True ($view.IsWorkflowVisible -and $view.IsWorkflowComplete -and $view.WorkflowPercent -eq 100 -and $view.VisibleSteps.Count -eq 3) 'Connection workflow was hidden or incomplete.'
            Assert-True (-not $view.HasSavedResult -and $view.CompactTokenCountText -eq '150') 'Connection testing fabricated a save or lost tokens.'
            $usage = $storage.GetTokenUsageTotals('day', [datetime]::Now)
            Assert-True ($usage.Item1 -eq 120 -and $usage.Item2 -eq 30) 'Connection-test token usage was not persisted exactly once.'
            $estimate = [LocalSecurityAudit.Services.AuditProgressEventArgs]::new('Analyze', 'Active', 'Synthetic estimate')
            $estimate.EstimatedInputTokens = 10000
            $scheduler.GetType().GetMethod('ReportProgress', $flags).Invoke($scheduler, @($estimate))
            $usage = $storage.GetTokenUsageTotals('day', [datetime]::Now)
            Assert-True ($usage.Item1 + $usage.Item2 -eq 150) 'Estimated usage was added to persisted totals.'
            $recorder.Events.Clear(); $null=Set-KernelPlan $fixture @{FailureAll=$true}
            $result=$scheduler.TestConnectionAsync((New-Target),'codex').GetAwaiter().GetResult()
            foreach ($progress in $recorder.Events.ToArray()) { $null=$type.GetMethod('ApplyProgress',$flags).Invoke($view,@($progress)) }
            Assert-True (-not $result.Item1 -and $view.IsWorkflowFailed -and $view.IsWorkflowVisible -and -not $scheduler.IsScanning) 'A failed test disappeared or left the app busy.'
            $usage = $storage.GetTokenUsageTotals('day', [datetime]::Now)
            Assert-True ($usage.Item1 + $usage.Item2 -eq 150) 'Failure without reported usage fabricated tokens.'
            $null=Set-KernelPlan $fixture @{Payload='invalid-json'}
            $result=$scheduler.TestConnectionAsync((New-Target),'pi').GetAwaiter().GetResult()
            $usage = $storage.GetTokenUsageTotals('day', [datetime]::Now)
            Assert-True (-not $result.Item1 -and $usage.Item1 + $usage.Item2 -eq 300) 'A response that failed validation lost its reported usage.'
        }
        finally { $scheduler.Dispose() }
    }
}
finally { [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools(); Remove-KernelFixture $fixture }
"Kernel transport tests: $script:passed passed, $script:failed failed."
if ($script:failed -gt 0) { exit 1 }
