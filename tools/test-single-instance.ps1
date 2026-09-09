# Headless tests of the actual guard with private random keys and temporary files.
# Never launches/kills the audit app, reads user settings, collects logs or requests UAC.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\bin\x64\Release\LocalSecurityAudit-0.3.8\net8.0-windows10.0.19041.0\LocalSecurityAudit.dll",
    [switch]$Child,
    [string]$Key,
    [string]$ResultPath,
    [string]$ReadyPath,
    [string]$StopPath,
    [switch]$Abandon
)
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$guardType = $assembly.GetType('LocalSecurityAudit.Helpers.SingleInstanceGuard', $true)
$flags = [Reflection.BindingFlags]'NonPublic,Instance'
function New-Guard([string]$Name) { return $guardType.GetConstructor($flags, $null, @([string]), $null).Invoke(@($Name)) }
function Acquire($Guard) { return $guardType.GetMethod('TryAcquire', $flags).Invoke($Guard, @()) }
function Activate($Guard) { return $guardType.GetMethod('ActivateExisting', $flags).Invoke($Guard, @()) }
function Assert-True([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }

if ($Child) {
    $guard = New-Guard $Key
    try {
        $primary = Acquire $guard
        $activated = if (-not $primary) { Activate $guard } else { $false }
        if ($Abandon -and $primary) {
            [IO.File]::WriteAllText($ReadyPath, 'ready')
            $deadline = [datetime]::UtcNow.AddSeconds(15)
            while (-not (Test-Path -LiteralPath $StopPath) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }
            [Environment]::Exit(0) # Intentionally abandon only this test key.
        }
        [IO.File]::WriteAllText($ResultPath, (@{Primary=$primary;Activated=$activated} | ConvertTo-Json -Compress))
    }
    finally { $guard.Dispose() }
    exit 0
}

Add-Type -TypeDefinition @'
using System.Threading;
public sealed class ActivationCounter
{
    private int count;
    public int Count => Volatile.Read(ref count);
    public void Record() => Interlocked.Increment(ref count);
}
'@
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('lsa-instance-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
$testKey = 'synthetic-' + [guid]::NewGuid().ToString('N')
$shellPath = (Get-Process -Id $PID).Path
$children = [Collections.Generic.List[Diagnostics.Process]]::new()
$script:passed = 0
$script:failed = 0
function Test-Case([string]$Name, [scriptblock]$Action) {
    try { $null = & $Action; $script:passed++; "PASS $Name" }
    catch { $script:failed++; ("FAIL {0}: {1}" -f $Name, $_.Exception.GetBaseException().Message) }
}
function Start-TestChild([string]$Name, [string]$DllPath = $assembly.Location, [switch]$AbandonOwner) {
    $resultFile = Join-Path $testRoot ($Name + '.json')
    $arguments = @('-NoProfile', '-File', ('"{0}"' -f $PSCommandPath), '-Child', '-Key', $testKey,
        '-AssemblyPath', ('"{0}"' -f $DllPath), '-ResultPath', ('"{0}"' -f $resultFile))
    if ($AbandonOwner) {
        $arguments += @('-Abandon', '-ReadyPath', ('"{0}"' -f (Join-Path $testRoot 'ready')),
            '-StopPath', ('"{0}"' -f (Join-Path $testRoot 'stop')))
    }
    $process = Start-Process -FilePath $shellPath -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $testRoot ($Name + '.stderr')) -RedirectStandardOutput (Join-Path $testRoot ($Name + '.stdout'))
    $children.Add($process)
    return [pscustomobject]@{Process=$process;Result=$resultFile;Error=(Join-Path $testRoot ($Name + '.stderr'))}
}
function Read-Child($Run) {
    Assert-True ($Run.Process.WaitForExit(15000)) 'A bounded test helper timed out.'
    Assert-True ($Run.Process.ExitCode -eq 0) ('Test helper failed: ' + (Get-Content -LiteralPath $Run.Error -Raw))
    return Get-Content -LiteralPath $Run.Result -Raw | ConvertFrom-Json
}

$owner = New-Guard $testKey
try {
    $counter = [ActivationCounter]::new()
    Test-Case 'One primary owns a path- and mode-independent key' {
        Assert-True (Acquire $owner) 'First owner was rejected.'
        $action = [Action]::CreateDelegate([Action], $counter, $counter.GetType().GetMethod('Record'))
        $guardType.GetMethod('Listen', $flags).Invoke($owner, @($action))
    }
    Test-Case 'A second process activates the owner and cannot become another primary' {
        $result = Read-Child (Start-TestChild 'second')
        Assert-True (-not $result.Primary -and $result.Activated) 'Duplicate process became primary or could not signal.'
        $deadline = [datetime]::UtcNow.AddSeconds(2)
        while ($counter.Count -eq 0 -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }
        Assert-True ($counter.Count -gt 0) 'Existing-window activation was not delivered.'
    }
    Test-Case 'A different build directory shares the same primary' {
        $copyPath = Join-Path $testRoot 'LocalSecurityAudit.dll'
        # The assembly's Windows App SDK module initializer needs its bundled DLLs.
        foreach ($dependency in (Get-ChildItem -LiteralPath (Split-Path -Parent $assembly.Location) -File -Filter '*.dll')) {
            Copy-Item -LiteralPath $dependency.FullName -Destination (Join-Path $testRoot $dependency.Name)
        }
        $result = Read-Child (Start-TestChild 'other-build' $copyPath)
        Assert-True (-not $result.Primary -and $result.Activated) 'Executable directory split the instance key.'
    }
    Test-Case 'Concurrent duplicate launches all leave the owner in place' {
        $runs = @(1..4 | ForEach-Object { Start-TestChild ('parallel-' + $_) })
        foreach ($run in $runs) {
            $result = Read-Child $run
            Assert-True (-not $result.Primary) 'A concurrent duplicate became primary.'
        }
    }
    Test-Case 'Releasing for an elevation handoff or exit allows one replacement' {
        $guardType.GetMethod('Release', $flags).Invoke($owner, @())
        $result = Read-Child (Start-TestChild 'replacement')
        Assert-True $result.Primary 'The instance key leaked after release.'
        Assert-True (Acquire $owner) 'Canceled handoff could not reacquire the key.'
        $guardType.GetMethod('Release', $flags).Invoke($owner, @())
    }
    Test-Case 'An abandoned owner can be recovered without touching another process' {
        $run = Start-TestChild 'abandon' -AbandonOwner
        $deadline = [datetime]::UtcNow.AddSeconds(10)
        while (-not (Test-Path -LiteralPath (Join-Path $testRoot 'ready')) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }
        Assert-True (Test-Path -LiteralPath (Join-Path $testRoot 'ready')) 'Abandonment helper did not start.'
        Assert-True (-not (Acquire $owner)) 'An active owner was not exclusive.'
        [IO.File]::WriteAllText((Join-Path $testRoot 'stop'), 'stop')
        Assert-True ($run.Process.WaitForExit(5000)) 'Abandonment helper did not stop.'
        Assert-True (Acquire $owner) 'An abandoned key could not be recovered.'
    }
}
finally {
    $owner.Dispose()
    foreach ($process in $children) {
        if (-not $process.HasExited) { $process.Kill(); $null = $process.WaitForExit(5000) }
        $process.Dispose()
    }
}
"$script:passed passed; $script:failed failed. Private test keys only; no audit app or real-data access."
if ($script:failed -gt 0) { exit 1 }
