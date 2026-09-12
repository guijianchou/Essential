$ErrorActionPreference = 'Stop'

Write-Host "=== W6 Regression Test Suite ===" -ForegroundColor Cyan
Write-Host ""

$script:passed = 0
$script:failed = 0
$toolsDir = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent $toolsDir

function Test-Script {
    param(
        [string]$Name,
        [string]$ScriptPath
    )

    Write-Host "Running: $Name" -ForegroundColor Yellow

    if (-not (Test-Path $ScriptPath)) {
        Write-Host "  [SKIP] Script not found: $ScriptPath" -ForegroundColor DarkGray
        return
    }

    try {
        $result = & pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:passed++
        } else {
            Write-Host "  [FAIL] $Name (exit code: $exitCode)" -ForegroundColor Red
            $script:failed++
        }
    } catch {
        Write-Host "  [FAIL] $Name - Exception: $($_.Exception.Message)" -ForegroundColor Red
        $script:failed++
    }

    Write-Host ""
}

function Test-Build {
    param(
        [string]$Name
    )

    Write-Host "Running: $Name" -ForegroundColor Yellow

    Push-Location $repoRoot
    try {
        $output = dotnet build -c Release -p:Platform=x64 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:passed++
        } else {
            Write-Host "  [FAIL] $Name (exit code: $exitCode)" -ForegroundColor Red
            Write-Host "  Build output:" -ForegroundColor DarkGray
            $output | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            $script:failed++
        }
    } catch {
        Write-Host "  [FAIL] $Name - Exception: $($_.Exception.Message)" -ForegroundColor Red
        $script:failed++
    } finally {
        Pop-Location
    }

    Write-Host ""
}

# Run build verification first
Test-Build "dotnet build -c Release -p:Platform=x64"

# Run existing tests
Test-Script "Single Instance" (Join-Path $toolsDir "test-single-instance.ps1")
Test-Script "Token Usage" (Join-Path $toolsDir "test-token-usage.ps1")

# Run new optimization tests
Test-Script "Optimization Safety" (Join-Path $toolsDir "test-optimization-safety.ps1")
Test-Script "File Services" (Join-Path $toolsDir "test-file-services.ps1")
Test-Script "Task AI Client" (Join-Path $toolsDir "test-task-ai-client.ps1")

# Summary
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Passed: $script:passed" -ForegroundColor Green
Write-Host "Failed: $script:failed" -ForegroundColor $(if ($script:failed -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($script:failed -gt 0) {
    Write-Host "Regression suite FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Regression suite PASSED" -ForegroundColor Green
    exit 0
}
