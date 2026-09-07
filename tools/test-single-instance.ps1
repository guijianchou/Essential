# Starts the app twice and records how many processes remain. Run elevated.
param(
    [string]$ExePath = "$PSScriptRoot\..\bin\x64\Release\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe",
    [string]$LogPath = "$PSScriptRoot\..\ui-review\single-instance.log"
)
$ErrorActionPreference = "Continue"
Get-Process -Name LocalSecurityAudit -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
$exe = (Resolve-Path $ExePath).Path
Set-Content -Path $LogPath -Value "first launch $(Get-Date -Format HH:mm:ss)"
Start-Process -FilePath $exe | Out-Null
Start-Sleep -Seconds 7
$first = @(Get-Process -Name LocalSecurityAudit -ErrorAction SilentlyContinue)
Add-Content -Path $LogPath -Value "processes after first launch: $($first.Count) (ids: $($first.Id -join ','))"
Start-Process -FilePath $exe -ArgumentList "--page=trends" | Out-Null
Start-Sleep -Seconds 6
$second = @(Get-Process -Name LocalSecurityAudit -ErrorAction SilentlyContinue)
Add-Content -Path $LogPath -Value "processes after second launch: $($second.Count) (ids: $($second.Id -join ','))"
$windows = @($second | Where-Object { $_.MainWindowHandle -ne 0 })
Add-Content -Path $LogPath -Value "processes with a window: $($windows.Count)"
Get-Process -Name LocalSecurityAudit -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Add-Content -Path $LogPath -Value "done"
