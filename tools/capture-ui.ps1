# Launches the built app on each requested page, captures a screenshot of the window,
# and closes it again. Used to review the UI without a human at the keyboard.
#
# The app manifest requires administrator rights, so run this script elevated:
#   Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','tools\capture-ui.ps1','-Pages','dashboard,trends'
# Output goes to ui-review\<page>.png and ui-review\capture.log.
param(
    [string]$ExePath = "$PSScriptRoot\..\bin\x64\Release\LocalSecurityAudit-0.3.8\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe",
    [string]$OutDir = "$PSScriptRoot\..\ui-review",
    [string[]]$Pages = @("dashboard"),
    [int]$StartupSeconds = 8
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win32 {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out RECT rect, int size);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
"@

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$logPath = Join-Path $OutDir "capture.log"
function Log([string]$message) {
    $line = "{0:HH:mm:ss} {1}" -f (Get-Date), $message
    Add-Content -Path $logPath -Value $line
    Write-Output $line
}

Set-Content -Path $logPath -Value ""
$exe = (Resolve-Path $ExePath).Path
$pageList = $Pages -split ","

foreach ($page in $pageList) {
    $page = $page.Trim()
    if (-not $page) { continue }
    Get-Process -Name LocalSecurityAudit -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    # "settings:ai" opens the settings page on the AI section and saves settings-ai.png.
    $parts = $page.Split(":")
    $arguments = @("--page=$($parts[0])")
    if ($parts.Length -gt 1) { $arguments += "--section=$($parts[1])" }
    $fileName = ($parts -join "-")
    Log "launching $page ($($arguments -join ' '))"
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru
    Start-Sleep -Seconds $StartupSeconds

    $hwnd = [IntPtr]::Zero
    for ($attempt = 0; $attempt -lt 10 -and $hwnd -eq [IntPtr]::Zero; $attempt++) {
        $candidate = Get-Process -Name LocalSecurityAudit -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowHandle -ne 0 } |
            Select-Object -First 1
        if ($candidate) { $hwnd = $candidate.MainWindowHandle; $process = $candidate }
        else { Start-Sleep -Seconds 1 }
    }
    if ($hwnd -eq [IntPtr]::Zero) {
        Log "window not found for $page (crashed?)"
        continue
    }

    [Win32]::ShowWindow($hwnd, 9) | Out-Null
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        [Win32]::SetForegroundWindow($hwnd) | Out-Null
        Start-Sleep -Milliseconds 400
        if ([Win32]::GetForegroundWindow() -eq $hwnd) { break }
    }
    Start-Sleep -Milliseconds 1200

    $rect = New-Object Win32+RECT
    [Win32]::DwmGetWindowAttribute($hwnd, 9, [ref]$rect, [System.Runtime.InteropServices.Marshal]::SizeOf($rect)) | Out-Null
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    $bitmap = New-Object System.Drawing.Bitmap $width, $height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
    $path = Join-Path $OutDir "$fileName.png"
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    Log "saved $path ($width x $height), foreground=$([Win32]::GetForegroundWindow() -eq $hwnd)"

    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

Get-Process -Name LocalSecurityAudit -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Log "done"
