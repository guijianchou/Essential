@echo off
setlocal
cd /d "%~dp0"
echo LocalSecurityAudit 0.3.8
echo Build and launch normally. Assistant mode needs no API key or administrator rights.
echo [1/3] Restoring packages...
dotnet restore -p:Platform=x64
if errorlevel 1 goto failed
echo [2/3] Building Release x64...
dotnet build --no-restore --nologo -p:Platform=x64 -c Release
if errorlevel 1 goto failed
echo [3/3] Opening the saved mode - assistant by default...
start "" "%~dp0bin\x64\Release\LocalSecurityAudit-0.3.8\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe"
exit /b 0

:failed
echo Build failed. No application was started.
pause
exit /b 1
