@echo off
echo Starting LocalSecurityAudit with Administrator privileges...
cd /d "%~dp0bin\x64\Debug\net8.0-windows10.0.19041.0"
powershell -Command "Start-Process '.\LocalSecurityAudit.exe' -Verb RunAs"
