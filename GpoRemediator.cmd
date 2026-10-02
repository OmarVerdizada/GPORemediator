@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "STARTER=%~dp0scripts\Start-ControlPanel.ps1"

if not exist "%PS%" (
    echo [GPO Remediator] Windows PowerShell was not found:
    echo %PS%
    pause
    exit /b 1
)

if not exist "%STARTER%" (
    echo [GPO Remediator] Startup script is missing:
    echo %STARTER%
    echo Re-extract the complete release ZIP to a new folder.
    pause
    exit /b 1
)

start "GPO Remediator" "%PS%" -NoLogo -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "%STARTER%" %*
if errorlevel 1 (
    echo [GPO Remediator] The Control Center process could not be launched.
    echo Check C:\ProgramData\GpoRemediator\State\panel-error.log
    pause
    exit /b 1
)
exit /b 0
