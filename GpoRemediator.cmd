@echo off
setlocal EnableExtensions DisableDelayedExpansion
title GPO Remediator - Startup
pushd "%~dp0"
if errorlevel 1 (
    echo [GPO Remediator] Cannot access the extracted project folder.
    pause
    exit /b 1
)
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "STARTER=%~dp0scripts\Start-ControlPanel.ps1"
if not exist "%PS%" goto missingPowerShell
if not exist "%STARTER%" goto missingStarter
echo.
echo   GPO REMEDIATOR - POLICY OPERATIONS
echo   Opening the local Control Center...
echo   Startup errors will remain visible in this window.
echo.
"%PS%" -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%STARTER%" %*
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (
    echo.
    echo [GPO Remediator] Startup failed. Exit code: %RESULT%
    echo Review the error above and the panel-error.log in:
    echo "%ProgramData%\GpoRemediator\State"
    echo "%LOCALAPPDATA%\GpoRemediator\Diagnostics"
    echo.
    pause
)
popd
exit /b %RESULT%
:missingPowerShell
echo [GPO Remediator] Windows PowerShell was not found:
echo "%PS%"
goto failed
:missingStarter
echo [GPO Remediator] Startup script is missing:
echo "%STARTER%"
echo Extract the complete release ZIP before starting.
:failed
pause
popd
exit /b 1
