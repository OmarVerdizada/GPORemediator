@echo off
setlocal EnableExtensions DisableDelayedExpansion
title GPO Remediator - Machine Control Center
pushd "%~dp0"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "CONTROL=%~dp0scripts\Start-MachineControlCenter.ps1"
if not exist "%PS%" goto missing
if not exist "%CONTROL%" goto missing
"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "%CONTROL%" -ProjectRoot "%~dp0" %*
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
:missing
echo GPO Remediator Machine Control Center is incomplete.
pause
popd
exit /b 1
