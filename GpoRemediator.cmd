@echo off
setlocal
cd /d "%~dp0"
title GPO Remediator
echo Opening GPO Remediator control panel...
if not exist "%~dp0scripts\Start-ControlPanel.ps1" (
  echo ERROR: Launcher files are missing. Extract the complete project ZIP first.
  pause
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0scripts\Start-ControlPanel.ps1" %*
set EXITCODE=%ERRORLEVEL%
if not "%EXITCODE%"=="0" (
  echo.
  echo GPO Remediator stopped with error code %EXITCODE%.
  echo Check work\panel-error.log, work\bootstrap.log and work\server-error.log.
  pause
)
exit /b %EXITCODE%
