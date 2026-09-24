@echo off
setlocal
cd /d "%~dp0"
title GPO Remediator
powershell.exe -NoLogo -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0Control-Panel.ps1"
set EXITCODE=%ERRORLEVEL%
if not "%EXITCODE%"=="0" (
  echo.
  echo GPO Remediator stopped with error code %EXITCODE%.
  echo Check the work\bootstrap.log and work\server-error.log files.
  pause
)
exit /b %EXITCODE%
