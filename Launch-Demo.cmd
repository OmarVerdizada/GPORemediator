@echo off
cd /d "%~dp0"
echo Compatibility shortcut: forwarding to the unified launcher in Demo mode.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0GpoRemediator.ps1" -Mode Demo
exit /b %ERRORLEVEL%
