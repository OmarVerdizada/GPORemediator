@echo off
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0Install-GpoRemediator.ps1" %*
