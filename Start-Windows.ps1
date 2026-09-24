Write-Warning 'Start-Windows.ps1 is a compatibility wrapper. Normal users should run GpoRemediator.cmd; mode is selected automatically from UI-saved configuration.'
& (Join-Path $PSScriptRoot 'GpoRemediator.ps1') -Mode Windows
exit $LASTEXITCODE
