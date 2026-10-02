Write-Warning 'Start-Windows.ps1 is a compatibility wrapper. Use GpoRemediator.cmd for normal operation.'
& (Join-Path $PSScriptRoot 'GpoRemediator.ps1') -Mode Windows
exit $LASTEXITCODE
