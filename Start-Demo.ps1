param([int]$Port = 5080)
Write-Warning 'Start-Demo.ps1 is a compatibility wrapper. Normal users should run GpoRemediator.cmd.'
& (Join-Path $PSScriptRoot 'GpoRemediator.ps1') -Mode Demo -Port $Port
exit $LASTEXITCODE
