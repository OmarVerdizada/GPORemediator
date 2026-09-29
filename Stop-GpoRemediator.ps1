param([int]$Port = 5080)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')
try {
    $state = Get-RemediatorService
    if (!$state) { Clear-RemediatorEphemeralState; Write-Host 'This project is already stopped. Any leftover local runtime data was cleaned.'; exit 0 }
    Invoke-RemediatorServiceAction -Action stop | Out-Null
    for ($attempt=0; $attempt -lt 30; $attempt++) {
        if (!(Get-RemediatorService)) {
            Clear-RemediatorEphemeralState
            Write-Host 'GPO Remediator stopped successfully. Local runtime history, database state, logs and session artifacts were removed.' -ForegroundColor Green
            exit 0
        }
        Start-Sleep -Milliseconds 500
    }
    throw 'Shutdown was requested but has not completed. Check the control panel and logs.'
} catch { Write-Error $_; exit 1 }
