$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')
try {
    $state=Get-RemediatorService
    if(!$state){ Clear-RemediatorTransientState -PreserveDiagnostics; Write-Host 'GPO Remediator is already stopped.' -ForegroundColor Yellow; exit 0 }
    $launcherId=if($state.launcherId){[int]$state.launcherId}else{0}
    Invoke-RemediatorServiceAction -Action stop | Out-Null
    if($launcherId -gt 0){ for($i=0;$i -lt 30;$i++){ if(!(Get-Process -Id $launcherId -ErrorAction SilentlyContinue)){break};Start-Sleep -Milliseconds 200 } }
    Clear-RemediatorTransientState -PreserveDiagnostics
    Write-Host 'GPO Remediator stopped. Audit data, backups, recovery copies and diagnostics were preserved.' -ForegroundColor Green
    exit 0
} catch { Write-Error $_; exit 1 }
