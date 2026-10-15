param([switch]$Force)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')
try {
    $state=Get-RemediatorService
    if(!$state){ Clear-RemediatorTransientState -PreserveDiagnostics; Write-Host 'GPO Remediator is already stopped.' -ForegroundColor Yellow; exit 0 }
    $launcherId=if($state.launcherId){[int]$state.launcherId}else{0}
    if($Force){ Stop-RemediatorEmergency | Out-Null }
    else { Invoke-RemediatorServiceAction -Action stop | Out-Null }
    if($launcherId -gt 0){
        for($i=0;$i -lt 30;$i++){ if(!(Get-Process -Id $launcherId -ErrorAction SilentlyContinue)){break};Start-Sleep -Milliseconds 200 }
        if(Get-Process -Id $launcherId -ErrorAction SilentlyContinue){throw 'Backend stopped, but the launcher has not exited. Stop marker and diagnostics were preserved; close the launcher window before deleting its folder.'}
    }
    Clear-RemediatorTransientState -PreserveDiagnostics
    Write-Host 'GPO Remediator stopped. Audit data, backups, recovery copies and diagnostics were preserved.' -ForegroundColor Green
    exit 0
} catch { Write-Error $_; exit 1 }
