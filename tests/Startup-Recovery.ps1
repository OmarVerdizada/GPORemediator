param([int]$Port=5086)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$testRoot=Join-Path $root ('work\startup-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
# Deliberately invalid saved settings must not prevent the local recovery UI API.
Set-Content (Join-Path $testRoot 'appsettings.Local.json') '{broken json' -Encoding UTF8
$exe=Join-Path $root 'runtime\GpoRemediator.exe'
$arguments=@('--contentRoot',('"'+$testRoot+'"'),'--LocalSetup','true','--Mode','Mock','--urls',"http://localhost:$Port",'--DatabasePath',('"'+(Join-Path $testRoot 'test.db')+'"'))
$process=Start-Process $exe -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $testRoot 'stdout.log') -RedirectStandardError (Join-Path $testRoot 'stderr.log')
try {
    $session=$null
    for($i=0;$i -lt 40;$i++) {
        if($process.HasExited){throw 'Recovery process stopped unexpectedly.'}
        try { $session=Invoke-RestMethod "http://localhost:$Port/api/session" -TimeoutSec 2; break } catch { Start-Sleep -Milliseconds 250 }
    }
    if(!$session -or !$session.setupRequired -or $session.mode -ne 'MOCK'){throw 'Local recovery did not start in explicit MOCK setup mode.'}
    $config=Invoke-RestMethod "http://localhost:$Port/api/setup/config"
    if($config.enableWrites){throw 'Recovery mode exposed enabled writes.'}
    $service=Invoke-RestMethod "http://localhost:$Port/api/service"
    if($service.writesEnabled){throw 'Recovery mode permits real writes.'}
    if((Get-Content (Join-Path $testRoot 'appsettings.Local.json') -Raw).Trim() -ne '{broken json'){throw 'Recovery modified the original configuration.'}
    Write-Host 'PASS: malformed saved configuration opens local setup without enabling real writes or replacing the configuration.'
} finally {
    if(!$process.HasExited){Stop-Process -Id $process.Id -Force}
}
