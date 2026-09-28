param(
    [Parameter(Mandatory=$true)][string]$DotnetPath,
    [int]$Port=5086
)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$testRoot=Join-Path $root ('work\startup-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
# Deliberately malformed persisted JSON must not stop the explicit local recovery path.
Set-Content (Join-Path $testRoot 'appsettings.Local.json') '{broken json' -Encoding UTF8
$sourceRoot=Join-Path $root 'backend'
Copy-Item -LiteralPath (Join-Path $sourceRoot 'appsettings.json') -Destination $testRoot
$dll=Join-Path $sourceRoot 'bin\Release\net8.0\GpoRemediator.dll'
$db=Join-Path $testRoot 'setup-recovery.db'
$arguments=@(('"'+$dll+'"'),'--contentRoot',('"'+$testRoot+'"'),'--LocalSetup','true','--Mode','Setup','--urls',"http://127.0.0.1:$Port",'--DatabasePath',('"'+$db+'"'))
$process=Start-Process -FilePath $DotnetPath -ArgumentList $arguments -WorkingDirectory $testRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $testRoot 'stdout.log') -RedirectStandardError (Join-Path $testRoot 'stderr.log')
try {
    $session=$null
    for($i=0;$i -lt 60;$i++) {
        if($process.HasExited){throw "Recovery process stopped unexpectedly. Inspect $testRoot"}
        try { $session=Invoke-RestMethod "http://127.0.0.1:$Port/api/session" -TimeoutSec 2; break } catch { Start-Sleep -Milliseconds 250 }
    }
    if(!$session -or !$session.setupRequired -or $session.mode -ne 'SETUP'){throw 'Local recovery did not start in explicit SETUP mode.'}
    $config=Invoke-RestMethod "http://127.0.0.1:$Port/api/setup/config" -TimeoutSec 5
    if($config.enableWrites){throw 'Recovery mode exposed enabled writes.'}
    $service=Invoke-RestMethod "http://127.0.0.1:$Port/api/service" -TimeoutSec 5
    if($service.writesEnabled){throw 'Recovery mode permits real writes.'}
    $blocked=$false
    try { Invoke-RestMethod "http://127.0.0.1:$Port/api/gpo/settings" -TimeoutSec 5 | Out-Null }
    catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -in @(403,409)) { $blocked=$true } else { throw } }
    if(!$blocked){throw 'Setup mode exposed GPO operation API.'}
    if((Get-Content (Join-Path $testRoot 'appsettings.Local.json') -Raw).Trim() -ne '{broken json'){throw 'Recovery modified the malformed configuration before an explicit save.'}
    $csrf=Invoke-RestMethod "http://127.0.0.1:$Port/api/session" -SessionVariable webSession
    $body=@{domain='example.local';domainController='dc01.example.local';backupPath='C:\GpoTestBackups';allowedOperators=@('TEST/Administrator');autoRestart=$false}|ConvertTo-Json
    $saved=Invoke-RestMethod "http://127.0.0.1:$Port/api/setup/config" -Method Post -ContentType 'application/json' -Body $body -WebSession $webSession -Headers @{'Origin'="http://127.0.0.1:$Port";'X-CSRF-Token'=$csrf.csrfToken}
    $config=Invoke-RestMethod "http://127.0.0.1:$Port/api/setup/config"
    if(!$saved.saved -or $config.allowedOperators[0] -cne 'TEST\Administrator'){throw 'Setup did not normalize the operator account.'}
    $savedPath=Join-Path $testRoot 'appsettings.Local.json'
    $legacy=(Get-Content -LiteralPath $savedPath -Raw).Replace('"Windows"','"windows"').Replace('"AllowedOperators"','"allowedOperators"').Replace('"DomainController"','"domainController"')
    Set-Content -LiteralPath $savedPath -Value $legacy -Encoding UTF8
    $legacyConfig=Invoke-RestMethod "http://127.0.0.1:$Port/api/setup/config"
    if($legacyConfig.allowedOperators[0] -cne 'TEST\Administrator' -or $legacyConfig.domainController -cne 'dc01.example.local'){throw 'Existing camelCase configuration could not be read.'}
    Write-Host 'PASS: malformed saved configuration opens local-only SETUP mode without writes or silent configuration replacement.'
} finally {
    if($process -and !$process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue}
}
