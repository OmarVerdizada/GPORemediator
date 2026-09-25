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
    try { Invoke-RestMethod "http://127.0.0.1:$Port/api/gpo/settings" -TimeoutSec 5 | Out-Null; throw 'Setup mode exposed GPO operation API.' }
    catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -notin @(403,409)) { throw } }
    if((Get-Content (Join-Path $testRoot 'appsettings.Local.json') -Raw).Trim() -ne '{broken json'){throw 'Recovery modified the malformed configuration before an explicit save.'}
    Write-Host 'PASS: malformed saved configuration opens local-only SETUP mode without writes or silent configuration replacement.'
} finally {
    if($process -and !$process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue}
}
