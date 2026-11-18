param([ValidateRange(1024,65535)][int]$Port = 5080, [switch]$SmokeTest)
# Start-Process can inherit PowerShell 7 module paths. Resolve Windows modules first.
$windowsModules = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$env:PSModulePath = $windowsModules + ';' + $env:PSModulePath
$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$workRoot=Join-Path $env:ProgramData 'GpoRemediator\State'
function Invoke-LocalLifecycleAction {
    param([ValidateSet('stop','restart')][string]$Action,[string]$BaseUrl)
    $session=Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($BaseUrl+'/api/session') -SessionVariable lifecycle -TimeoutSec 8
    $token=($session.Content|ConvertFrom-Json).csrfToken
    if([string]::IsNullOrWhiteSpace([string]$token)){throw 'LIFECYCLE_SESSION_INVALID: The backend did not issue a CSRF token.'}
    $headers=@{'X-CSRF-Token'=[string]$token;'Origin'=$BaseUrl}
    $result=Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($BaseUrl+'/api/service/'+$Action) -WebSession $lifecycle -Headers $headers -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 8
    if($result.StatusCode -ne 202){throw ('LIFECYCLE_REQUEST_REJECTED: HTTP '+$result.StatusCode)}
}
function Show-OperatorLauncher {
    param([string]$BaseUrl)
    Start-Process $BaseUrl | Out-Null
    Write-Host ''
    Write-Host '  MACHINE BACKEND: RUNNING' -ForegroundColor Green
    Write-Host ('  Workspace: '+$BaseUrl)
    Write-Host '  This launcher may be closed without stopping the backend.' -ForegroundColor DarkGray
    while($true){
        Write-Host ''
        $choice=(Read-Host '[O] Open web  [R] Restart backend  [S] Stop backend  [Q] Close launcher').Trim().ToUpperInvariant()
        switch($choice){
            'O' {Start-Process $BaseUrl|Out-Null}
            'R' {
                try{Invoke-LocalLifecycleAction -Action restart -BaseUrl $BaseUrl;Write-Host 'Restart accepted. Active operations remain protected by the operation gate.' -ForegroundColor Yellow}
                catch{Write-Host $_.Exception.Message -ForegroundColor Red}
            }
            'S' {
                if((Read-Host 'Type STOP to stop the computer-wide backend') -cne 'STOP'){Write-Host 'Stop cancelled.' -ForegroundColor DarkGray;continue}
                try{Invoke-LocalLifecycleAction -Action stop -BaseUrl $BaseUrl;Write-Host 'Stop accepted. A local administrator is required to start the machine task again.' -ForegroundColor Yellow;return}
                catch{Write-Host $_.Exception.Message -ForegroundColor Red}
            }
            'Q' {return}
            default {Write-Host 'Choose O, R, S or Q.' -ForegroundColor DarkGray}
        }
    }
}
try {
    $url=('http://127.0.0.1:{0}' -f $Port)
    try {
        $health=Invoke-WebRequest -UseBasicParsing -Uri ($url+'/api/v1/health/live') -TimeoutSec 2
        $payload=$health.Content|ConvertFrom-Json
        if($health.StatusCode -eq 200 -and [string]$payload.status -ceq 'live' -and [string]$payload.apiVersion -ceq '1.0' -and [string]$payload.productVersion -match '^3\.'){
            if(!$SmokeTest){Show-OperatorLauncher -BaseUrl $url}
            exit 0
        }
    } catch { }
    $task=Get-ScheduledTask -TaskName 'GPO Remediator Policy Operations' -ErrorAction SilentlyContinue
    if($task){throw 'MACHINE_SERVICE_OFFLINE: The computer-wide GPO Remediator service is installed but is not ready. Ask a local administrator to start or repair the scheduled service. Operator sessions must not create a second backend.'}
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    $panel=Join-Path $projectRoot 'Control-Panel.ps1'
    if (!(Test-Path -LiteralPath $panel)) { throw 'Control-Panel.ps1 is missing. Extract the complete project archive before starting.' }
    & $panel -Port $Port -SmokeTest:$SmokeTest
    exit 0
} catch {
    $details=('[{0}] Control panel startup failed: {1}{2}{3}' -f (Get-Date -Format 's'),$_.Exception.Message,[Environment]::NewLine,$_.ScriptStackTrace)
    $diagnosticPath=Join-Path $workRoot 'panel-error.log'
    try { Add-Content -LiteralPath $diagnosticPath -Value $details -Encoding UTF8 } catch {
        try {
            $fallback=Join-Path $env:LOCALAPPDATA 'GpoRemediator\Diagnostics'
            New-Item -ItemType Directory -Path $fallback -Force | Out-Null
            $diagnosticPath=Join-Path $fallback 'panel-error.log'
            Add-Content -LiteralPath $diagnosticPath -Value $details -Encoding UTF8
        } catch { $diagnosticPath='Log file could not be written. See the startup console.' }
    }
    [Console]::Error.WriteLine($details)
    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        [System.Windows.MessageBox]::Show(
            "GPO Remediator Control Center could not start.`n`n$($_.Exception.Message)`n`nFull details were written to:`n$diagnosticPath",
            'GPO Remediator - Startup Error',
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        ) | Out-Null
    } catch { }
    exit 1
}
