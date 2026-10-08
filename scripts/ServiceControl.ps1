function Get-RemediatorService {
    $statePath=Join-Path $env:ProgramData 'GpoRemediator\State\service.json'
    if(!(Test-Path -LiteralPath $statePath)){ return $null }
    try {
        $state=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $process=Get-Process -Id ([int]$state.processId) -ErrorAction Stop
        if($process.ProcessName -ine 'GpoRemediator'){ return $null }
        if($state.startedAt){
            $actual=$process.StartTime.ToUniversalTime()
            $expected=[DateTimeOffset]::Parse([string]$state.startedAt).UtcDateTime
            if([Math]::Abs(($actual-$expected).TotalSeconds) -gt 2){ return $null }
        }
        if($state.executablePath -and $process.Path -and ([IO.Path]::GetFullPath($process.Path) -ine [IO.Path]::GetFullPath([string]$state.executablePath))){ return $null }
        return $state
    } catch { return $null }
}

function Invoke-RemediatorServiceAction {
    param([ValidateSet('stop','restart')][string]$Action)
    $state=Get-RemediatorService
    if(!$state){ throw 'No running GPO Remediator service was found.' }
    $work=Join-Path $env:ProgramData 'GpoRemediator\State'
    $stopMarker=Join-Path $work 'stop.request.json'
    if($Action -eq 'restart' -and [string]$state.mode -eq 'Setup'){
        $configPath=Join-Path $env:ProgramData 'GpoRemediator\Config\appsettings.Local.json'
        try {
            $cfg=Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if(!$cfg -or [string]$cfg.Mode -ne 'Windows' -or !$cfg.Windows -or [string]::IsNullOrWhiteSpace([string]$cfg.Windows.Domain) -or [string]::IsNullOrWhiteSpace([string]$cfg.Windows.DomainController) -or @($cfg.Windows.AllowedOperators).Count -lt 1){
                throw 'Domain, writable DC and at least one operator must be saved before Windows / AD promotion.'
            }
        } catch {
            throw ('Windows / AD promotion is blocked because the saved configuration is incomplete or invalid: '+$_.Exception.Message)
        }
    }
    $baseUrl=([string]$state.url).TrimEnd('/')
    $serviceUri=$null
    if(![Uri]::TryCreate($baseUrl,[UriKind]::Absolute,[ref]$serviceUri) -or !$serviceUri.IsLoopback -or $serviceUri.Scheme -notin @('http','https') -or $serviceUri.UserInfo){throw 'Service state contains an invalid local URL. No credentials were sent.'}
    try {
        $session=Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($baseUrl+'/api/session') -SessionVariable web -TimeoutSec 8
        $token=($session.Content | ConvertFrom-Json).csrfToken
        $headers=@{'X-CSRF-Token'=[string]$token;'Origin'=$baseUrl}
        $result=Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($baseUrl+'/api/service/'+$Action) -WebSession $web -Headers $headers -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 8
        $parsed=$result.Content | ConvertFrom-Json
        if($Action -eq 'stop'){
            # Write only after acceptance. A busy/denied API response must never
            # leave a marker that makes the launcher terminate an active job.
            @{requestedAt=[DateTimeOffset]::UtcNow.ToString('o');requestedBy=[Security.Principal.WindowsIdentity]::GetCurrent().Name} |
                ConvertTo-Json | Set-Content -LiteralPath $stopMarker -Encoding UTF8
        }
        # The backend's generic restart endpoint preserves the current mode. In recovery Setup mode
        # the operator expects Restart to promote a valid saved configuration into Windows / AD mode.
        # Overwrite the launcher marker after the API accepted the restart so the handoff is explicit.
        if($Action -eq 'restart' -and [string]$state.mode -eq 'Setup'){
            @{mode='Windows';requestedAt=[DateTimeOffset]::UtcNow.ToString('o');requestedBy=[Security.Principal.WindowsIdentity]::GetCurrent().Name;source='ControlCenterPromotion'} |
                ConvertTo-Json | Set-Content -LiteralPath (Join-Path $work 'restart.request.json') -Encoding UTF8
            $parsed | Add-Member -NotePropertyName requestedMode -NotePropertyValue 'Windows' -Force
        }
    } catch {
        if($Action -eq 'restart'){ throw }
        if($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -ge 400 -and [int]$_.Exception.Response.StatusCode -lt 500){throw}
        # A dead/unresponsive backend must not keep the old launcher alive forever.
        @{requestedAt=[DateTimeOffset]::UtcNow.ToString('o');source='UnreachableBackendStop'} |
            ConvertTo-Json | Set-Content -LiteralPath $stopMarker -Encoding UTF8
        try {
            $p=Get-Process -Id ([int]$state.processId) -ErrorAction Stop
            if($p.ProcessName -ieq 'GpoRemediator'){ Stop-Process -Id $p.Id -Force -ErrorAction Stop }
        } catch { }
        $parsed=[pscustomobject]@{action='stop';accepted=$true;forced=$true}
    }
    if($Action -eq 'stop'){
        for($i=0;$i -lt 40;$i++){ Start-Sleep -Milliseconds 250; if(!(Get-RemediatorService)){ break } }
        Remove-Item -LiteralPath (Join-Path $work 'service.json') -Force -ErrorAction SilentlyContinue
    }
    return $parsed
}

function Clear-RemediatorTransientState {
    param([switch]$PreserveDiagnostics)
    $work=Join-Path $env:ProgramData 'GpoRemediator\State'
    foreach($name in @('service.json','restart.request.json','stop.request.json')){ Remove-Item -LiteralPath (Join-Path $work $name) -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath (Join-Path $env:ProgramData 'GpoRemediator\Config\appsettings.Local.json.tmp') -Force -ErrorAction SilentlyContinue
    if(Test-Path -LiteralPath $work){
        Get-ChildItem -LiteralPath $work -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^runtime-(install|old)-[a-f0-9]{32}$' } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}
function Clear-RemediatorEphemeralState { param([switch]$PreserveDiagnostics); Clear-RemediatorTransientState -PreserveDiagnostics:$PreserveDiagnostics }
