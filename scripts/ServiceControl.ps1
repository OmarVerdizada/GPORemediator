# Shared by the desktop control panel and the command-line stop utility.
function Get-RemediatorService {
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $statePath = Join-Path $env:ProgramData 'GpoRemediator\State\service.json'
    if (!(Test-Path -LiteralPath $statePath)) { return $null }
    try {
        $state = Get-Content -LiteralPath $statePath -Encoding UTF8 -Raw | ConvertFrom-Json
        $process = Get-Process -Id ([int]$state.processId) -ErrorAction Stop
        $expected = Join-Path $projectRoot 'runtime\GpoRemediator.exe'
        if ($process.Path -ine $expected) { return $null }
        if ($process.StartTime.ToUniversalTime().ToString('o') -ne $state.startedAt) { return $null }
        return $state
    } catch { return $null }
}
function Invoke-RemediatorServiceAction {
    param([ValidateSet('stop','restart')][string]$Action)
    $state = Get-RemediatorService
    if (!$state) { throw 'No running service belonging to this project was found.' }
    $baseUrl = ([string]$state.url).TrimEnd('/')
    $session = Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($baseUrl + '/api/session') -SessionVariable serviceWeb -TimeoutSec 8
    $token = ($session.Content | ConvertFrom-Json).csrfToken
    $headers = @{ 'X-CSRF-Token'=[string]$token; 'Origin'=$baseUrl }
    try {
        $result = Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($baseUrl + '/api/service/' + $Action) -WebSession $serviceWeb -Headers $headers -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 8
        $parsed = ($result.Content | ConvertFrom-Json)
        if ($Action -eq 'stop') {
            for ($attempt=0; $attempt -lt 40; $attempt++) {
                Start-Sleep -Milliseconds 250
                if (!(Get-RemediatorService)) { Clear-RemediatorTransientState; break }
            }
        }
        return $parsed
    } catch {
        if ($_.ErrorDetails.Message) { throw $_.ErrorDetails.Message }
        throw
    }
}

# Remove launcher-owned transient files after a full stop. Operational databases,
# audit history, evidence and diagnostics are durable and are never stop-time cleanup.
function Clear-RemediatorTransientState {
    param([switch]$PreserveDiagnostics)
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $work = Join-Path $env:ProgramData 'GpoRemediator\State'

    # Launcher/service logs, state and transient worker/test artifacts. Keep documentation placeholders only.
    if (Test-Path -LiteralPath $work) {
        foreach ($name in @('service.json','restart.request.json')) {
            Remove-Item -LiteralPath (Join-Path $work $name) -Force -ErrorAction SilentlyContinue
        }
    }

    # Defensive cleanup for transient config write files only; the saved local configuration remains.
    Remove-Item -LiteralPath (Join-Path $env:ProgramData 'GpoRemediator\Config\appsettings.Local.json.tmp') -Force -ErrorAction SilentlyContinue
}

# Backward-compatible function name for older shortcuts. It deliberately preserves data.
function Clear-RemediatorEphemeralState { param([switch]$PreserveDiagnostics); Clear-RemediatorTransientState -PreserveDiagnostics:$PreserveDiagnostics }
