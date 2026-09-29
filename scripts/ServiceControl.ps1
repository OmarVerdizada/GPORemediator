# Shared by the desktop control panel and the command-line stop utility.
function Get-RemediatorService {
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $statePath = Join-Path $projectRoot 'work\service.json'
    if (!(Test-Path -LiteralPath $statePath)) { return $null }
    try {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
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
                if (!(Get-RemediatorService)) { Clear-RemediatorEphemeralState; break }
            }
        }
        return $parsed
    } catch {
        if ($_.ErrorDetails.Message) { throw $_.ErrorDetails.Message }
        throw
    }
}

# Remove local runtime/session/history artifacts after a full stop.
# Persistent operator configuration and GPO rollback backups are intentionally NOT removed.
function Clear-RemediatorEphemeralState {
    param([switch]$PreserveDiagnostics)
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $backendData = Join-Path $projectRoot 'backend\data'
    $work = Join-Path $projectRoot 'work'

    # SQLite operational state: plans, runs, local audit/history and WAL sidecars.
    foreach ($name in @('windows.db','windows.db-wal','windows.db-shm','setup.db','setup.db-wal','setup.db-shm')) {
        Remove-Item -LiteralPath (Join-Path $backendData $name) -Force -ErrorAction SilentlyContinue
    }

    # Launcher/service logs, state and transient worker/test artifacts. Keep documentation placeholders only.
    if (Test-Path -LiteralPath $work) {
        $keep = @('README.txt')
        if ($PreserveDiagnostics) { $keep += @('bootstrap.log','launcher-output.log','launcher-error.log','server-error.log') }
        Get-ChildItem -LiteralPath $work -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin $keep } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Defensive cleanup for transient config write files only; the saved local configuration remains.
    Remove-Item -LiteralPath (Join-Path $projectRoot 'backend\appsettings.Local.json.tmp') -Force -ErrorAction SilentlyContinue
}
