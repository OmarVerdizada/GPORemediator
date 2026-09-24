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
        return ($result.Content | ConvertFrom-Json)
    } catch {
        if ($_.ErrorDetails.Message) { throw $_.ErrorDetails.Message }
        throw
    }
}
