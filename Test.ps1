param([int]$Port = 5081)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\Tooling.ps1')
$dotnet = Find-Dotnet
$backend = Join-Path $PSScriptRoot 'backend'

& $dotnet build (Join-Path $backend 'GpoRemediator.csproj') -c Release --nologo
Assert-Exit
& $dotnet run --project (Join-Path $PSScriptRoot 'tests\InvariantTests\InvariantTests.csproj') -c Release
Assert-Exit

$testDirectory = Join-Path $PSScriptRoot ('work\test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
$oldMode = $env:Mode; $oldDatabase = $env:DatabasePath
$env:Mode = 'Mock'; $env:DatabasePath = Join-Path $testDirectory 'isolated.db'
$env:TEST_ISOLATED = '1'; $env:TEST_BASE_URL = "http://localhost:$Port"
$dll = Join-Path $backend 'bin\Release\net8.0\GpoRemediator.dll'
$process = Start-Process -FilePath $dotnet -ArgumentList @(('"' + $dll + '"'), '--contentRoot', ('"' + $backend + '"'), '--urls', $env:TEST_BASE_URL) -WorkingDirectory $backend -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $testDirectory 'server.log') -RedirectStandardError (Join-Path $testDirectory 'server-error.log')
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($process.HasExited) { throw "Test server stopped. Inspect $testDirectory" }
        try {
            $sessionResponse = Invoke-WebRequest -UseBasicParsing -Uri "$env:TEST_BASE_URL/api/session" -SessionVariable web -TimeoutSec 2
            $session = $sessionResponse.Content | ConvertFrom-Json
            if ($session.mode -match 'mock') { $ready = $true; break }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (!$ready) { throw 'Isolated test server did not become ready.' }
    if ([string]::IsNullOrWhiteSpace([string]$session.csrfToken)) { throw 'Session did not return a CSRF token.' }

    function Get-Api([string]$Path) {
        $r = Invoke-WebRequest -UseBasicParsing -Uri ($env:TEST_BASE_URL + $Path) -WebSession $web -TimeoutSec 15
        return ($r.Content | ConvertFrom-Json)
    }
    function Post-Api([string]$Path,[object]$Body) {
        $headers = @{ 'X-CSRF-Token' = [string]$session.csrfToken; 'Origin' = $env:TEST_BASE_URL; 'Accept' = 'application/json' }
        $json = $Body | ConvertTo-Json -Depth 20 -Compress
        $r = Invoke-WebRequest -UseBasicParsing -Uri ($env:TEST_BASE_URL + $Path) -WebSession $web -Method Post -Headers $headers -ContentType 'application/json' -Body $json -TimeoutSec 30
        return ($r.Content | ConvertFrom-Json)
    }

    $controls = Get-Api '/api/controls'
    if (@($controls).Count -lt 1) { throw 'Control catalog smoke test failed.' }
    $benchmark = @($controls | Where-Object { $_.benchmarkId -eq 'CIS' })
    if ($benchmark.Count -ne 397) { throw 'Operator benchmark import is incomplete.' }
    $selection = Post-Api '/api/findings' @{ controlId='cis-2.2.3'; hostname='SRV-SELECT.prosol.az'; profile='MemberServer'; benchmarkSelection=$true }
    if ($selection.status -ne 'NOT_SCANNED') { throw 'Unscanned benchmark selection incorrectly claims compliance.' }
    $selectedPlan = Post-Api ('/api/findings/' + $selection.id + '/safe-plan') @{}
    if (!$selectedPlan.dryRun -or $selectedPlan.writes -ne 0) { throw 'Benchmark selection must prepare a zero-write plan without scanning.' }
    $audit = Get-Api '/api/audit'
    if (@($audit.events | Where-Object { $_.event -eq 'TARGET_SCANNED' }).Count) { throw 'Benchmark selection unexpectedly scanned the target.' }
    $service = Get-Api '/api/service'
    if ($service.managed -or $service.writesEnabled -or $service.stopping) { throw 'Isolated service lifecycle metadata is incorrect.' }
    try { Post-Api '/api/service/stop' @{} | Out-Null; throw 'Unmanaged service accepted stop.' }
    catch {
        if (!$_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 409) { throw }
    }
    $service = Get-Api '/api/service'
    if ($service.stopping) { throw 'Rejected stop still changed service state.' }
    $readiness = Get-Api '/api/automation/readiness'
    if (!$readiness.ready) { throw 'Mock readiness smoke test did not report ready.' }
    $scan = Post-Api '/api/automation/scan' @{ hostname='SRV-AUTO.prosol.az'; profile='MemberServer' }
    $finding = @($scan.results | Where-Object { $_.findingId } | Select-Object -First 1)
    if ($finding.Count -ne 1) { throw 'Target scan did not create a finding.' }
    $plan = Post-Api ('/api/findings/' + $finding[0].findingId + '/safe-plan') @{}
    if (!$plan.dryRun -or [int]$plan.writes -ne 0) { throw 'Safe-plan smoke test was not zero-write.' }
    $jobs = Get-Api '/api/jobs'
    if (@($jobs).Count -ne 0) { throw 'Safe-plan smoke test unexpectedly queued a write job.' }
} finally {
    if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    $env:Mode = $oldMode; $env:DatabasePath = $oldDatabase
    Remove-Item Env:TEST_ISOLATED,Env:TEST_BASE_URL -ErrorAction SilentlyContinue
}
Write-Host "All .NET invariant and PowerShell HTTP smoke tests passed. Evidence: $testDirectory" -ForegroundColor Green
