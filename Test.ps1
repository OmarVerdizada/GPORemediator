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
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'tests\PasswordPilot.ps1')
Assert-Exit

$testDirectory = Join-Path $PSScriptRoot ('work\test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
$testContentRoot=Join-Path $testDirectory 'backend'
New-Item -ItemType Directory -Path $testContentRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $backend 'appsettings.json') -Destination $testContentRoot
$oldMode = $env:Mode; $oldDatabase = $env:DatabasePath
$env:Mode = 'Mock'; $env:DatabasePath = Join-Path $testDirectory 'isolated.db'
$env:TEST_ISOLATED = '1'; $env:TEST_BASE_URL = "http://localhost:$Port"
$dll = Join-Path $backend 'bin\Release\net8.0\GpoRemediator.dll'
$process = Start-Process -FilePath $dotnet -ArgumentList @(('"' + $dll + '"'), '--contentRoot', ('"' + $testContentRoot + '"'), '--urls', $env:TEST_BASE_URL) -WorkingDirectory $testContentRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $testDirectory 'server.log') -RedirectStandardError (Join-Path $testDirectory 'server-error.log')
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
    foreach ($blockedPath in @('/api/automation/scan',('/api/findings/' + $selection.id + '/apply'))) {
        try { Post-Api $blockedPath @{} | Out-Null; throw 'Password-only pilot accepted a scan or legacy policy write.' }
        catch { if (!$_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 409) { throw } }
    }
    $passwordSettings=Get-Api '/api/password/settings'
    if (@($passwordSettings).Count -ne 6) { throw 'Password pilot catalog must contain six supported settings.' }
    $passwordPlan=Post-Api '/api/password/plan' @{user='test.user';setting='MinPasswordLength';value=14}
    if ($passwordPlan.before.values.MinPasswordLength -ne 8 -or $passwordPlan.after.MinPasswordLength -ne 14) { throw 'Password preview did not retain before/after values.' }
    $passwordJob=Post-Api ('/api/password/' + $passwordPlan.id + '/apply') @{confirmation='APPLY'}
    if ($passwordJob.state -ne 'VERIFIED') { throw ('Password apply failed: ' + $passwordJob.message) }
    $replay=Post-Api ('/api/password/' + $passwordPlan.id + '/apply') @{confirmation='APPLY'}
    if ($replay.updatedAt -ne $passwordJob.updatedAt) { throw 'Repeated Apply was not idempotent.' }
    $rollback=Post-Api ('/api/password/' + $passwordPlan.id + '/rollback') @{confirmation='ROLLBACK'}
    if ($rollback.state -ne 'ROLLED_BACK') { throw 'Password rollback was not verified.' }
    $audit=Get-Api '/api/audit'
    if (@($audit.events | Where-Object { $_.event -eq 'TARGET_SCANNED' }).Count -or !$audit.integrityValid) { throw 'Unexpected scan or invalid audit chain.' }
    $jobs = Get-Api '/api/jobs'
    if (@($jobs).Count -ne 0) { throw 'Safe-plan smoke test unexpectedly queued a write job.' }
    # Regression for the original setup failure: password pilot needs no GPO/OU/computer allowlists.
    $setup=@{urls='https://management.example.com:5443';domain='example.com';domainController='dc01.example.com';approvedGpoIds=@();authorizedOus=@();allowedHosts=@();allowedOperators=@('EXAMPLE\operator');backupPath='C:\ProgramData\GpoRemediator\Backups';autoRestart=$false}
    $saved=Post-Api '/api/setup/config' $setup
    if (!$saved.saved -or $saved.writesEnabled) { throw 'Pilot setup without GPO GUIDs did not save safely.' }
    # Old Default Domain Policy entries must not carry over to the user-scoped pilot.
    $setup.approvedGpoIds=@('31b2f340-016d-11d2-945f-00c04fb984f9')
    Post-Api '/api/setup/config' $setup | Out-Null
    $stored=Get-Api '/api/setup/config'
    if (@($stored.approvedGpoIds).Count -or @($stored.authorizedOus).Count -or @($stored.allowedHosts).Count -or $stored.enableWrites) { throw 'Legacy setup values leaked into the password pilot.' }
    if (!(Test-Path -LiteralPath (Join-Path $testContentRoot 'appsettings.Local.json'))) { throw 'Setup was not persisted in isolated content root.' }
} finally {
    if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    $env:Mode = $oldMode; $env:DatabasePath = $oldDatabase
    Remove-Item Env:TEST_ISOLATED,Env:TEST_BASE_URL -ErrorAction SilentlyContinue
}
Write-Host "All .NET invariant and PowerShell HTTP smoke tests passed. Evidence: $testDirectory" -ForegroundColor Green
