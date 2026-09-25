param([int]$RecoveryPort = 5086)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\Tooling.ps1')

$dotnet = Find-Dotnet
$backend = Join-Path $PSScriptRoot 'backend'

Write-Host '[1/7] Building current backend...' -ForegroundColor Cyan
& $dotnet build (Join-Path $backend 'GpoRemediator.csproj') -c Release --nologo
Assert-Exit

Write-Host '[2/7] Running .NET invariants...' -ForegroundColor Cyan
& $dotnet run --project (Join-Path $PSScriptRoot 'tests\InvariantTests\InvariantTests.csproj') -c Release --no-build
if ($LASTEXITCODE -ne 0) {
    # The invariant project has its own output and can require a first build after checkout.
    & $dotnet run --project (Join-Path $PSScriptRoot 'tests\InvariantTests\InvariantTests.csproj') -c Release
    Assert-Exit
}

Write-Host '[3/7] Validating production CIS mapping registry...' -ForegroundColor Cyan
$mappingPath = Join-Path $backend 'data\gpo-production-mappings.json'
$mapping = Get-Content -LiteralPath $mappingPath -Raw | ConvertFrom-Json
$items = @($mapping.mappings)
if ($items.Count -ne 405) { throw "Expected 405 unique CIS mappings, got $($items.Count)." }
if (@($items.id | Sort-Object -Unique).Count -ne 405) { throw 'Production mapping registry contains duplicate control IDs.' }
$handlerCounts = @{}; foreach ($m in $items) { if (!$handlerCounts.ContainsKey($m.handler)) { $handlerCounts[$m.handler]=0 }; $handlerCounts[$m.handler]++ }
$expected = @{ Registry=325; SecurityTemplate=48; AdvancedAudit=27; RegistrySet=5 }
foreach ($name in $expected.Keys) { if ($handlerCounts[$name] -ne $expected[$name]) { throw "Unexpected $name mapping count." } }
if (@($items | Where-Object { $_.automation -eq 'Automated' }).Count -ne 401) { throw 'Expected 401 CIS controls classified Automated.' }
$blocked=@($items | Where-Object { $_.automation -ne 'Automated' -or $_.handler -eq 'Manual' })
if ($blocked.Count -ne 4) { throw 'Expected exactly four manual/read-only CIS controls.' }
$blockedIds=@($blocked.id | Sort-Object)
$expectedBlocked=@('1.2.3','18.10.43.10.1','18.10.43.10.2','2.3.11.6' | Sort-Object)
if (($blockedIds -join '|') -cne ($expectedBlocked -join '|')) { throw 'Manual/read-only CIS control set changed unexpectedly.' }
if (@($items | Where-Object requiresInput).Count -ne 4) { throw 'Organization-specific input mapping count changed unexpectedly.' }
if ((Get-Content -LiteralPath $mappingPath -Raw) -match '\{\{') { throw 'Unresolved mapping template value remains in production registry.' }

Write-Host '[4/7] Running isolated GPO worker transaction tests...' -ForegroundColor Cyan
& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'tests\GpoWorkflow.ps1')
Assert-Exit

Write-Host '[5/7] Running local recovery-mode startup test...' -ForegroundColor Cyan
& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'tests\Startup-Recovery.ps1') -DotnetPath $dotnet -Port $RecoveryPort
Assert-Exit

Write-Host '[6/7] Verifying frontend source/dist integrity...' -ForegroundColor Cyan
if (!(Test-FrontendDistMatchesSource)) { throw 'frontend/dist does not match frontend/source. Rebuild or resync the frontend before release.' }
foreach ($name in @('workspace.js','automation.js','workspace.css','automation.css','index.html','benchmark-v4.json')) {
    $a=Join-Path $PSScriptRoot ('frontend\source\'+$name); $b=Join-Path $PSScriptRoot ('frontend\dist\'+$name)
    if (!(Test-Path $a) -or !(Test-Path $b) -or (Get-FileHash $a -Algorithm SHA256).Hash -cne (Get-FileHash $b -Algorithm SHA256).Hash) { throw "Frontend source/dist mismatch: $name" }
}

Write-Host '[7/7] Checking release safety markers...' -ForegroundColor Cyan
$prodMarker=Join-Path $PSScriptRoot 'runtime\production-backend-v3.ready'
if (Test-Path -LiteralPath $prodMarker) { Write-Warning 'Production build marker exists. Remove it before packaging a source-changed release unless runtime was rebuilt from this exact source.' }

Write-Host 'PASS: build, invariants, 405-control registry (401 automated + 4 read-only), isolated GPO transaction worker, recovery startup and frontend integrity.' -ForegroundColor Green
Write-Host 'Real AD/GPO publication, replication, gpupdate and effective-policy convergence still require the final Windows domain test.' -ForegroundColor Yellow
