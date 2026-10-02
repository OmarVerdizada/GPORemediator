param([int]$RecoveryPort = 5086)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\Tooling.ps1')

$dotnet = Find-Dotnet
$backend = Join-Path $PSScriptRoot 'backend'

$controlPanelBytes=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'Control-Panel.ps1'))
if($controlPanelBytes.Length -lt 3 -or $controlPanelBytes[0] -ne 0xEF -or $controlPanelBytes[1] -ne 0xBB -or $controlPanelBytes[2] -ne 0xBF){throw 'Control-Panel.ps1 must be UTF-8 with BOM for Windows PowerShell 5.1.'}

Write-Host '[1/8] Building current backend...' -ForegroundColor Cyan
& $dotnet build (Join-Path $backend 'GpoRemediator.csproj') -c Release --nologo
Assert-Exit

Write-Host '[2/8] Running .NET invariants...' -ForegroundColor Cyan
& $dotnet run --project (Join-Path $PSScriptRoot 'tests\InvariantTests\InvariantTests.csproj') -c Release
Assert-Exit

Write-Host '[3/8] Validating production CIS mapping registry...' -ForegroundColor Cyan
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

Write-Host '[4/8] Running isolated GPO worker transaction tests...' -ForegroundColor Cyan
& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'tests\GpoWorkflow.ps1')
Assert-Exit

Write-Host '[5/8] Running local recovery-mode startup test...' -ForegroundColor Cyan
& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'tests\Startup-Recovery.ps1') -DotnetPath $dotnet -Port $RecoveryPort
Assert-Exit

Write-Host '[6/8] Verifying UI domain truth model...' -ForegroundColor Cyan
$node = Get-Command node.exe,node -ErrorAction SilentlyContinue | Select-Object -First 1
if (!$node) { throw 'Node.js and the pinned Playwright test dependencies are required for the release gate; frontend tests may not be skipped.' }
& $node.Source (Join-Path $PSScriptRoot 'tests\UiDomain.cjs'); Assert-Exit

Write-Host '[7/8] Verifying frontend source/dist integrity and dependency-free workflow smoke checks...' -ForegroundColor Cyan
& $node.Source (Join-Path $PSScriptRoot 'tests\Frontend.Static.cjs'); Assert-Exit
& $node.Source (Join-Path $PSScriptRoot 'tests\Frontend.cjs'); Assert-Exit
if (!(Test-FrontendDistMatchesSource)) { throw 'frontend/dist does not match frontend/source. Rebuild or resync the frontend before release.' }
foreach ($name in @('client.js','workspace.js','automation.js','ui-domain.js','i18n.js','router.js','workspace.css','automation.css','command-center.css','index.html','benchmark-v4.json')) {
    $a=Join-Path $PSScriptRoot ('frontend\source\'+$name); $b=Join-Path $PSScriptRoot ('frontend\dist\'+$name)
    if (!(Test-Path $a) -or !(Test-Path $b) -or (Get-FileHash $a -Algorithm SHA256).Hash -cne (Get-FileHash $b -Algorithm SHA256).Hash) { throw "Frontend source/dist mismatch: $name" }
}

Write-Host '[8/8] Checking release safety markers...' -ForegroundColor Cyan
$prodMarker=Join-Path $PSScriptRoot 'runtime\production-backend-v4.ready'
$runtimeArchive=Join-Path $PSScriptRoot 'release\GpoRemediator-runtime-win-x64.zip'
$runtimeArchiveHash=$runtimeArchive+'.sha256'
if ((Test-Path -LiteralPath $runtimeArchive) -xor (Test-Path -LiteralPath $runtimeArchiveHash)) { throw 'Packaged runtime archive and its SHA-256 manifest must be shipped together.' }
if (Test-Path -LiteralPath $runtimeArchive) {
    $expected=(Get-Content -LiteralPath $runtimeArchiveHash -Raw -Encoding ASCII).Trim().ToUpperInvariant()
    $actual=(Get-FileHash -LiteralPath $runtimeArchive -Algorithm SHA256).Hash
    if ($expected -cne $actual) { throw 'Packaged runtime archive SHA-256 verification failed.' }
    Write-Host 'Packaged runtime archive SHA-256: verified.' -ForegroundColor Green
}
if ((Test-Path -LiteralPath $prodMarker) -and !(Test-PortableBackendMatchesSource)) { Write-Warning 'Production runtime exists but does not match the current backend source. Rebuild the portable package before release.' }
elseif (Test-Path -LiteralPath $prodMarker) { Write-Host 'Production runtime fingerprint matches the current backend source.' -ForegroundColor Green }

Write-Host 'PASS: build, invariants, 405-control registry (401 automated + 4 read-only), isolated GPO transaction worker, recovery startup and frontend integrity.' -ForegroundColor Green
Write-Host 'Real AD/GPO publication, replication, gpupdate and effective-policy convergence still require the final Windows domain test.' -ForegroundColor Yellow
