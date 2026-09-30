$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\Tooling.ps1')
$dotnet = Find-Dotnet

# Frontend is dependency-free at build time. Keep source canonical and copy it
# deterministically to dist before publishing the backend.
$frontendSource = Join-Path $PSScriptRoot 'frontend\source'
$frontendDist = Join-Path $PSScriptRoot 'frontend\dist'
if (!(Test-Path -LiteralPath (Join-Path $frontendSource 'index.html'))) {
    throw 'frontend\source is missing. The packaged static UI is required.'
}
New-Item -ItemType Directory -Path $frontendDist -Force | Out-Null
Get-ChildItem -LiteralPath $frontendDist -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $frontendSource '*') -Destination $frontendDist -Recurse -Force
(Get-FrontendSourceFingerprint) | Set-Content -LiteralPath (Join-Path $frontendDist 'source.sha256') -Encoding ASCII -NoNewline

$project = Join-Path $PSScriptRoot 'backend\GpoRemediator.csproj'

function Invoke-RestoreWithRetry {
    $last = $null
    for ($attempt=1; $attempt -le 3; $attempt++) {
        Write-Host ("Restoring .NET/NuGet dependencies for win-x64 (attempt {0}/3)..." -f $attempt) -ForegroundColor Cyan
        & $dotnet restore $project -r win-x64 --nologo --disable-parallel
        if ($LASTEXITCODE -eq 0) { return }
        $last = $LASTEXITCODE
        if ($attempt -lt 3) { Start-Sleep -Seconds (2 * $attempt) }
    }
    throw "NuGet restore failed after 3 attempts (exit $last). Use the approved developer build environment and NuGet source, then retry the explicit build."
}

Invoke-RestoreWithRetry

# Publish into a staging directory first. A failed publish must never leave a
# half-updated production runtime behind.
$runtime = Join-Path $PSScriptRoot 'runtime'
$stage = Join-Path $PSScriptRoot ('work\runtime-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    Write-Host 'Publishing self-contained Windows x64 backend...' -ForegroundColor Cyan
    & $dotnet publish $project -c Release -r win-x64 --self-contained true -o $stage --nologo --no-restore
    Assert-Exit

    foreach ($required in @('GpoRemediator.exe','GpoRemediator.dll','GpoRemediator.deps.json','GpoRemediator.runtimeconfig.json','PowerShell\Invoke-GpoWorkflow.ps1','PowerShell\GpoWorkflow.Worker.ps1','PowerShell\SecurityTemplate.psm1')) {
        if (!(Test-Path -LiteralPath (Join-Path $stage $required))) { throw "Published runtime is incomplete: $required is missing." }
    }

    (Get-BackendSourceFingerprint) | Set-Content -LiteralPath (Join-Path $stage 'backend-source.sha256') -Encoding ASCII -NoNewline
    'production-backend-v4' | Set-Content -LiteralPath (Join-Path $stage 'production-backend-v4.ready') -Encoding ASCII -NoNewline

    # Swap only after a complete publish. Preserve the previous runtime as a
    # temporary fallback until the new directory is in place, then delete it.
    $old = Join-Path $PSScriptRoot ('work\runtime-old-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $runtime) { Move-Item -LiteralPath $runtime -Destination $old }
    try {
        Move-Item -LiteralPath $stage -Destination $runtime
        if (!(Test-PortableBackendMatchesSource)) { throw 'Portable backend fingerprint does not match current source.' }
        if (!(Test-FrontendDistMatchesSource)) { throw 'Static frontend fingerprint does not match current source.' }
        if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Recurse -Force }
    } catch {
        if (Test-Path -LiteralPath $runtime) { Remove-Item -LiteralPath $runtime -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $old) { Move-Item -LiteralPath $old -Destination $runtime -Force }
        throw
    }
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host 'Portable Windows x64 application ready. No Node.js/pnpm/npm registry is required.' -ForegroundColor Green
Write-Host 'Run GpoRemediator.cmd. For real AD/GPO use, complete Setup in the built-in Automation Center.' -ForegroundColor Green
