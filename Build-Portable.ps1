$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\Tooling.ps1')
$dotnet = Find-Dotnet

# Frontend is intentionally dependency-free at build time. The canonical UI files
# live under frontend\source and are copied verbatim to frontend\dist.
$frontendSource = Join-Path $PSScriptRoot 'frontend\source'
$frontendDist = Join-Path $PSScriptRoot 'frontend\dist'
if (!(Test-Path -LiteralPath (Join-Path $frontendSource 'index.html'))) {
    throw 'frontend\source is missing. The packaged static UI is required.'
}
if (Test-Path -LiteralPath $frontendDist) { Remove-Item -LiteralPath $frontendDist -Recurse -Force }
New-Item -ItemType Directory -Path $frontendDist -Force | Out-Null
Copy-Item -Path (Join-Path $frontendSource '*') -Destination $frontendDist -Recurse -Force
(Get-FrontendSourceFingerprint) | Set-Content -LiteralPath (Join-Path $frontendDist 'source.sha256') -Encoding ASCII -NoNewline

$runtime = Join-Path $PSScriptRoot 'runtime'
if (Test-Path -LiteralPath $runtime) { Remove-Item -LiteralPath $runtime -Recurse -Force }
New-Item -ItemType Directory -Path $runtime -Force | Out-Null

# Keep NuGet artifacts local to the product so repeat builds can reuse them. This is
# independent from npm; no Node.js registry is involved anywhere in this build.
$nugetCache = Join-Path $PSScriptRoot '.tools\nuget'
New-Item -ItemType Directory -Path $nugetCache -Force | Out-Null
$env:NUGET_PACKAGES = $nugetCache
$project = Join-Path $PSScriptRoot 'backend\GpoRemediator.csproj'
Write-Host 'Restoring .NET/NuGet dependencies for win-x64...' -ForegroundColor Cyan
& $dotnet restore $project -r win-x64 --nologo
if ($LASTEXITCODE -ne 0) {
    throw 'NuGet restore failed. Node.js/npm/pnpm are not involved. Allow the approved NuGet source (normally https://api.nuget.org/v3/index.json) or pre-populate .tools\nuget, then run GpoRemediator.cmd again.'
}
Write-Host 'Publishing self-contained Windows x64 backend...' -ForegroundColor Cyan
& $dotnet publish $project -c Release -r win-x64 --self-contained true -o $runtime --nologo --no-restore
Assert-Exit
(Get-BackendSourceFingerprint) | Set-Content -LiteralPath (Join-Path $runtime 'backend-source.sha256') -Encoding ASCII -NoNewline
'production-backend-v3' | Set-Content -LiteralPath (Join-Path $runtime 'production-backend-v3.ready') -Encoding ASCII -NoNewline

if (!(Test-PortableBackendMatchesSource)) { throw 'Portable backend fingerprint does not match current source. Do not distribute this package.' }
if (!(Test-FrontendDistMatchesSource)) { throw 'Static frontend fingerprint does not match current source. Do not distribute this package.' }

Write-Host 'Portable Windows x64 application ready. No Node.js/pnpm/npm registry is required.' -ForegroundColor Green
Write-Host 'Run GpoRemediator.cmd. For real AD/GPO use, complete Setup in the built-in Automation Center.' -ForegroundColor Green
