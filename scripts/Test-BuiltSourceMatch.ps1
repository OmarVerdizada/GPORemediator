$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Tooling.ps1')
if(!(Test-FrontendDistMatchesSource)){throw 'Packaged frontend no longer matches current source'}
if(!(Test-PortableBackendMatchesSource)){throw 'Packaged backend no longer matches current source'}
$repo=Split-Path $PSScriptRoot -Parent
$archive=Join-Path $repo 'release/GpoRemediator-runtime-win-x64.zip'
$expected=(Get-Content -LiteralPath ($archive+'.sha256') -Raw).Trim()
if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine $expected){throw 'Release ZIP SHA-256 mismatch'}
Write-Output 'PASS current backend/frontend source fingerprints and distributed runtime ZIP SHA-256'
