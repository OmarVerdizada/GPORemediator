function Find-Dotnet {
    $portable = Join-Path $PSScriptRoot '..\.tools\dotnet\dotnet.exe'
    if (Test-Path -LiteralPath $portable) { return (Resolve-Path -LiteralPath $portable).Path }
    $candidate = Get-Command dotnet.exe,dotnet -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        try { if ((& $candidate.Source --list-sdks 2>$null) -match '^8\.') { return $candidate.Source } } catch { }
    }
    throw '.NET 8 SDK is required for source builds. The unified GpoRemediator.cmd launcher installs a portable SDK automatically when needed.'
}
function Assert-Exit { if ($LASTEXITCODE -ne 0) { throw "Build command failed with exit code $LASTEXITCODE." } }

function Get-FileSetFingerprint([System.IO.FileInfo[]]$Files, [string]$BasePath) {
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($file in @($Files | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($BasePath.TrimEnd('\').Length).TrimStart('\')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $lines.Add($relative.Replace('\','/') + ':' + $hash)
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
        return [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
    } finally { $sha.Dispose() }
}

function Get-BackendSourceFingerprint {
    $backend = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\backend'))
    $files = @(Get-ChildItem -LiteralPath $backend -Recurse -File | Where-Object {
          ($_.Name -in @('benchmark.json','gpo-production-mappings.json')) -or ($_.FullName -notmatch '[\\/](bin|obj|data)[\\/]' -and
          ($_.Extension -in @('.cs','.csproj','.ps1','.psm1') -or $_.Name -eq 'appsettings.json'))
    })
    return (Get-FileSetFingerprint $files $backend)
}

function Get-FrontendSourceFingerprint {
    $frontend = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\frontend\source'))
    if (!(Test-Path -LiteralPath $frontend)) { return '' }
    $files = @(Get-ChildItem -LiteralPath $frontend -Recurse -File | Where-Object { $_.Name -ne 'source.sha256' })
    return (Get-FileSetFingerprint $files $frontend)
}

function Test-PortableBackendMatchesSource {
    $manifest = Join-Path $PSScriptRoot '..\runtime\backend-source.sha256'
    if (!(Test-Path -LiteralPath $manifest)) { return $false }
    return ((Get-Content -LiteralPath $manifest -Raw).Trim() -ceq (Get-BackendSourceFingerprint))
}

function Test-FrontendDistMatchesSource {
    $manifest = Join-Path $PSScriptRoot '..\frontend\dist\source.sha256'
    if (!(Test-Path -LiteralPath $manifest)) { return $false }
    return ((Get-Content -LiteralPath $manifest -Raw).Trim() -ceq (Get-FrontendSourceFingerprint))
}
