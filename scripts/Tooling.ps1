function Find-Dotnet {
    $candidate = Get-Command dotnet.exe,dotnet -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        try { if ((& $candidate.Source --list-sdks 2>$null) -match '^8\.') { return $candidate.Source } } catch { }
    }
    throw '.NET 8 SDK is required in the approved developer build environment. Production startup never installs a toolchain.'
}
function Assert-Exit { if ($LASTEXITCODE -ne 0) { throw "Build command failed with exit code $LASTEXITCODE." } }

function Get-FileSetFingerprint([System.IO.FileInfo[]]$Files, [string]$BasePath) {
    $lines = [Collections.Generic.List[string]]::new()
    $textExtensions = @('.cs','.csproj','.json','.ps1','.psm1','.js','.cjs','.css','.html','.htm','.md','.txt','.xml','.yml','.yaml')
    foreach ($file in @($Files | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($BasePath.TrimEnd('\').Length).TrimStart('\')
        if ($file.Extension.ToLowerInvariant() -in $textExtensions) {
            # GitHub source archives use LF while Windows checkouts commonly use
            # CRLF. Hash canonical UTF-8/LF text so identical source remains
            # verifiable across both distribution forms.
            $text = [IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n").Replace("`r","`n")
            $canonicalBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
            $fileSha = [Security.Cryptography.SHA256]::Create()
            try { $hash = [BitConverter]::ToString($fileSha.ComputeHash($canonicalBytes)).Replace('-','') } finally { $fileSha.Dispose() }
        } else { $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
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
        $relative = $_.FullName.Substring($backend.TrimEnd('\').Length).TrimStart('\').Replace('\','/')
        if ($relative -match '^(bin|obj)/') { return $false }
        if ($relative -match '^data/') { return $_.Name -in @('benchmark.json','gpo-production-mappings.json') }
        return $_.Extension -in @('.cs','.csproj','.ps1','.psm1') -or $_.Name -eq 'appsettings.json'
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
