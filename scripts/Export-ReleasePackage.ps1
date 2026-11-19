param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (!$OutputDirectory) { $OutputDirectory = Join-Path $root 'work/releases' }
Import-Module (Join-Path $PSScriptRoot 'ReleasePackage.psm1') -Force

$manifestPath = 'release/package-files.json'
$manifest = Get-Content -LiteralPath (Join-Path $root $manifestPath) -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.product -cne 'GPO Remediator' -or [string]$manifest.version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'The release manifest is invalid. Build the portable release first.'
}

$output = Assert-PackagePath $OutputDirectory
$null = [IO.Directory]::CreateDirectory($output)
$archive = Join-Path $output ('GPORemediator-' + $manifest.version + '-win-x64.zip')
if ((Test-Path -LiteralPath $archive) -or (Test-Path -LiteralPath ($archive + '.sha256'))) {
    throw 'The release output already exists. Choose a new output directory.'
}

$staging = Join-Path $output ('.package-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($staging)
try {
    foreach ($path in @($manifest.files.path) + @($manifestPath)) {
        $source = Assert-PackagePath (Resolve-PackageChild $root $path)
        $destination = Resolve-PackageChild $staging $path
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        [IO.File]::Copy($source, $destination)
    }
    $null = Test-ReleasePackage $staging

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $temporaryArchive = Join-Path $staging 'package.tmp'
    $zip = [IO.Compression.ZipFile]::Open($temporaryArchive, 'Create')
    try {
        foreach ($path in @($manifest.files.path) + @($manifestPath)) {
            $file = Resolve-PackageChild $staging $path
            $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $file, ('GPORemediator/' + $path), [IO.Compression.CompressionLevel]::Optimal)
        }
    } finally {
        $zip.Dispose()
    }
    [IO.File]::Move($temporaryArchive, $archive)
    $hash = Get-PackageHash $archive $false
    [IO.File]::WriteAllText($archive + '.sha256', $hash, [Text.Encoding]::ASCII)
    Write-Output ([pscustomobject]@{ Archive = $archive; Sha256 = $hash })
} finally {
    $resolved = (Get-Item -LiteralPath $staging -Force).FullName
    if ([IO.Path]::GetDirectoryName($resolved) -ieq $output.TrimEnd('\') -and
        [IO.Path]::GetFileName($resolved) -match '^\.package-[a-f0-9]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
