# Deterministic, cross-platform text hashing and bounded Windows package validation.
Set-StrictMode -Version Latest
function Get-PackageHash([string]$Path,[bool]$Text){
    if(!$Text){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
    $content=[IO.File]::ReadAllText($Path).Replace("`r`n","`n").Replace("`r","`n")
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($content))).Replace('-','')}finally{$sha.Dispose()}
}
function Assert-PackagePath([string]$Path){
    $full=[IO.Path]::GetFullPath($Path)
    for($entry=[IO.DirectoryInfo]::new($full);$null -ne $entry;$entry=$entry.Parent){
        $item=Get-Item -LiteralPath $entry.FullName -Force -ErrorAction SilentlyContinue
        if($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Package/install paths cannot contain junctions or symbolic links.'}
    }
    return $full
}
function Resolve-PackageChild([string]$Root,[string]$Relative){
    if(!$Relative -or [IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|[\\/])\.\.([\\/]|$)|[:\x00-\x1f]' -or ($Relative -split '[\\/]').Count -gt 64){throw 'Package contains an unsafe relative path.'}
    $rootFull=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    $child=[IO.Path]::GetFullPath((Join-Path $rootFull $Relative))
    if(!$child.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)){throw 'Package path escaped its root.'}
    return $child
}
function Test-ReleasePackage([string]$Root){
    $rootFull=Assert-PackagePath $Root
    $manifestPath=Join-Path $rootFull 'release\package-files.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json
    if($manifest.product -cne 'GPO Remediator' -or $manifest.format -ne 1 -or [string]$manifest.version -notmatch '^\d+\.\d+\.\d+$' -or [string]$manifest.stateSchema -notmatch '^\d+\.\d+\.\d+$'){throw 'Unsupported release package manifest.'}
    $files=@($manifest.files);if(!$files.Count -or $files.Count -gt 20000){throw 'Invalid release file count.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($file in $files){
        if(!$seen.Add([string]$file.path) -or [string]$file.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or [string]$file.mode -notin @('text-lf','binary')){throw 'Invalid or duplicate release file entry.'}
        $path=Resolve-PackageChild $rootFull ([string]$file.path);$null=Assert-PackagePath $path
        if(!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-PackageHash $path ($file.mode -eq 'text-lf')) -ine [string]$file.sha256){throw ('Incomplete/mixed release: '+$file.path)}
    }
    foreach($required in @('GpoRemediator.cmd','GpoRemediator.ps1','Control-Panel.ps1','scripts/ReleasePackage.psm1','scripts/Start-Installed.ps1','release/GpoRemediator-runtime-win-x64.zip','release/GpoRemediator-runtime-win-x64.zip.sha256')){
        if(!$seen.Contains($required)){throw ('Required component absent from release manifest: '+$required)}
    }
    foreach($item in Get-ChildItem -LiteralPath $rootFull -File){if($item.Extension -in @('.ps1','.cmd','.exe','.dll') -and !$seen.Contains($item.Name)){throw ('Unexpected root executable/source: '+$item.Name)}}
    # Unexpected executable/source files in application directories are not accepted.
    foreach($folder in @('backend','frontend','scripts','security','release')){
        $directory=Join-Path $rootFull $folder
        if(!(Test-Path -LiteralPath $directory)){continue}
        foreach($item in Get-ChildItem -LiteralPath $directory -Recurse -File -Force){
            $relative=$item.FullName.Substring($rootFull.TrimEnd('\').Length+1).Replace('\','/')
            if($relative -eq 'release/package-files.json'){continue}
            if(!$seen.Contains($relative)){throw ('Unexpected component in release: '+$relative)}
        }
    }
    return $manifest
}
function Expand-ReleasePackage([string]$Archive,[string]$ExpectedSha256,[string]$Stage){
    if($ExpectedSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or (Get-PackageHash $Archive $false) -ine $ExpectedSha256){throw 'The full package SHA-256 does not match the trusted expected hash.'}
    $stageFull=Assert-PackagePath $Stage
    if(Test-Path -LiteralPath $stageFull){throw 'Extraction stage must be a new directory.'}
    $null=[IO.Directory]::CreateDirectory($stageFull)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip=[IO.Compression.ZipFile]::OpenRead([IO.Path]::GetFullPath($Archive))
    try{
        if($zip.Entries.Count -gt 20000 -or ($zip.Entries|Measure-Object Length -Sum).Sum -gt 536870912){throw 'Release archive exceeds the bounded package size.'}
        $roots=@($zip.Entries|Where-Object{$_.Name}|ForEach-Object{($_.FullName -split '/')[0]}|Sort-Object -Unique)
        if($roots.Count -ne 1){throw 'The release must have one top-level application directory.'}
        $prefix=$roots[0]+'/'
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($entry in $zip.Entries){
            if(!$entry.Name){continue}
            if(!$entry.FullName.StartsWith($prefix,[StringComparison]::Ordinal)){throw 'Invalid archive root.'}
            if((([int64]$entry.ExternalAttributes -shr 16) -band 61440) -eq 40960 -or ($entry.ExternalAttributes -band 1024) -ne 0){throw 'Release archive cannot contain file links.'}
            $relative=$entry.FullName.Substring($prefix.Length)
            if(!$seen.Add($relative)){throw 'Duplicate archive path.'}
            $path=Resolve-PackageChild $stageFull $relative;$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
            $inputStream=$entry.Open();$output=[IO.File]::Open($path,'CreateNew','Write','None')
            try{$inputStream.CopyTo($output)}finally{$output.Dispose();$inputStream.Dispose()}
        }
    }finally{$zip.Dispose()}
    return Test-ReleasePackage $stageFull
}
function Write-InstallState([string]$Path,$State){
    $temp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    [IO.File]::WriteAllText($temp,($State|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temp,$Path,[NullString]::Value)}else{[IO.File]::Move($temp,$Path)}
}
Export-ModuleMember -Function Get-PackageHash,Assert-PackagePath,Resolve-PackageChild,Test-ReleasePackage,Expand-ReleasePackage,Write-InstallState
