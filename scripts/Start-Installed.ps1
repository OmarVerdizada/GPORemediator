param([string]$InstallRoot=(Split-Path $PSScriptRoot -Parent),[switch]$NoBrowser)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($InstallRoot)
# This copy of the wrapper and module is placed at the stable install root.
Import-Module (Join-Path $PSScriptRoot 'ReleasePackage.psm1') -Force
$null=Assert-PackagePath $root
$pointer=Get-Content -LiteralPath (Join-Path $root 'current.json') -Raw -Encoding UTF8|ConvertFrom-Json
$directory=Resolve-PackageChild $root ([string]$pointer.current)
if(!(Test-Path -LiteralPath $directory -PathType Container)){throw 'Installed release is missing. Reinstall the complete verified package.'}
if((Get-PackageHash (Join-Path $directory 'release/package-files.json') $false) -ine [string]$pointer.manifestSha256){throw 'Installed release manifest differs from the activated version.'}
$null=Test-ReleasePackage $directory
if($NoBrowser){& (Join-Path $directory 'GpoRemediator.ps1') -NoBrowser}else{& (Join-Path $directory 'GpoRemediator.cmd')}
