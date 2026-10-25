# Actual installer/package engine with tiny release archives and a fake service API.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $PSScriptRoot 'ReleasePackage.psm1') -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
$temp=Join-Path ([IO.Path]::GetTempPath()) ('gpr-installer-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path (Join-Path $temp 'tools/scripts') -Force
Copy-Item -LiteralPath (Join-Path $repo 'Install-GpoRemediator.ps1') -Destination (Join-Path $temp 'tools')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ReleasePackage.psm1') -Destination (Join-Path $temp 'tools/scripts')
@'
function Get-RemediatorService {if($env:GPOR_FIXTURE_BUSY -eq '1'){@{running=$true}}}
function Invoke-RemediatorServiceAction {throw 'fixture active operation; stop denied'}
'@|Set-Content (Join-Path $temp 'tools/scripts/ServiceControl.ps1') -Encoding UTF8
$installer=Join-Path $temp 'tools/Install-GpoRemediator.ps1';$destination=Join-Path $temp 'install'
function Check($Ok,$Name){if(!$Ok){throw $Name};Write-Output ('PASS '+$Name)}
function Reject($Block,$Name){try{& $Block|Out-Null;throw ('Accepted: '+$Name)}catch{if($_.Exception.Message -like 'Accepted:*'){throw}};Write-Output ('PASS '+$Name)}
function Package([string]$Version,[string]$Schema='3.1.2'){
 $dir=Join-Path $temp ('source-'+$Version+'-'+$Schema);$null=New-Item -ItemType Directory -Path (Join-Path $dir 'release'),(Join-Path $dir 'scripts') -Force
 foreach($name in @('GpoRemediator.cmd','GpoRemediator.ps1','Control-Panel.ps1','release/GpoRemediator-runtime-win-x64.zip','release/GpoRemediator-runtime-win-x64.zip.sha256')){[IO.File]::WriteAllText((Join-Path $dir $name),'fixture '+$Version,[Text.UTF8Encoding]::new($false))}
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ReleasePackage.psm1'),(Join-Path $PSScriptRoot 'Start-Installed.ps1') -Destination (Join-Path $dir 'scripts')
 $files=@(Get-ChildItem -LiteralPath $dir -Recurse -File|ForEach-Object{@{path=$_.FullName.Substring($dir.Length+1).Replace('\','/');mode='binary';sha256=(Get-PackageHash $_.FullName $false)}})
 Write-InstallState (Join-Path $dir 'release/package-files.json') @{product='GPO Remediator';format=1;version=$Version;stateSchema=$Schema;files=$files}
 $zip=Join-Path $temp ($Version+'-'+$Schema+'.zip');$archive=[IO.Compression.ZipFile]::Open($zip,'Create')
 try{foreach($file in Get-ChildItem -LiteralPath $dir -Recurse -File){$null=[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$file.FullName,('GPORemediator/'+$file.FullName.Substring($dir.Length+1).Replace('\','/')))}}finally{$archive.Dispose()}
 return @{zip=$zip;hash=(Get-PackageHash $zip $false)}
}
function Pointer {Get-Content -LiteralPath (Join-Path $destination 'current.json') -Raw|ConvertFrom-Json}
$previousBusy=$env:GPOR_FIXTURE_BUSY
try{
 $a=Package '3.16.0';$b=Package '3.16.1';$incompatible=Package '4.0.0' '4.0.0'
 Reject {& $installer -PackagePath $a.zip -ExpectedSha256 ('0'*64) -Destination $destination} 'wrong full-package hash rejected'
 & $installer -PackagePath $a.zip -ExpectedSha256 $a.hash -Destination $destination|Out-Null
 Check ((Pointer).version -eq '3.16.0') 'failed first install can resume safely and activate complete release'
 $sentinel=Join-Path $destination 'preserved-state.json';[IO.File]::WriteAllText($sentinel,'configuration/database/backup fixture');$before=Get-PackageHash $sentinel $false
 $env:GPOR_FIXTURE_BUSY='1'
 Reject {& $installer -PackagePath $b.zip -ExpectedSha256 $b.hash -Destination $destination -StopRunning} 'active operation stop rejection retains active version'
 Check ((Pointer).version -eq '3.16.0') 'failed update does not activate partially staged files'
 $env:GPOR_FIXTURE_BUSY='0'
 & $installer -PackagePath $b.zip -ExpectedSha256 $b.hash -Destination $destination|Out-Null
 Check ((Pointer).version -eq '3.16.1' -and (Get-PackageHash $sentinel $false) -eq $before) 'whole-package update preserves external state'
 & $installer -Destination $destination -Rollback|Out-Null
 Check ((Pointer).version -eq '3.16.0' -and (Get-PackageHash $sentinel $false) -eq $before) 'activation rollback restores previous compatible release without data rollback'
 Reject {& $installer -PackagePath $incompatible.zip -ExpectedSha256 $incompatible.hash -Destination $destination} 'incompatible state schema cannot auto activate'
 $current=Resolve-PackageChild $destination ([string](Pointer).current)
 [IO.File]::AppendAllText((Join-Path $current 'GpoRemediator.ps1'),'tampered')
 Reject {Test-ReleasePackage $current} 'mixed/tampered installed component rejected'
 foreach($path in @('../escape','C:\escape','folder/../../escape','file:stream')){Reject {Resolve-PackageChild $temp $path} 'unsafe package child rejected'}
 $attack=Join-Path $temp 'traversal.zip';$z=[IO.Compression.ZipFile]::Open($attack,'Create');$entry=$z.CreateEntry('GPORemediator/../../escaped.txt');$stream=$entry.Open();$stream.WriteByte(65);$stream.Dispose();$z.Dispose()
 Reject {Expand-ReleasePackage $attack (Get-PackageHash $attack $false) (Join-Path $temp 'attack-stage')} 'archive traversal rejected even with matching archive hash'
 Check (!(Test-Path -LiteralPath (Join-Path $temp 'escaped.txt'))) 'extraction never writes outside stage'
 Write-Output 'PASS actual installer lifecycle with fixtures; no real app or ProgramData modified.'
}finally{
 $env:GPOR_FIXTURE_BUSY=$previousBusy
 $resolved=[IO.Path]::GetFullPath($temp)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-installer-*'){throw 'Unsafe fixture path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
