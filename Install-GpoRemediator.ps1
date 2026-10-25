param(
    [string]$PackagePath,
    [string]$ExpectedSha256,
    [string]$Destination=(Join-Path $env:LOCALAPPDATA 'Programs\GpoRemediator'),
    [switch]$Rollback,
    [switch]$StopRunning,
    [switch]$Start,
    [switch]$DesktopShortcut
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'scripts/ReleasePackage.psm1') -Force
. (Join-Path $PSScriptRoot 'scripts/ServiceControl.ps1')
$root=Assert-PackagePath $Destination
$forbidden=@([IO.Path]::GetPathRoot($root),$env:SystemRoot,$env:USERPROFILE,$env:ProgramFiles,$env:ProgramData,$env:LOCALAPPDATA)|Where-Object{$_}
if($forbidden|Where-Object{[IO.Path]::GetFullPath($_).TrimEnd('\') -ieq $root.TrimEnd('\')}){throw 'Choose a dedicated application install directory.'}
if($env:SystemRoot -and $root.StartsWith([IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Do not install application releases inside Windows.'}
$owner=Join-Path $root 'install-owner.json'
if((Test-Path -LiteralPath $root) -and @(Get-ChildItem -LiteralPath $root -Force).Count){
    if(!(Test-Path -LiteralPath $owner) -or (Get-Content -LiteralPath $owner -Raw|ConvertFrom-Json).product -cne 'GPO Remediator'){throw 'The destination is not a managed install. Choose a new empty directory; existing folders are not overwritten.'}
}
$null=[IO.Directory]::CreateDirectory($root)
$lock=[IO.File]::Open((Join-Path $root '.install.lock'),'OpenOrCreate','ReadWrite','None')
try{
    if(!(Test-Path -LiteralPath $owner)){Write-InstallState $owner @{product='GPO Remediator';format=1}}
    $pointerPath=Join-Path $root 'current.json'
    $old=if(Test-Path -LiteralPath $pointerPath){Get-Content -LiteralPath $pointerPath -Raw -Encoding UTF8|ConvertFrom-Json}else{$null}
    if($Rollback){
        if(!$old -or !$old.previous){throw 'No previous installed release is available.'}
        $relative=[string]$old.previous;$target=Resolve-PackageChild $root $relative;$manifest=Test-ReleasePackage $target
        if((Get-PackageHash (Join-Path $target 'release/package-files.json') $false) -ine [string]$old.previousManifestSha256){throw 'The previous release manifest changed. Automatic activation rollback is blocked.'}
    }else{
        if(!$PackagePath){throw 'Supply -PackagePath FULL.zip and the trusted -ExpectedSha256 (or a matching .sha256 sidecar).'}
        $archive=[IO.Path]::GetFullPath($PackagePath)
        if(!$ExpectedSha256 -and (Test-Path -LiteralPath ($archive+'.sha256'))){$ExpectedSha256=(Get-Content -LiteralPath ($archive+'.sha256') -Raw).Trim()}
        $stage=Join-Path $root ('.stage-'+[guid]::NewGuid().ToString('N'))
        $manifest=Expand-ReleasePackage $archive $ExpectedSha256 $stage
        $relative='versions\'+[string]$manifest.version+'-'+$ExpectedSha256.Substring(0,12).ToLowerInvariant()
        $target=Resolve-PackageChild $root $relative;$null=[IO.Directory]::CreateDirectory((Split-Path $target -Parent))
        if(Test-Path -LiteralPath $target){$null=Test-ReleasePackage $target;if((Get-PackageHash (Join-Path $target 'release/package-files.json') $false) -cne (Get-PackageHash (Join-Path $stage 'release/package-files.json') $false)){throw 'Existing version directory does not match this package.'}}else{Move-Item -LiteralPath $stage -Destination $target}
    }
    if($old){
        if((Get-PackageHash (Join-Path (Resolve-PackageChild $root ([string]$old.current)) 'release/package-files.json') $false) -ine [string]$old.manifestSha256){throw 'The active release manifest changed. Activation was not modified.'}
        $previous=Test-ReleasePackage (Resolve-PackageChild $root ([string]$old.current))
        if([string]$previous.stateSchema -cne [string]$manifest.stateSchema){throw 'State schema changed. This installer will not migrate or roll back application data automatically.'}
    }
    $running=Get-RemediatorService
    if($running){
        if(!$StopRunning){throw 'Verified version staged. Close the running application, or retry with -StopRunning. Active jobs are never interrupted.'}
        $null=Invoke-RemediatorServiceAction stop
        $deadline=[DateTimeOffset]::UtcNow.AddSeconds(30)
        while((Get-RemediatorService) -and [DateTimeOffset]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 300}
        if(Get-RemediatorService){throw 'The service has not stopped. Activation was not changed.'}
    }
    # Stable wrappers are written only after the entire new/previous release validates.
    $scripts=Join-Path $root 'scripts';$null=[IO.Directory]::CreateDirectory($scripts)
    Copy-Item -LiteralPath (Join-Path $target 'scripts/ReleasePackage.psm1') -Destination $scripts -Force
    Copy-Item -LiteralPath (Join-Path $target 'scripts/Start-Installed.ps1') -Destination $scripts -Force
    $launcher='@echo off'+"`r`n"+'powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0scripts\Start-Installed.ps1" -InstallRoot "%~dp0"'+"`r`n"
    [IO.File]::WriteAllText((Join-Path $root 'GpoRemediator.cmd'),$launcher,[Text.ASCIIEncoding]::new())
    $previous=if($old -and [string]$old.current -ine $relative){[string]$old.current}elseif($old){[string]$old.previous}else{''}
    $previousHash=if($old -and [string]$old.current -ine $relative){[string]$old.manifestSha256}elseif($old){[string]$old.previousManifestSha256}else{''}
    Write-InstallState $pointerPath @{product='GPO Remediator';current=$relative;previous=$previous;previousManifestSha256=$previousHash;version=$manifest.version;stateSchema=$manifest.stateSchema;manifestSha256=(Get-PackageHash (Join-Path $target 'release/package-files.json') $false);activatedAt=[DateTimeOffset]::UtcNow.ToString('O')}
    if($DesktopShortcut){try{
        $shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'GPO Remediator.lnk'))
        $link.TargetPath=Join-Path $root 'GpoRemediator.cmd';$link.WorkingDirectory=$root;$link.Save()
    }catch{Write-Warning ('Release activated; desktop shortcut could not be created: '+$_.Exception.Message)}}
    Write-Output ('Activated GPO Remediator '+$manifest.version+' at '+$target+'. ProgramData configuration, databases and backups were preserved.')
}finally{$lock.Dispose()}
if($Start){Start-Process -FilePath (Join-Path $root 'GpoRemediator.cmd') -WindowStyle Hidden}
