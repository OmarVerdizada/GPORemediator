param(
    [ValidateRange(1024,65535)][int]$Port=5080,
    [ValidateSet('Install','Status','Remove')][string]$Action='Install',
    [string]$ProjectRoot=(Split-Path $PSScriptRoot -Parent),
    [switch]$InitializeFreshMachineState,
    [string]$ConfirmFreshState
)
$ErrorActionPreference='Stop'
$taskName='GPO Remediator Policy Operations'
$root=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
$installedWrapper=Join-Path $root 'scripts\Start-Installed.ps1'
$installed=(Test-Path -LiteralPath (Join-Path $root 'current.json') -PathType Leaf) -and (Test-Path -LiteralPath $installedWrapper -PathType Leaf)
$launcher=if($installed){$installedWrapper}else{Join-Path $root 'GpoRemediator.ps1'}

function Assert-Administrator {
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'MACHINE_SERVICE_ADMIN_REQUIRED: Run this script once from an elevated Windows PowerShell window.'}
}

function Clear-SensitiveBytes {
    param([byte[]]$Bytes)
    if($null -ne $Bytes -and $Bytes.Length -gt 0){[Array]::Clear($Bytes,0,$Bytes.Length)}
}

function Convert-AuditKeyToMachineScope {
    $keyPath=Join-Path $env:ProgramData 'GpoRemediator\Data\audit-hmac-key.dpapi'
    if(!(Test-Path -LiteralPath $keyPath -PathType Leaf)){return 'No existing audit key required migration.'}
    if((Get-Item -LiteralPath $keyPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'MACHINE_SERVICE_KEY_LINK: Audit key cannot be a symbolic link.'}
    Add-Type -AssemblyName System.Security
    $entropy=[Text.Encoding]::UTF8.GetBytes('GPORemediator.AuditHmac.v1')
    $sealed=[IO.File]::ReadAllBytes($keyPath);$plain=$null;$replacement=$null
    try {
        try {
            $plain=[Security.Cryptography.ProtectedData]::Unprotect($sealed,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
            if($plain.Length -ne 32){throw 'Invalid machine audit key length.'}
            return 'Audit key already uses computer-scoped DPAPI.'
        } catch {
            if($plain){Clear-SensitiveBytes $plain;$plain=$null}
            try {$plain=[Security.Cryptography.ProtectedData]::Unprotect($sealed,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)}
            catch {throw 'MACHINE_SERVICE_KEY_MIGRATION: The existing audit key belongs to another Windows DPAPI profile or computer. Run as its original identity, or explicitly preserve the incompatible state and initialize a fresh machine state.'}
            if($plain.Length -ne 32){throw 'MACHINE_SERVICE_KEY_LENGTH: Existing audit key is invalid.'}
            $replacement=[Security.Cryptography.ProtectedData]::Protect($plain,$entropy,[Security.Cryptography.DataProtectionScope]::LocalMachine)
            $temp=$keyPath+'.machine-'+[guid]::NewGuid().ToString('N')+'.tmp'
            [IO.File]::WriteAllBytes($temp,$replacement)
            try {[IO.File]::Replace($temp,$keyPath,$null)} finally {if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
            return 'Audit key migrated to computer-scoped DPAPI; the audit database was preserved.'
        }
    } finally {
        if($plain){Clear-SensitiveBytes $plain}
        if($replacement){Clear-SensitiveBytes $replacement}
        Clear-SensitiveBytes $sealed
        Clear-SensitiveBytes $entropy
    }
}

function Reset-BrowserProtectionKeys {
    $keys=Join-Path $env:ProgramData 'GpoRemediator\Data\Keys'
    if(!(Test-Path -LiteralPath $keys -PathType Container)){return 'No browser protection keys required rotation.'}
    $files=@(Get-ChildItem -LiteralPath $keys -File -Force -ErrorAction Stop)
    if(!$files.Count){return 'No browser protection keys required rotation.'}
    $recovery=Join-Path $env:ProgramData ('GpoRemediator\Recovery\PreMachineServiceKeys-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
    $null=New-Item -ItemType Directory -Path $recovery -Force
    foreach($file in $files){Move-Item -LiteralPath $file.FullName -Destination (Join-Path $recovery $file.Name)}
    return ('Browser session keys rotated for the machine service; prior local cookies were invalidated. Previous encrypted key files were preserved at '+$recovery+'.')
}

function Preserve-IncompatibleState {
    if(!$InitializeFreshMachineState -or $ConfirmFreshState -cne 'PRESERVE_AND_INITIALIZE'){
        throw 'MACHINE_SERVICE_FRESH_STATE_CONFIRMATION: Re-run with -InitializeFreshMachineState -ConfirmFreshState PRESERVE_AND_INITIALIZE only if the old DPAPI profile is unavailable. Existing state will be preserved, not deleted, and the active audit history will start fresh.'
    }
    $stateRoot=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'GpoRemediator')).TrimEnd('\')
    $expected=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'GpoRemediator')).TrimEnd('\')
    if($stateRoot -cne $expected -or !(Test-Path -LiteralPath $stateRoot -PathType Container)){throw 'MACHINE_SERVICE_STATE_PATH: The exact legacy state root was not found.'}
    $item=Get-Item -LiteralPath $stateRoot -Force
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'MACHINE_SERVICE_STATE_LINK: Legacy state cannot be a junction or symbolic link.'}
    $suffix=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
    $preserved=Join-Path $env:ProgramData ('GpoRemediator.LegacyState-'+$suffix)
    if(Test-Path -LiteralPath $preserved){throw 'MACHINE_SERVICE_STATE_COLLISION: The preservation target already exists.'}
    Move-Item -LiteralPath $stateRoot -Destination $preserved -ErrorAction Stop
    return [IO.Path]::GetFullPath($preserved)
}

if($Action -eq 'Status'){
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if(!$task){[pscustomobject]@{Installed=$false;Task=$taskName;State='NotInstalled'};exit 0}
    [pscustomobject]@{Installed=$true;Task=$taskName;State=[string]$task.State;Principal=[string]$task.Principal.UserId;ProjectRoot=$root};exit 0
}

Assert-Administrator
if($Action -eq 'Remove'){
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    Write-Output 'Removed the machine startup task. ProgramData, configuration, audit history and backups were not deleted.'
    exit 0
}
if(!(Test-Path -LiteralPath $launcher -PathType Leaf)){throw 'MACHINE_SERVICE_LAUNCHER_MISSING: GpoRemediator.ps1 was not found in the selected project root.'}
if((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'MACHINE_SERVICE_PROJECT_LINK: Project root cannot be a symbolic link or junction.'}

. (Join-Path $root 'scripts\ServiceControl.ps1')
$running=Get-RemediatorService
if($running){$null=Invoke-RemediatorServiceAction stop}
$preservedState=''
try {$migration=Convert-AuditKeyToMachineScope}
catch {
    if($_.Exception.Message -notmatch '^MACHINE_SERVICE_KEY_MIGRATION:'){throw}
    $preservedState=Preserve-IncompatibleState
    $migration=('The incompatible user-bound state was preserved unchanged at '+$preservedState+'. A fresh machine-scoped audit history will be initialized.')
}
$rotation=Reset-BrowserProtectionKeys

$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments=if($installed){'-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -InstallRoot "{1}" -NoBrowser' -f $launcher,$root}else{'-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Port {1} -NoBrowser' -f $launcher,$Port}
$taskAction=New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $root
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
$null=Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Description 'Computer-wide GPO Remediator backend. Interactive Windows sessions connect through localhost and are audited separately.' -Force
Start-ScheduledTask -TaskName $taskName

$deadline=[DateTimeOffset]::UtcNow.AddSeconds(45);$ready=$false
do {
    Start-Sleep -Milliseconds 500
    try {
        $response=Invoke-WebRequest -UseBasicParsing -Uri ('http://127.0.0.1:{0}/api/v1/health/live' -f $Port) -TimeoutSec 2
        $payload=$response.Content|ConvertFrom-Json
        if($response.StatusCode -eq 200 -and [string]$payload.status -ceq 'live' -and [string]$payload.apiVersion -ceq '1.0' -and [string]$payload.productVersion -match '^3\.'){$ready=$true}
    }
    catch { }
} until($ready -or [DateTimeOffset]::UtcNow -ge $deadline)
if(!$ready){throw 'MACHINE_SERVICE_NOT_READY: The startup task was registered, but the backend did not become healthy. Review the protected startup diagnostics and Task Scheduler history.'}
Write-Output $migration
Write-Output $rotation
if($preservedState){Write-Output ('Preserved legacy state: '+$preservedState)}
Write-Output ('Machine service installed and healthy. Any Windows session may now open http://127.0.0.1:'+ $Port +'; each caller is authenticated and audited as that Windows identity.')
