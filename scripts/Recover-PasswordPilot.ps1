[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory=$true)][string]$BackupFile)
$ErrorActionPreference='Stop'
$OutputEncoding=[Text.UTF8Encoding]::new($false)
$path=(Resolve-Path -LiteralPath $BackupFile).Path
$plan=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if($plan.id -notmatch '^[a-f0-9]{32}$' -or !$plan.before.userId -or !$plan.domain -or !$plan.domainController){throw 'Not a valid password-pilot backup.'}
$scriptPath=Join-Path $PSScriptRoot '../backend/PowerShell/Invoke-PasswordPilot.ps1'
if(!(Test-Path -LiteralPath $scriptPath)){throw 'Run recovery from a complete source checkout containing the bundled password-pilot script.'}
$target='Pilot PSO ' + $plan.id + ' for ' + $plan.before.user + ' in ' + $plan.domain
if($PSCmdlet.ShouldProcess($target,'Remove the pilot assignment and its unchanged PSO, then verify the prior effective password policy')){
    $request=@{operation='passwordRollback';configuration=@{domain=$plan.domain;domainController=$plan.domainController;backupPath=(Split-Path (Split-Path $path -Parent) -Parent)};payload=@{plan=$plan}}
    $json=$request | ConvertTo-Json -Depth 30 -Compress
    $executable=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $result=$json | & $executable -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptPath
    $result
    if($LASTEXITCODE -ne 0){throw 'Recovery requires review. See the structured result above; do not retry blindly.'}
    $parsed=$result|ConvertFrom-Json
    if(!$parsed.ok -or !$parsed.data.verified){throw 'Previous effective policy was not verified. Review AD state.'}
}
