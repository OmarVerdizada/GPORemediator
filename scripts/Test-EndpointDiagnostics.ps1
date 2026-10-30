# Real failure formatter and bounded refresh helper with mocked transport only.
# Never contacts an endpoint or runs gpupdate.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Check($Condition,$Message){if(!$Condition){throw $Message};Write-Output ('PASS '+$Message)}
$EndpointCredential=[Management.Automation.PSCredential]::new('EXAMPLE\fixture',(ConvertTo-SecureString 'not-a-real-password' -AsPlainText -Force))
$cfg=@{emitProgress=$false}
function Invoke-Command {
 [CmdletBinding()]
 param($ComputerName,$Authentication,$Credential,$ThrottleLimit,$ScriptBlock)
 if($Authentication -ne 'Kerberos' -or $Credential.UserName -ne 'EXAMPLE\fixture' -or $ThrottleLimit -ne 16){throw 'Wrong transport options'}
 foreach($name in $ComputerName){
  if($name -eq 'ok.example.test'){[pscustomobject]@{PSComputerName=$name;state='COMPLETED';message='Completed fixture'};continue}
  $record=[Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('Access denied; sensitive fixture data must never be returned'),'AccessDenied,PSSessionOpenFailed',[Management.Automation.ErrorCategory]::PermissionDenied,$name)
  Write-Error -ErrorRecord $record
 }
}
$results=@(Refresh-ComputerPolicy @('ok.example.test','denied.example.test'))
Check ($results.Count -eq 2) 'mixed refresh retains every requested host'
Check ($results[0].state -eq 'COMPLETED') 'one denied host does not discard successful refresh'
Check ($results[1].PSComputerName -eq 'denied.example.test' -and $results[1].state -eq 'FAILED' -and $results[1].message -match 'ENDPOINT_ACCESS_DENIED') 'transport failure maps to the denied host with actionable access guidance'
Check ($results[1].message -notmatch 'sensitive fixture|not-a-real-password') 'failure evidence excludes raw exceptions and credentials'
$cfg.emitProgress=$true
$stream=@(Refresh-ComputerPolicy @('ok.example.test','denied.example.test') 6>&1)
$events=@($stream|Where-Object{$_ -is [Management.Automation.InformationRecord]}|ForEach-Object{$_.MessageData.gpoCheck})
Check ($events.Count -eq 4 -and @($events|Where-Object{$_.phase -ne 'REFRESH'}).Count -eq 0 -and @($events|Where-Object{$_.state -eq 'CHECKING'}).Count -eq 2) 'refresh streams each host opening and completion as refresh evidence, not endpoint values'
$cfg.emitProgress=$false
foreach($case in @(
 @{id='112,PSSessionStateBroken';category='OpenError';message='WSMan could not launch a host process';code='ENDPOINT_DISK_FULL'},
 @{id='39,PSSessionStateBroken';category='OpenError';message='Disk full';code='ENDPOINT_DISK_FULL'},
 @{id='KerberosError,PSSessionOpenFailed';category='OpenError';message='Kerberos failed';code='ENDPOINT_AUTHENTICATION_FAILED'},
 @{id='PSSessionOpenFailed';category='OpenError';message='Unavailable';code='ENDPOINT_CONNECTION_FAILED'},
 @{id='NativeToolFailed';category='NotSpecified';message='Unexpected native error';code='ENDPOINT_PROBE_FAILED'},
 @{id='1726,PSSessionStateBroken';category='OpenError';message='Private transport details';code='ENDPOINT_SESSION_BROKEN'},
 @{id='JobFailure';category='NotSpecified';message='Private job details';code='ENDPOINT_JOB_FAILED'}
)){
 $record=[Management.Automation.ErrorRecord]::new([Exception]::new($case.message),$case.id,[Management.Automation.ErrorCategory]$case.category,'pc.example.test')
 Check ((Endpoint-FailureMessage $record) -match $case.code) ('distinct diagnostic: '+$case.code)
}
$wrapped=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Private wrapper text',[ComponentModel.Win32Exception]::new(1726,'Private inner text')),'JobFailure',[Management.Automation.ErrorCategory]::NotSpecified,'pc.example.test')
$description=Endpoint-FailureMessage $wrapped
Check ($description -match 'ENDPOINT_SESSION_BROKEN' -and $description -match '1726' -and $description -notmatch 'Private') 'wrapped JobFailure retains Windows 1726 without exposing native text'
function Invoke-Command {
 [CmdletBinding()]
 param($ComputerName,$Authentication,$Credential,$ArgumentList,$ScriptBlock)
 Write-Error -ErrorRecord ([Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('Access denied'),'AccessDenied,PSSessionOpenFailed',[Management.Automation.ErrorCategory]::PermissionDenied,$ComputerName))
}
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) [pscustomobject]@{DNSHostName='denied.example.test'}}
$cfg=@{domainController='dc.example.test';allowedHosts=@('denied.example.test')}
$plan=@{selection=@{scopeDn='OU=Pilot,DC=example,DC=test'};preview=@{impact=$null;verificationComputers=@('denied.example.test')}}
$map=@{handler='SecurityTemplate';scope='Computer';domainPolicySensitive=$false;requiresInput=$false;allowValueOverride=$false;comparator='>=';items=@(@{section='System Access';key='MinimumPasswordLength';name=$null;type='Integer';guid=$null;value=@('14')})}
$check=@(Verify-EffectiveSamples $plan $map)[0]
Check ($check.state -eq 'UNAVAILABLE' -and $null -eq $check.actualValue -and $check.message -match 'ENDPOINT_ACCESS_DENIED') 'failed effective probe retains its access cause without fabricating a measured value'
