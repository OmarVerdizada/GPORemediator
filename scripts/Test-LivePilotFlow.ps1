# Run the real pilot entry point in a child process with an in-memory HTTP transport.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$temp=Join-Path ([IO.Path]::GetTempPath()) ('gpr-pilot-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
$wrapper=Join-Path $temp 'fixture.ps1'
@'
param($Runner,$Output,$Scenario)
$ErrorActionPreference='Stop';$global:fixtureScenario=$Scenario;$global:fixtureRolledBack=$false;$global:applyCount=0;$global:rollbackCount=0
function Get-Credential {param($Message) [pscredential]::new('EXAMPLE\fixture',(ConvertTo-SecureString ([guid]::NewGuid().ToString('N')) -AsPlainText -Force))}
function Invoke-WebRequest {
 param($Uri,$UseBasicParsing,$UseDefaultCredentials,$WebSession,$TimeoutSec,$ErrorAction,$Method,$ContentType,$Body,$Headers)
 $path=([uri]$Uri).AbsolutePath;$gpo='11111111-1111-1111-1111-111111111111';$ou='OU=Pilot,DC=example,DC=test'
 $mapping=@{scope='Computer';automation='Automated';requiresInput=$false;requiresRestart=$false;domainPolicySensitive=$false;id='18.1.1.1';suggested=1}
 $value=switch -Regex ($path){
  '/session$' {@{mode='WINDOWS';csrfToken='fixture'}}
  '/operator/sign-in$' {@{confirmed=$true;connected=$true}}
  '/service$' {@{writesEnabled=$true}}
  '/gpo/settings$' {$mapping}
  '/gpo/preview$' {@{id='fixture-plan';selection=@{gpoId=$gpo;scopeDn=$ou};writeAuthorized=$true;preview=@{gpo=@{protected=$false};noChange=$false;preflight=@{ready=$true};verificationComputers=@('pc.example.test');impact=@{existingLinkScopes=@($ou);affectedObjects=@{computers=1;truncated=$false}}}}}
  '/explain$' {@{hostname='pc.example.test';effectiveChecks=@(@{state=$(if($global:fixtureScenario -eq 'baseline-denied'){'UNAVAILABLE'}else{'MISMATCH'});actualValue=$(if($global:fixtureRolledBack -and $global:fixtureScenario -eq 'restore-diff'){'changed'}else{'baseline'})})}}
  '/apply$' {$global:applyCount++;if($global:fixtureScenario -eq 'unknown-apply'){throw 'fixture interrupted transport'};@{result=@{state='PUBLISHED';backupId='fixture-backup'}}}
  '/refresh$' {@{result=@{state='REFRESH_COMPLETED';refreshResults=@(@{computer='pc.example.test';state='COMPLETED'})}}}
  '/verify$' {@{result=@{state='VERIFIED';effectiveStatus='VERIFIED_ON_ALL_TARGETS';verification=@{replicationConverged=$true}}}}
  '/rollback$' {$global:rollbackCount++;$global:fixtureRolledBack=$true;@{result=@{state='ROLLED_BACK'}}}
  default {throw ('Unexpected fixture path '+$path)}
 }
 [pscustomobject]@{Content=($value|ConvertTo-Json -Depth 30 -Compress)}
}
try{& $Runner -GpoId '11111111-1111-1111-1111-111111111111' -OuDn 'OU=Pilot,DC=example,DC=test' -ControlId '18.1.1.1' -Confirmation 'RUN PILOT' -OutputDirectory $Output}
finally{@{apply=$global:applyCount;rollback=$global:rollbackCount}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Output 'calls.json') -Encoding UTF8}
exit $LASTEXITCODE
'@|Set-Content -LiteralPath $wrapper -Encoding UTF8
try{
 foreach($scenario in @('complete','baseline-denied','unknown-apply','restore-diff')){
  $out=Join-Path $temp $scenario;$null=New-Item -ItemType Directory -Path $out
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wrapper -Runner (Join-Path $PSScriptRoot 'Invoke-LivePilot.ps1') -Output $out -Scenario $scenario *> (Join-Path $out 'console.txt');$code=$LASTEXITCODE
  $reportFile=Get-ChildItem -LiteralPath $out -Recurse -Filter pilot-report.json|Select-Object -First 1
  if(!$reportFile){throw ('No report for '+$scenario+': '+(Get-Content (Join-Path $out 'console.txt') -Raw))}
  $report=Get-Content -LiteralPath $reportFile.FullName -Raw|ConvertFrom-Json;$calls=Get-Content -LiteralPath (Join-Path $out 'calls.json') -Raw|ConvertFrom-Json
  switch($scenario){
   'complete' {if($code -ne 0 -or $report.state -ne 'CONFIGURATION_LIFECYCLE_VERIFIED' -or $calls.apply -ne 1 -or $calls.rollback -ne 1){throw ('Successful fixture lifecycle failed: '+$report.state+' exit='+$code+' calls='+($calls|ConvertTo-Json -Compress)+' log='+(Get-Content (Join-Path $out 'console.txt') -Raw))}}
   'baseline-denied' {if($code -eq 0 -or $calls.apply -ne 0 -or $calls.rollback -ne 0){throw ('Unavailable baseline permitted write: '+$report.state+' code='+$code+' calls='+($calls|ConvertTo-Json -Compress))}}
   'unknown-apply' {if($code -eq 0 -or $calls.apply -ne 1 -or $calls.rollback -ne 0){throw 'Unknown apply outcome blindly retried or rolled back'}}
   'restore-diff' {if($code -eq 0 -or $report.state -ne 'RESTORED_REVIEW_REQUIRED' -or $calls.rollback -ne 1){throw 'Different restored endpoint values falsely certified'}}
  }
  Write-Output ('PASS actual pilot runner / '+$scenario+' / '+$report.state+'; no AD contacted')
 }
}finally{
 $resolved=[IO.Path]::GetFullPath($temp)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-pilot-*'){throw 'Unsafe fixture path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
