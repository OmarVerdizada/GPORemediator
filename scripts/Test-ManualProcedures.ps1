# Parse all generated scripts; execute representative complete procedures with
# AD/GroupPolicy calls mocked and SYSVOL/backups redirected into a short temporary
# fixture tree (Windows PowerShell 5.1 uses legacy path limits). No live AD.
param([Parameter(Mandatory=$true)][string]$FixturePath)
$ErrorActionPreference='Stop';$WarningPreference='SilentlyContinue'
Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$rows=Get-Content -LiteralPath $FixturePath -Raw|ConvertFrom-Json
# Load the stock file-hash function before mocking Import-Module, otherwise its
# module auto-loader can be intercepted by the AD-only import fixture.
$null=Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $FixturePath -Algorithm SHA256
function Assert-Test($Condition,[string]$Message){if(!$Condition){throw $Message}}
foreach($row in $rows){
 $tokens=$null;$errors=$null
 $null=[Management.Automation.Language.Parser]::ParseInput($row.script,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($row.id+' / '+$row.action+': '+($errors|Out-String))}
}
$sandbox=Join-Path ([IO.Path]::GetTempPath()) ('gpm-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $sandbox
function Import-Module {param($Name,$ErrorAction) if($Name -notin @('ActiveDirectory','GroupPolicy')){throw 'Unexpected module import'}}
function Get-ADDomain {param($Identity,$Server) [pscustomobject]@{DNSRoot='example.test';DistinguishedName='DC=example,DC=test';NetBIOSName='EXAMPLE'}}
function Get-ADDomainController {param($Identity,$Server) [pscustomobject]@{IsReadOnly=$script:readOnlyDc;Domain='example.test';HostName=($env:COMPUTERNAME+'.example.test')}}
function Get-CimInstance {param($ClassName,$Filter) if($ClassName -ne 'Win32_Share'){throw 'Unexpected CIM call'};[pscustomobject]@{Path=$script:share}}
function Get-GPO {param($Guid,$Domain,$Server) Assert-Test ($Domain -is [string] -and $Domain -eq 'example.test') 'Domain name was overwritten by an AD domain object';[pscustomobject]@{Id=$Guid;DisplayName='Fixture GPO';GpoStatus='AllSettingsEnabled'}}
function Get-ADOrganizationalUnit {param($Identity,$Filter,$Server,$Properties,$ResultSetSize) if($Identity){[pscustomobject]@{DistinguishedName=$Identity;Name='Fixture OU'}}else{@('OU=Endpoints,DC=example,DC=test','OU=Users,DC=example,DC=test')|ForEach-Object{[pscustomobject]@{DistinguishedName=$_;Name='Fixture';gPLink=(Fixture-Link $_)}}}}
function Fixture-Link([string]$Dn){if($script:linkedTarget -eq $Dn){return ('[LDAP://CN='+$script:gpoId.ToString('B')+',CN=Policies,CN=System,DC=example,DC=test;0]')};return ''}
function Get-ADRootDSE {param($Server) [pscustomobject]@{configurationNamingContext='CN=Configuration,DC=example,DC=test'}}
function Get-ADObject {
 param($Identity,$Server,$Properties,$Filter,$SearchBase,$ResultSetSize)
 if($Filter){return @()}
 if($Identity -match '^CN=\{'){
  return [pscustomobject]@{DistinguishedName=$Identity;versionNumber=$script:version;gPCMachineExtensionNames=$script:extensions;gPCUserExtensionNames='';flags=0;whenChanged=[datetime]::new(2026,1,1).AddSeconds($script:version);gPCWQLFilter=$null}
 }
 [pscustomobject]@{gPLink=(Fixture-Link $Identity)}
}
function Get-GPPermission {param($Guid,[switch]$All,$Domain,$Server) @()}
function Get-GPInheritance {
 param($Target,$Domain,$Server)
 $links=@();if($script:linkedTarget -eq $Target){$links=@([pscustomobject]@{GpoId=$script:gpoId;Order=$script:linkOrder;Enforced=$false;Enabled=$true})}
 [pscustomobject]@{GpoLinks=$links}
}
function Get-GPRegistryValue {
 param($Guid,$Key,$ValueName,$Domain,$Server,$ErrorAction)
 $entry=$script:registry[$Key+'|'+$ValueName]
 if(!$entry){Write-Error 'Fixture policy not configured' -ErrorId UnableToRetrievePolicyRegistryItem -ErrorAction Stop}
 [pscustomobject]@{Value=$entry.value;Type=$entry.type}
}
function Advance-Version {$script:version++;[IO.File]::WriteAllText((Join-Path $script:folder 'GPT.INI'),("[General]`r`nVersion="+$script:version+"`r`n"))}
function Set-GPRegistryValue {
 param($Guid,$Key,$ValueName,$Type,$Value,$Domain,$Server)
 Assert-Test ($Domain -eq 'example.test' -and $Server -eq 'dc.example.test') 'Registry write escaped pinned domain/DC'
 Assert-Test ($script:events -contains 'backup') 'Policy write occurred before backup'
 $script:events.Add('write');$script:registry[$Key+'|'+$ValueName]=@{value=$Value;type=$Type};Advance-Version
 if($script:failure -eq 'write'){throw 'Fixture partial write failure'}
}
function Set-ADObject {
 param($Identity,$Server,$Replace)
 Assert-Test ($script:events -contains 'backup') 'Metadata write occurred before backup'
 $script:events.Add('write');$script:version=$Replace.versionNumber;$script:extensions=$Replace.gPCMachineExtensionNames
}
function New-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order=2) Assert-Test ($script:events -contains 'backup') 'Link write occurred before backup';$script:events.Add('link');$script:linkedTarget=$Target;$script:linkOrder=[int]$Order}
function Set-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order) $script:events.Add('link');$script:linkedTarget=$Target;if($Order){$script:linkOrder=[int]$Order}}
function Read-Host {param($Prompt) $script:events.Add('confirm');if($script:failure -eq 'cancel'){return 'CANCEL'};return ('APPLY '+$script:control+' '+$script:gpoId.ToString())}
function Backup-GPO {
 param($Guid,$Path,$Domain,$Server,$Comment)
 $script:events.Add('backup')
 if($script:failure -eq 'backup'){throw 'Fixture backup failure'}
 if($script:failure -eq 'drift'){Advance-Version}
 [pscustomobject]@{Id=[guid]'22222222-2222-2222-2222-222222222222'}
}
function Run-Fixture([string]$Id,[string]$Action,[string]$Failure=''){
 $script:control=$Id;$script:failure=$Failure;$script:readOnlyDc=$Failure -eq 'dc';$script:linkedTarget='';$script:linkOrder=2
 $script:events=New-Object 'System.Collections.Generic.List[string]';$script:registry=@{};$script:version=7;$script:extensions=''
 $case=Join-Path $sandbox ([guid]::NewGuid().ToString('N').Substring(0,8));$script:share=Join-Path $case 's';$backupRoot=Join-Path $case 'Backups'
 $row=$rows|Where-Object{$_.id -eq $Id -and $_.action -eq $Action}|Select-Object -First 1
 Assert-Test ($null -ne $row) ('Missing fixture '+$Id+'/'+$Action)
 $script:gpoId=[guid]([regex]::Match($row.script,"\`$GpoId = '([^']+)'" ).Groups[1].Value)
 $script:folder=Join-Path $script:share ('example.test\Policies\'+$script:gpoId.ToString('B').ToUpperInvariant())
 $null=New-Item -ItemType Directory -Path $script:folder -Force
 [IO.File]::WriteAllText((Join-Path $script:folder 'GPT.INI'),"[General]`r`nVersion=7`r`n")
 $code=$row.script.Replace('$BackupRoot = ''C:\ProgramData\GpoRemediator\Backups''',('$BackupRoot = '''+$backupRoot+''''))
 try{& ([scriptblock]::Create($code))|Out-Null;if($Failure){throw 'Expected fixture failure was not raised'}}catch{
  if(!$Failure -or $_.Exception.Message -eq 'Expected fixture failure was not raised'){throw}
  $expected=@{cancel='Cancelled; no changes made';backup='Fixture backup failure';drift='GPO or links changed during backup';write='Fixture partial write failure';dc='Run on the selected writable DC'}[$Failure]
  Assert-Test ($_.Exception.Message.StartsWith($expected)) ('Unexpected failure for '+$Failure+': '+$_.Exception.Message)
 }
 $writes=@($script:events|Where-Object{$_ -in @('write','link')}).Count
 if($Action -eq 'Preview'){
  Assert-Test ($script:events.Count -eq 0 -and !(Test-Path -LiteralPath $backupRoot)) 'Preview caused a confirmation, backup or write'
 }elseif(!$Failure){
  Assert-Test ($writes -gt 0 -and $script:events[0] -eq 'confirm' -and $script:events[1] -eq 'backup') 'Manual execution order was incorrect'
  $manifestPath=@(Get-ChildItem -LiteralPath $backupRoot -Filter manifest.json -Recurse)[0].FullName
  $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
  Assert-Test ($manifest.phase -eq 'GPO_VERIFIED' -and $manifest.backupId -and $manifest.postFingerprint) 'Read-back did not retain backup/publication evidence'
  $before=$script:events.Count
  & ([scriptblock]::Create($code))|Out-Null
  Assert-Test ($script:events.Count -eq $before) 'Repeated compliant Apply was not idempotent'
 }elseif($Failure -eq 'write'){
  Assert-Test ($writes -gt 0) 'Partial-write fixture never wrote'
  $manifest=Get-Content -LiteralPath (@(Get-ChildItem -LiteralPath $backupRoot -Filter manifest.json -Recurse)[0].FullName) -Raw|ConvertFrom-Json
  Assert-Test ($manifest.phase -eq 'REVIEW_REQUIRED' -and $manifest.backupId) 'Partial write was mislabeled safe or lost its backup'
 }else{Assert-Test ($writes -eq 0) ('Failure '+$Failure+' still wrote policy')}
}
foreach($id in @('9.1.6','18.4.4','2.3.1.2','17.2.1','1.1.4','19.5.1.1')){Run-Fixture $id 'Preview';Run-Fixture $id 'Apply'}
foreach($failure in @('cancel','backup','drift','write','dc')){Run-Fixture '9.1.6' 'Apply' $failure}
Run-Fixture '2.3.7.4' 'Escaping'
Write-Output ('PASS '+$rows.Count+' generated PowerShell 5.1 scripts parsed. Complete offline Preview/Apply: registry, registry set, security template, audit, domain account, HKCU, literal custom input; backup order, read-back, idempotence, cancellation, failed backup, drift, partial write and read-only DC rejection. Live AD: NOT RUN.')
