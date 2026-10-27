# Real worker dispatch + writer + manifests against private filesystem fixtures.
# AD, GPMC, DNS and remote endpoints are mocked. No live domain is contacted.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$temp=Join-Path ([IO.Path]::GetTempPath()) ('gpr-chain-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
Import-Module (Join-Path $repo 'backend/PowerShell/SecurityTemplate.psm1') -Force
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
$dispatch=[scriptblock]::Create(($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst]}|Select-Object -Last 1).Extent.Text)
$cfg=@{domain='example.test';domainController='dc.example.test';backupPath=(Join-Path $temp 'Backups');allowedHosts=@();endpointTargeting='SelectedOu';emitProgress=$false}
$domainDn='DC=example,DC=test';$target='OU=Pilot,'+$domainDn
$domain=@{DNSRoot='example.test';DistinguishedName=$domainDn;PDCEmulator='dc.example.test'};$dc=@{HostName='dc.example.test'}
$protectedBuiltInGpoIds=@();$gpoId='11111111-1111-1111-1111-111111111111'
$script:folder=Join-Path $temp 'Policy';$script:rawLinks='';$script:version=0;$script:extensions='';$script:userExtensions='';$script:registry=@{};$script:backupDenied=$false;$script:refreshes=0
function Check($ok,$name){if(!$ok){throw $name};Write-Output ('PASS '+$name)}
function Sysvol-Policies {return $script:folder}
function Gpo-Folder {param($Id) return $script:folder}
function Remote-GpoFolder {param($Server,$Id) return $script:folder}
function Resolve-DnsName {param($Name,$Type,$ErrorAction) [pscustomobject]@{IPAddress='127.0.0.1'}}
function Get-ADDomain {param($Identity,$Server,$ErrorAction) return $domain}
function Get-ADDomainController {param($Filter,$Server) [pscustomobject]@{HostName=$cfg.domainController}}
function Get-ADReplicationPartnerMetadata {param($Target,$Scope,$ErrorAction) @()}
function Get-ADOrganizationalUnit {param($Identity,$Server) [pscustomobject]@{DistinguishedName=$Identity;Name='Pilot'}}
function Get-ADObject {param($Identity,$Server,$Properties,$Replace,$ErrorAction)
 if($Identity -like 'CN=*'){return [pscustomobject]@{DistinguishedName=$Identity;allowedAttributesEffective=@('versionNumber','gPCMachineExtensionNames','gPCUserExtensionNames');versionNumber=$script:version;gPCMachineExtensionNames=$script:extensions;gPCUserExtensionNames=$script:userExtensions;gPCWQLFilter='';flags=0;whenChanged=[datetime]'2026-01-01'}}
 return [pscustomobject]@{gPLink=$script:rawLinks;allowedAttributesEffective=@('gPLink')}
}
function Set-ADObject {param($Identity,$Server,$Replace) $script:version=[int]$Replace.versionNumber;$script:extensions=[string]$Replace.gPCMachineExtensionNames}
function Get-GPO {param($Guid,$Domain,$Server) [pscustomobject]@{Id=[guid]$gpoId;DisplayName='Dedicated pilot';GpoStatus='AllSettingsEnabled'}}
function Get-GPPermission {param($Guid,[switch]$All,$Domain,$Server) [pscustomobject]@{Permission='GpoApply';Trustee=[pscustomobject]@{Name='Authenticated Users';Sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-11')}}}
function Get-ADDefaultDomainPasswordPolicy {param($Identity,$Server) @{PasswordHistoryCount=24}}
function All-LinkScopes {@([pscustomobject]@{dn=$target;rawLinks=$script:rawLinks})}
function Get-GPInheritance {param($Target,$Domain,$Server)
 $links=@();if($script:rawLinks){$links=@([pscustomobject]@{GpoId=[guid]$gpoId;Order=1;Enforced=$false;Enabled=$true;DisplayName='Dedicated pilot'})}
 [pscustomobject]@{GpoLinks=$links;InheritedGpoLinks=@();GpoInheritanceBlocked=$false}
}
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) [pscustomobject]@{DNSHostName='ws.example.test';OperatingSystem='Windows 11';Enabled=$true}}
function Get-ADUser {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) [pscustomobject]@{SamAccountName='pilot';Enabled=$true}}
function New-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order) $script:rawLinks='[LDAP://CN={'+$gpoId+'},CN=Policies,CN=System,'+$domainDn+';0]'}
function Set-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order,$Enforced) New-GPLink}
function Remove-GPLink {param($Guid,$Target,$Domain,$Server,$Confirm) $script:rawLinks=''}
function Set-GPRegistryValue {param($Guid,$Key,$ValueName,$Type,$Value,$Domain,$Server)
 $script:registry[$Key+'|'+$ValueName]=@{Value=$Value;Type=$Type}
 [IO.File]::WriteAllText((Join-Path $script:folder 'registry-fixture.json'),($script:registry|ConvertTo-Json -Depth 10))
}
function Get-GPRegistryValue {param($Guid,$Key,$ValueName,$Domain,$Server,$ErrorAction)
 $keyName=$Key+'|'+$ValueName
 if(!$script:registry.ContainsKey($keyName)){Write-Error 'Fixture absent policy' -ErrorId UnableToRetrievePolicyRegistryItem -ErrorAction Stop}
 [pscustomobject]$script:registry[$keyName]
}
function Backup-GPO {param($Guid,$Path,$Domain,$Server,$Comment)
 if($script:backupDenied){throw [UnauthorizedAccessException]::new('Access is denied')}
 $snapshot=Join-Path $Path 'snapshot';$null=New-Item -ItemType Directory -Path $snapshot
 Copy-Item -Path (Join-Path $script:folder '*') -Destination $snapshot -Recurse
 $script:snapshot=@{version=$script:version;extensions=$script:extensions;userExtensions=$script:userExtensions;registry=$script:registry.Clone()}
 [pscustomobject]@{Id=[guid]::NewGuid()}
}
function Import-GPO {param($BackupId,$TargetGuid,$Path,$Domain,$Server)
 Get-ChildItem -LiteralPath $script:folder -Force|Remove-Item -Recurse -Force
 Copy-Item -Path (Join-Path $Path 'snapshot/*') -Destination $script:folder -Recurse
 $script:version=$script:snapshot.version;$script:extensions=$script:snapshot.extensions;$script:userExtensions=$script:snapshot.userExtensions;$script:registry=$script:snapshot.registry.Clone()
}
function Invoke-GPUpdate {param($Computer,$Force,$RandomDelayInMinutes,$ErrorAction,$Target) $script:refreshes++}
$catalog=(Get-Content (Join-Path $repo 'backend/data/gpo-production-mappings.json') -Raw|ConvertFrom-Json).mappings
try{
 $cases=@(@('1.1.1','LocalComputers'),@('1.1.1','Domain'),@('2.3.1.1','LocalComputers'),@('18.4.4','LocalComputers'),@('17.1.1','LocalComputers'),@('19.5.1.1','Users'))
 foreach($manual in @($catalog|Where-Object automation -ne 'Automated')){$cases+=,@([string]$manual.id,'LocalComputers')}
 foreach($case in $cases){
  $map=($catalog|Where-Object id -eq $case[0])|ConvertTo-Json -Depth 15|ConvertFrom-Json
  Check ($null -ne $map) ('mapping exists '+$case[0])
  if($map.automation -ne 'Automated'){$map.automation='Automated';if($map.handler -eq 'Manual'){$map.handler='SecurityTemplate'}}
  if($case[1] -eq 'LocalComputers' -and $map.domainPolicySensitive){$map.scope='Computer';$map.domainPolicySensitive=$false}
  foreach($item in $map.items){foreach($field in @('section','key','name','guid','state','mask','value')){if(!$item.PSObject.Properties[$field]){$item|Add-Member -NotePropertyName $field -NotePropertyValue $null}}}
  if(Test-Path $script:folder){Remove-Item -LiteralPath $script:folder -Recurse -Force}
  $null=New-Item -ItemType Directory -Path $script:folder
  [IO.File]::WriteAllText((Join-Path $script:folder 'GPT.INI'),"[General]`r`nVersion=0`r`n")
  $script:version=0;$script:extensions='';$script:userExtensions='';$script:rawLinks='';$script:registry=@{}
  $s=@{gpoId=$gpoId;scopeDn=$(if($case[1] -eq 'Domain'){$domainDn}else{$target});setting=$map.id;value=$map.suggested;customValue='';refresh='None';firstLink=($case[1] -eq 'Domain');accountScope=$case[1];endpointScopeDn='';verificationUser=''}
  $Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$script:workerStage='VALIDATING';$preview=& $dispatch
  Check ($preview.preflight.ready) ('readiness '+$map.id+' '+$case[1])
  $plan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$s;preview=$preview}
  $refreshBefore=$script:refreshes
  $Operation='gpoApply';$Data=@{plan=$plan;mapping=$map;consent=@{confirmation='APPLY'}};$result=& $dispatch
  Check ($result.state -eq 'PUBLISHED') ('backup/write/link/publication '+$map.id+' '+$case[1]+': '+$result.message)
  Check ($script:refreshes -eq $refreshBefore) 'Apply does not schedule unrequested endpoint refresh'
  if($case[1] -ne 'Users'){
   $Operation='gpoRefresh';$Data.refresh=if($case[1] -eq 'Domain'){'Pdc'}else{'Scope'};$result=& $dispatch
   Check ($result.state -eq 'REFRESH_SCHEDULED' -and $script:refreshes -eq $refreshBefore+1) ('explicit refresh schedules exactly one target '+$map.id)
  }
  $Operation='gpoRollback';$result=& $dispatch
  Check ($result.state -eq 'ROLLED_BACK') ('snapshot rollback '+$map.id)
  $Operation='gpoVerify';$result=& $dispatch
  Check ($result.state -eq 'ROLLED_BACK') ('rollback read-back '+$map.id)
 }
 # A denied preflight must not poison an otherwise valid publication manifest.
 $plan.id=[guid]::NewGuid().ToString('N');$Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$plan.preview=& $dispatch
 $Operation='gpoApply';$Data=@{plan=$plan;mapping=$map;consent=@{confirmation='APPLY'}};$result=& $dispatch
 Check ($result.state -eq 'PUBLISHED') 'recovery fixture publication'
 $manifestPath=Join-Path (Run-Directory $plan) 'manifest.json'
 $accessFn=(Get-Item Function:\Assert-SelectionAccess).ScriptBlock
 $importFn=(Get-Item Function:\Import-GPO).ScriptBlock
 try {
  function Assert-SelectionAccess {param($Selection,$Mapping) throw [UnauthorizedAccessException]::new('Access denied fixture')}
  $beforeFingerprint=Fingerprint $s.gpoId $s.scopeDn
  $Operation='gpoRollback';$result=& $dispatch
  $saved=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
  Check ($result.state -eq 'FAILED_SAFE' -and $saved.phase -eq 'PUBLISHED' -and $saved.rollbackFailure.stage -eq 'RESTORE_ACCESS_CHECK') 'pre-restore access denial preserves the recoverable manifest phase'
  Check ((Fingerprint $s.gpoId $s.scopeDn) -ceq $beforeFingerprint) 'denied restore does not mutate GPO or link'
  Set-Item Function:\Assert-SelectionAccess $accessFn
  $script:restoreCalls=0
  function Import-GPO {param($BackupId,$TargetGuid,$Path,$Domain,$Server) $script:restoreCalls++;throw [InvalidOperationException]::new('Private fixture import failure')}
  $Operation='gpoRollback';$result=& $dispatch
  $saved=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
  Check ($result.state -eq 'ROLLBACK_REVIEW_REQUIRED' -and $saved.phase -eq 'ROLLBACK_REVIEW_REQUIRED' -and $saved.rollbackFailure.stage -eq 'RESTORING_GPO') 'failure after import begins remains blocked and retains its stage'
  Check ($result.message -notmatch 'Private fixture') 'native rollback errors are sanitized'
  $Operation='gpoRollbackInspect';$assessment=& $dispatch
  Check (!$assessment.canRestore -and $assessment.manifestPhase -eq 'ROLLBACK_REVIEW_REQUIRED' -and $assessment.reason -eq 'MANUAL_REVIEW_REQUIRED' -and $assessment.failure.stage -eq 'RESTORING_GPO') 'read-only recovery assessment exposes the retained block reason'
  $Operation='gpoRollback';$blocked=$false;try{$null=& $dispatch}catch{$blocked=$_.Exception.Message -match 'ROLLBACK_CONFLICT'}
  Check ($blocked -and $script:restoreCalls -eq 1) 'review-required retry cannot invoke native restore'
 } finally {Set-Item Function:\Assert-SelectionAccess $accessFn;Set-Item Function:\Import-GPO $importFn}
 Import-GPO -Path (Run-Directory $plan)
 # Check that a real exception before policy mutation is retained with context.
 $plan.id=[guid]::NewGuid().ToString('N');$Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$plan.preview=& $dispatch
 $script:backupDenied=$true;$Operation='gpoApply';$Data=@{plan=$plan;mapping=$map;consent=@{confirmation='APPLY'}};$result=& $dispatch
 Check ($result.state -eq 'FAILED_SAFE' -and $result.message -match 'Stage BACKUP failed') 'backup denial returns failed-safe stage and recovery guidance'
 Write-Output 'PASS real worker chain: preview, readiness, backup, write, link, publication, rollback and re-verification with mocked directory APIs only'
}finally{
 $resolved=[IO.Path]::GetFullPath($temp)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-chain-*'){throw 'Unsafe fixture cleanup path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
