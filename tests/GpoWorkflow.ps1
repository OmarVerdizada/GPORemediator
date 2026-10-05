# Real GPO worker exercised against isolated files and fake AD/GroupPolicy cmdlets. No domain connection.
$ErrorActionPreference='Stop'
$script:fixture=Join-Path ([IO.Path]::GetTempPath()) ('gpor-'+[guid]::NewGuid().ToString('N'))
$script:fixture=[IO.Path]::GetFullPath($script:fixture)
try {
$script:gpoId=[guid]'31b2f340-016d-11d2-945f-00c04fb984f9'
$script:domainDn='DC=example,DC=com';$script:ouDn='OU=Test,DC=example,DC=com'
$script:sysvol=Join-Path $script:fixture 'sysvol'
$script:folder=Join-Path $script:sysvol ('example.com/Policies/'+$script:gpoId.ToString('B').ToUpperInvariant())
$null=New-Item -ItemType Directory -Path $script:folder -Force
[IO.File]::WriteAllText((Join-Path $script:folder 'GPT.INI'),"[General]`r`nVersion=0`r`n")
$infDir=Join-Path $script:folder 'Machine/Microsoft/Windows NT/SecEdit'
$null=New-Item -ItemType Directory -Path $infDir -Force
[IO.File]::WriteAllText((Join-Path $infDir 'GptTmpl.inf'),"[System Access]`r`nMinimumPasswordLength = 8`r`nPasswordHistorySize = 12`r`n[Privilege Rights]`r`nSeNetworkLogonRight = *S-1-5-11`r`n",[Text.Encoding]::Unicode)
$script:version=0;$script:extensions='';$script:changed=[DateTime]::UtcNow;$script:links=@{};$script:writes=0;$script:refreshCount=0;$script:backups=@{};$script:refreshFails=$false
function Check($c,$m){if(!$c){throw $m}}
function Get-Module {param($Name,[switch]$ListAvailable) if($ListAvailable -and $Name -in @('ActiveDirectory','GroupPolicy')){return [pscustomobject]@{Name=$Name}}; return Microsoft.PowerShell.Core\Get-Module @PSBoundParameters }
function Import-Module {param($Name,[switch]$Force) if($Name -is [System.Management.Automation.PSModuleInfo]){Microsoft.PowerShell.Core\Import-Module $Name -Force} }
function Get-ADDomain {param($Identity,$Server) return [pscustomobject]@{DNSRoot='example.com';DistinguishedName=$script:domainDn;PDCEmulator=($env:COMPUTERNAME+'.example.com')} }
function Get-ADDomainController {param($Identity,$Server,$Filter) if($Filter){return [pscustomobject]@{IsReadOnly=$false;Domain='example.com';HostName=($env:COMPUTERNAME+'.example.com')}};return [pscustomobject]@{IsReadOnly=$false;Domain='example.com';HostName=($env:COMPUTERNAME+'.example.com')} }
function Get-ADRootDSE {param($Server) return [pscustomobject]@{configurationNamingContext='CN=Configuration,DC=example,DC=com'} }
function RawLinks([string]$Dn){if(!$script:links.ContainsKey($Dn)){return ''};return ('[LDAP://CN='+$script:gpoId.ToString('B').ToUpperInvariant()+',CN=Policies,CN=System,'+$script:domainDn+';'+$(if($script:links[$Dn].Enabled){0}else{1})+']')}
function Get-ADOrganizationalUnit {param($Identity,$Filter,$Server,$Properties,$ResultSetSize) return [pscustomobject]@{DistinguishedName=$script:ouDn;Name='Test';gPLink=(RawLinks $script:ouDn)} }
function Get-ADObject {param($Identity,$Filter,$SearchBase,$Server,$Properties,$ResultSetSize)
  if($SearchBase){return @()}
  if($Identity -like 'CN=*'){return [pscustomobject]@{DistinguishedName=$Identity;versionNumber=$script:version;gPCMachineExtensionNames=$script:extensions;flags=0;whenChanged=$script:changed;gPCWQLFilter=''}}
  return [pscustomobject]@{gPLink=(RawLinks $Identity)}
}
function Set-ADObject {param($Identity,$Server,$Replace) $script:version=$Replace.versionNumber;$script:extensions=$Replace.gPCMachineExtensionNames;$script:changed=$script:changed.AddSeconds(1);$script:writes++ }
function Get-GPO {param($Guid,$Domain,$Server,[switch]$All) return [pscustomobject]@{Id=$script:gpoId;DisplayName='Password Test';GpoStatus='AllSettingsEnabled'} }
function Get-CimInstance {param($ClassName,$Filter) return [pscustomobject]@{Path=$script:sysvol} }
function Get-GPPermission {param($Guid,[switch]$All,$Domain,$Server) $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;return [pscustomobject]@{Trustee=[pscustomobject]@{Sid=[pscustomobject]@{Value=$sid};Name='Test Operator'};Permission='GpoEdit'} }
function Get-GPInheritance {param($Target,$Domain,$Server) return [pscustomobject]@{GpoInheritanceBlocked=$false;InheritedGpoLinks=@();GpoLinks=@(if($script:links.ContainsKey($Target)){$script:links[$Target]})} }
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize) return [pscustomobject]@{DNSHostName='test-pc.example.com';OperatingSystem='Windows Server 2019';Enabled=$true} }
function Backup-GPO {param($Guid,$Path,$Domain,$Server,$Comment)
  $id=[guid]::NewGuid();$files=@{};Get-ChildItem -LiteralPath $script:folder -Recurse -File|ForEach-Object{$files[$_.FullName]=[IO.File]::ReadAllBytes($_.FullName)}
  $script:backups[$id.ToString()]=@{files=$files;extensions=$script:extensions}
  return [pscustomobject]@{Id=$id}
}
function Restore-GPO {param($BackupId,$Path,$Domain,$Server)
  $b=$script:backups[$BackupId.ToString()]
  Get-ChildItem -LiteralPath $script:folder -File -Recurse|ForEach-Object{if(!$b.files.ContainsKey($_.FullName)){if(!$_.FullName.StartsWith($script:fixture+[IO.Path]::DirectorySeparatorChar)){throw 'Test path escape'};[IO.File]::Delete($_.FullName)}}
  foreach($key in $b.files.Keys){[IO.File]::WriteAllBytes($key,$b.files[$key])}
  $script:extensions=$b.extensions;$script:version=0;$script:changed=$script:changed.AddSeconds(1);$script:writes++
}
# Registry cmdlets persist policy data into the fixture GPO so full backups/fingerprints cover it.
function Get-GPRegistryValue {param($Guid,$Key,$ValueName,$Domain,$Server,$ErrorAction)
  $path=Join-Path $script:folder 'registry-fixture.json';$data=if(Test-Path $path){Get-Content $path -Raw|ConvertFrom-Json}else{[pscustomobject]@{}}
  $property=$data.PSObject.Properties[$Key+'|'+$ValueName]
  if(!$property){$errorRecord=New-Object Management.Automation.ErrorRecord ([Exception]::new('Not configured')),'UnableToRetrievePolicyRegistryItem',([Management.Automation.ErrorCategory]::ObjectNotFound),$ValueName;throw $errorRecord}
  return [pscustomobject]@{Value=$property.Value}
}
function Set-GPRegistryValue {param($Guid,$Key,$ValueName,$Type,$Value,$Domain,$Server)
  if($ValueName -eq 'FailWrite'){throw 'Injected second registry write failure'}
  $path=Join-Path $script:folder 'registry-fixture.json';$data=if(Test-Path $path){Get-Content $path -Raw|ConvertFrom-Json}else{[pscustomobject]@{}}
  $data|Add-Member NoteProperty ($Key+'|'+$ValueName) $Value -Force
  [IO.File]::WriteAllText($path,($data|ConvertTo-Json -Depth 20))
  $script:version++;$script:changed=$script:changed.AddSeconds(1);$script:writes++
  [IO.File]::WriteAllText((Join-Path $script:folder 'GPT.INI'),("[General]`r`nVersion="+$script:version+"`r`n"))
}
function New-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order=1) Check ($script:backups.Count -gt 0) 'Link before backup';$script:links[$Target]=[pscustomobject]@{GpoId=$Guid;Order=$Order;Enabled=($LinkEnabled -eq 'Yes');Enforced=$false};$script:writes++ }
function Set-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order,$Enforced) $l=$script:links[$Target];$l.Enabled=$LinkEnabled -eq 'Yes';if($Order){$l.Order=$Order};if($Enforced){$l.Enforced=$Enforced -eq 'Yes'};$script:writes++ }
function Remove-GPLink {param($Guid,$Target,$Domain,$Server,$Confirm) $script:links.Remove($Target);$script:writes++ }
function Invoke-GPUpdate {param($Computer,$Target,[switch]$Force,$RandomDelayInMinutes,$ErrorAction) if($script:refreshFails){throw 'Expected RPC failure'};Check ($Force -and $RandomDelayInMinutes -eq 0) 'Force refresh not requested';$script:refreshCount++ }
function Get-ADDefaultDomainPasswordPolicy {param($Identity,$Server) return [pscustomobject]@{MinPasswordLength=8;ComplexityEnabled=$false;PasswordHistoryCount=12;MaxPasswordAge=[TimeSpan]::FromDays(90);MinPasswordAge=[TimeSpan]::Zero;ReversibleEncryptionEnabled=$false} }
function Resolve-DnsName {param($Name,$Type,$ErrorAction) return [pscustomobject]@{IPAddress='127.0.0.1'} }
function Get-ADReplicationPartnerMetadata {param($Target,$Scope,$ErrorAction) return @() }
$worker=Join-Path $PSScriptRoot '../backend/PowerShell/GpoWorkflow.Worker.ps1'
$module=Get-Content (Join-Path $PSScriptRoot '../backend/PowerShell/SecurityTemplate.psm1') -Raw
$cfg=[pscustomobject]@{domain='example.com';domainController=($env:COMPUTERNAME+'.example.com');backupPath=(Join-Path $script:fixture 'backups');allowedHosts=@('*')}
function Invoke-Worker($Operation,$Data){if(!$Data.ContainsKey('consent')){$Data.consent=$null};$result=& ([scriptblock]::Create([IO.File]::ReadAllText($worker))) -Operation $Operation -Configuration $cfg -Data $Data -SecurityModule $module;return ($result|ConvertTo-Json -Depth 40|ConvertFrom-Json)}
$inventory=Invoke-Worker 'gpoInventory' @{}
Check ($inventory.gpos.Count -eq 1 -and $script:writes -eq 0) 'Inventory wrote or failed'
$readiness=Invoke-Worker 'gpoReadiness' @{}
Check ($readiness.checks.Count -ge 5 -and $readiness.ready) 'Readiness must return typed checks without throwing'
$selection=[pscustomobject]@{gpoId=$script:gpoId.ToString();scopeDn=$script:domainDn;setting='1.1.4';value=14;accountScope='Domain';refresh='Pdc';firstLink=$true;customValue=$null}
$mapping=[pscustomobject]@{id='1.1.4';controlId='1.1.4';title='Minimum password length';automation='Automated';handler='SecurityTemplate';scope='Domain';domainPolicySensitive=$true;requiresInput=$false;allowValueOverride=$true;minimum=0;maximum=20;comparator='>=';source='test mapping';warnings=@();items=@([pscustomobject]@{section='System Access';key='MinimumPasswordLength';name=$null;type='Integer';value=@('14');guid=$null;state=$null;mask=$null})}
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.previousValue -eq '8' -and $script:writes -eq 0) 'Read-only preview failed'
$plan=[pscustomobject]@{id=[guid]::NewGuid().ToString('N');domain='example.com';domainController=$cfg.domainController;selection=$selection;preview=$preview}
$result=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($result.state -eq 'PUBLISHED' -and $result.gpoPublished -and $result.linkVerified) ('Apply/link failed: '+($result|ConvertTo-Json -Compress -Depth 10))
Check ($script:version -eq 1 -and $script:refreshCount -eq 0 -and $result.effectiveStatus -eq 'REPLICATION_PENDING' -and $null -ne $result.verification -and !$result.verification.replicationConverged) ('Version/explicit-refresh/effective status wrong: version='+$script:version+' refresh='+$script:refreshCount+' status='+$result.effectiveStatus)
$updated=[IO.File]::ReadAllText((Join-Path $infDir 'GptTmpl.inf'))
Check ($updated -match 'PasswordHistorySize = 12' -and $updated -match 'SeNetworkLogonRight = \*S-1-5-11') 'Unrelated security settings changed'
$verified=Invoke-Worker 'gpoVerify' @{plan=$plan;mapping=$mapping;previous=$result}
Check ($verified.gpoPublished -and $verified.linkVerified) 'Read-only verification failed'
$refreshed=Invoke-Worker 'gpoRefresh' @{plan=$plan;mapping=$mapping;previous=$verified}
Check ($refreshed.state -eq 'REFRESH_SCHEDULED' -and $script:refreshCount -eq 1 -and $refreshed.refreshResults[0].state -eq 'SCHEDULED') 'Explicit gpupdate refresh failed'
$beforeWrites=$script:writes
try{Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}|Out-Null;throw 'Replay accepted'}catch{if($_.Exception.Message -notlike 'GPO_ALREADY_STARTED*'){throw}}
Check ($script:writes -eq $beforeWrites) 'Replay wrote again'
$script:changed=$script:changed.AddSeconds(1)
try{Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$result}|Out-Null;throw 'Stale rollback accepted'}catch{if($_.Exception.Message -notlike 'ROLLBACK_CONFLICT*'){throw}}
$script:changed=$script:changed.AddSeconds(-1)
$rolled=Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$result}
Check ($rolled.state -eq 'ROLLED_BACK' -and !$script:links.ContainsKey($script:domainDn)) 'Rollback did not restore snapshot/remove link'
$rollbackVerified=Invoke-Worker 'gpoVerify' @{plan=$plan;mapping=$mapping;previous=$rolled}
Check ($rollbackVerified.state -eq 'ROLLED_BACK') 'Verify after rollback must preserve ROLLED_BACK when the pre-change snapshot still matches'
Check ([IO.File]::ReadAllText((Join-Path $infDir 'GptTmpl.inf')) -match 'MinimumPasswordLength = 8') 'Old password value not restored'
# Existing disabled link must return to its original state after rollback.
$script:links[$script:domainDn]=[pscustomobject]@{GpoId=$script:gpoId;Order=1;Enabled=$false;Enforced=$false}
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping};$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview;$script:refreshFails=$true
$partial=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ((Get-Content (Join-Path $partial.backupDirectory 'manifest.json') -Raw|ConvertFrom-Json).phase -eq $partial.state) 'Manifest publication state differs from result'
Check ($partial.state -eq 'PUBLISHED' -and $partial.gpoPublished) 'Apply should publish without running gpupdate'
$refreshPartial=Invoke-Worker 'gpoRefresh' @{plan=$plan;mapping=$mapping;previous=$partial}
Check ($refreshPartial.state -eq 'REFRESH_PARTIAL' -and $refreshPartial.gpoPublished -and $refreshPartial.refreshResults[0].state -eq 'FAILED') 'Explicit refresh failure obscured successful GPO write'
$rolled=Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$partial}
Check ($rolled.state -eq 'ROLLED_BACK' -and !$script:links[$script:domainDn].Enabled) 'Existing disabled link was not restored'
# A restricted host boundary must be identical in Preview and Apply.
$cfg.allowedHosts=@('test-pc.example.com');$selection.refresh='Scope'
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.refreshComputers.Count -eq 1) 'Allowed scope host omitted'
$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$allowed=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($allowed.state -eq 'PUBLISHED') 'Restricted host plan rejected its own refreshed preview'
Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$allowed}|Out-Null
$cfg.allowedHosts=@();$selection.refresh='Pdc'
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.refreshComputers.Count -eq 0 -and $preview.impact.affectedObjects.sampleHosts.Count -eq 0) 'Empty host allowlist permits endpoint probes'
$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$restricted=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($restricted.state -eq 'PUBLISHED') 'Empty host boundary rejected a valid policy write'

# Interrupted publication must not become success simply because one value matches.
$manifestPath=Join-Path $restricted.backupDirectory 'manifest.json'
$manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
$manifest.phase='WRITING';$manifest|ConvertTo-Json -Depth 50|Set-Content $manifestPath -Encoding UTF8
$interrupted=Invoke-Worker 'gpoVerify' @{plan=$plan;mapping=$mapping;previous=$restricted}
Check ($interrupted.state -eq 'REVIEW_REQUIRED') 'Partial execution promoted to published'
try{Invoke-Worker 'gpoRefresh' @{plan=$plan;mapping=$mapping;previous=$interrupted}|Out-Null;throw 'Interrupted refresh accepted'}catch{if($_.Exception.Message -notlike 'REFRESH_REVIEW_REQUIRED*'){throw}}

# A crash after recording rollback intent retains rollback semantics on Verify.
$manifest.phase='ROLLING_BACK';$manifest|ConvertTo-Json -Depth 50|Set-Content $manifestPath -Encoding UTF8
$interruptedRollback=Invoke-Worker 'gpoVerify' @{plan=$plan;mapping=$mapping;previous=$restricted}
Check ($interruptedRollback.state -eq 'ROLLBACK_DRIFT_DETECTED') 'Interrupted rollback promoted to publication'
$manifest.phase='PUBLISHED';$manifest|ConvertTo-Json -Depth 50|Set-Content $manifestPath -Encoding UTF8
Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$restricted}|Out-Null

# Missing user-right assignments differ from an explicitly configured empty list.
$selection.setting='2.2.test';$selection.value=0;$selection.refresh='None'
$mapping.id='2.2.test';$mapping.controlId='2.2.test';$mapping.domainPolicySensitive=$false;$mapping.allowValueOverride=$false
$mapping.items=@([pscustomobject]@{section='Privilege Rights';key='SeDenyInteractiveLogonRight';name=$null;type='Principals';value=@();guid=$null;state=$null;mask=$null})
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check (!$preview.noChange -and $null -eq $preview.previousValue) 'Missing empty assignment treated as configured'
$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$emptyRights=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($emptyRights.state -eq 'PUBLISHED') 'Empty user-right assignment not published'
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.noChange -and $preview.previousValue -eq '') 'Explicit empty rights are not idempotent'
Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$emptyRights}|Out-Null

# Advanced audit uses numeric masks, preserves other subcategories and rolls back.
$auditDir=Join-Path $script:folder 'Machine/Microsoft/Windows NT/Audit'
$null=New-Item -ItemType Directory -Path $auditDir -Force
$auditPath=Join-Path $auditDir 'audit.csv'
[IO.File]::WriteAllText($auditPath,"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n,System,Test,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,0`r`n,System,Other,{0CCE9216-69AE-11D9-BED3-505054503030},Failure,,2`r`n")
$selection.setting='17.test';$mapping.id='17.test';$mapping.controlId='17.test';$mapping.handler='AdvancedAudit'
$mapping.items=@([pscustomobject]@{section=$null;key=$null;name='Test';type='Audit';value=@();guid='{0CCE9215-69AE-11D9-BED3-505054503030}';state='Success';mask=1})
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check (!$preview.noChange) 'Incorrect numeric audit mask treated as compliant display text'
$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$audit=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($audit.state -eq 'PUBLISHED') 'Advanced audit write/CSE/version failed'
Check ((Get-Content $auditPath -Raw) -match 'Other.*Failure,,2') 'Unrelated audit subcategory changed'
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.noChange) 'Advanced audit mapping is not idempotent'
Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$audit}|Out-Null

# Registry and RegistrySet preserve unrelated values and support empty strings/multiple writes.
$registryKey='HKLM\Software\Policies\Fixture';$selection.setting='18.test';$mapping.id='18.test';$mapping.controlId='18.test';$mapping.handler='Registry';$mapping.domainPolicySensitive=$false
$mapping.items=@([pscustomobject]@{section=$null;key=$registryKey;name='EmptyValue';type='String';value=@('');guid=$null;state=$null;mask=$null})
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check (!$preview.noChange) 'Missing registry string treated as a configured empty string'
$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$registry=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($registry.state -eq 'PUBLISHED') 'Registry empty string was not published'
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.noChange) 'Registry empty string is not idempotent'
Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$registry}|Out-Null

$mapping.handler='RegistrySet'
$mapping.items=@(
 [pscustomobject]@{section=$null;key=$registryKey;name='First';type='DWord';value=@('1');guid=$null;state=$null;mask=$null},
 [pscustomobject]@{section=$null;key=$registryKey;name='Second';type='MultiString';value=@('alpha','beta');guid=$null;state=$null;mask=$null})
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping};$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$registrySet=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($registrySet.state -eq 'PUBLISHED') 'RegistrySet did not publish both values'
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.noChange) 'RegistrySet is not idempotent'
Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$registrySet}|Out-Null

# Failure after the first registry write preserves an ambiguous manifest; Apply is never replayed.
$mapping.items[1].name='FailWrite'
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping};$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$partialWrite=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($partialWrite.state -eq 'REVIEW_REQUIRED' -and $partialWrite.backupId -and !$partialWrite.postFingerprint) 'Partial RegistrySet write lost its backup or uncertainty'
$checkedPartial=Invoke-Worker 'gpoVerify' @{plan=$plan;mapping=$mapping;previous=$partialWrite}
Check ($checkedPartial.state -eq 'REVIEW_REQUIRED') 'Partial RegistrySet write was promoted to success'
try{Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}|Out-Null;throw 'Partial write replay accepted'}catch{if($_.Exception.Message -notlike 'GPO_ALREADY_STARTED*'){throw}}
try{Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$partialWrite}|Out-Null;throw 'Unknown-version rollback accepted'}catch{if($_.Exception.Message -notlike 'ROLLBACK_VERSION_UNKNOWN*'){throw}}
# Manual fixture recovery emulates administrator review before the remaining independent case.
Restore-GPO -BackupId ([guid]$partialWrite.backupId) -Path $partialWrite.backupDirectory -Domain $cfg.domain -Server $cfg.domainController

# Simulate immediate read-back failure after a write: manifest must record it too.
$selection.setting='1.1.4';$selection.value=14;$mapping.id='1.1.4';$mapping.controlId='1.1.4';$mapping.handler='SecurityTemplate';$mapping.domainPolicySensitive=$true;$mapping.allowValueOverride=$true
$mapping.items=@([pscustomobject]@{section='System Access';key='MinimumPasswordLength';name=$null;type='Integer';value=@('14');guid=$null;state=$null;mask=$null})
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping};$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview
$originalSet=(Get-Item Function:Set-ADObject).ScriptBlock
function Set-ADObject {param($Identity,$Server,$Replace) $script:version=$Replace.versionNumber+1;$script:extensions=$Replace.gPCMachineExtensionNames;$script:changed=$script:changed.AddSeconds(1);$script:writes++}
$mismatch=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($mismatch.state -eq 'VERIFY_MISMATCH') 'Immediate version mismatch hidden'
Check ((Get-Content (Join-Path $mismatch.backupDirectory 'manifest.json') -Raw|ConvertFrom-Json).phase -eq 'VERIFY_MISMATCH') 'Manifest falsely records publication after read-back mismatch'
Set-Item Function:Set-ADObject $originalSet
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview;$beforeWrites=$script:writes
$noChangeMismatch=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($noChangeMismatch.state -eq 'VERIFY_MISMATCH' -and !$noChangeMismatch.gpoPublished -and $script:writes -eq $beforeWrites) 'No-change path hid an AD/SYSVOL version mismatch'
Write-Host 'PASS: isolated GPO transactions across SecurityTemplate, Registry, RegistrySet and AdvancedAudit; backup/rollback, host boundaries, idempotency, partial writes, replay, interrupted recovery and manifest read-back mismatch.'
} finally {
    if (!$script:fixture.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)) { throw 'Test cleanup path escape' }
    if (Test-Path -LiteralPath $script:fixture) { Remove-Item -LiteralPath $script:fixture -Recurse -Force }
}
