# Real GPO worker exercised against isolated files and fake AD/GroupPolicy cmdlets. No domain connection.
$ErrorActionPreference='Stop'
$script:fixture=Join-Path $PSScriptRoot ('../work/gpo-worker-'+[guid]::NewGuid().ToString('N'))
$script:fixture=[IO.Path]::GetFullPath($script:fixture)
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
function Get-GPInheritance {param($Target,$Domain,$Server) return [pscustomobject]@{GpoLinks=@(if($script:links.ContainsKey($Target)){$script:links[$Target]})} }
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
function New-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order=1) Check ($script:backups.Count -gt 0) 'Link before backup';$script:links[$Target]=[pscustomobject]@{GpoId=$Guid;Order=$Order;Enabled=($LinkEnabled -eq 'Yes');Enforced=$false};$script:writes++ }
function Set-GPLink {param($Guid,$Target,$Domain,$Server,$LinkEnabled,$Order,$Enforced) $l=$script:links[$Target];$l.Enabled=$LinkEnabled -eq 'Yes';if($Order){$l.Order=$Order};if($Enforced){$l.Enforced=$Enforced -eq 'Yes'};$script:writes++ }
function Remove-GPLink {param($Guid,$Target,$Domain,$Server,$Confirm) $script:links.Remove($Target);$script:writes++ }
function Invoke-GPUpdate {param($Computer,$Target,[switch]$Force,$RandomDelayInMinutes,$ErrorAction) if($script:refreshFails){throw 'Expected RPC failure'};Check ($Force -and $RandomDelayInMinutes -eq 0) 'Force refresh not requested';$script:refreshCount++ }
function Get-ADDefaultDomainPasswordPolicy {param($Identity,$Server) return [pscustomobject]@{MinPasswordLength=8;ComplexityEnabled=$false;PasswordHistoryCount=12;MaxPasswordAge=[TimeSpan]::FromDays(90);MinPasswordAge=[TimeSpan]::Zero;ReversibleEncryptionEnabled=$false} }
function Resolve-DnsName {param($Name,$Type,$ErrorAction) return [pscustomobject]@{IPAddress='127.0.0.1'} }
function Get-ADReplicationPartnerMetadata {param($Target,$Scope,$ErrorAction) return @() }
$worker=Join-Path $PSScriptRoot '../backend/PowerShell/GpoWorkflow.Worker.ps1'
$module=Get-Content (Join-Path $PSScriptRoot '../backend/PowerShell/SecurityTemplate.psm1') -Raw
$cfg=[pscustomobject]@{domain='example.com';domainController=($env:COMPUTERNAME+'.example.com');backupPath=(Join-Path $script:fixture 'backups')}
function Invoke-Worker($Operation,$Data){$result=& $worker -Operation $Operation -Configuration $cfg -Data $Data -SecurityModule $module;return ($result|ConvertTo-Json -Depth 40|ConvertFrom-Json)}
$inventory=Invoke-Worker 'gpoInventory' @{}
Check ($inventory.gpos.Count -eq 1 -and $script:writes -eq 0) 'Inventory wrote or failed'
$selection=[pscustomobject]@{gpoId=$script:gpoId.ToString();scopeDn=$script:domainDn;setting='1.1.4';value=14;accountScope='Domain';refresh='Pdc';firstLink=$true;customValue=$null}
$mapping=[pscustomobject]@{id='1.1.4';controlId='1.1.4';title='Minimum password length';automation='Automated';handler='SecurityTemplate';scope='Domain';domainPolicySensitive=$true;requiresInput=$false;allowValueOverride=$true;minimum=0;maximum=20;source='test mapping';warnings=@();items=@([pscustomobject]@{section='System Access';key='MinimumPasswordLength';name=$null;type='Integer';value=@('14');guid=$null;state=$null;mask=$null})}
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping}
Check ($preview.previousValue -eq '8' -and $script:writes -eq 0) 'Read-only preview failed'
$plan=[pscustomobject]@{id=[guid]::NewGuid().ToString('N');domain='example.com';domainController=$cfg.domainController;selection=$selection;preview=$preview}
$result=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($result.state -eq 'PUBLISHED' -and $result.gpoPublished -and $result.linkVerified) ('Apply/link failed: '+($result|ConvertTo-Json -Compress -Depth 10))
Check ($script:version -eq 1 -and $script:refreshCount -eq 1 -and $result.effectiveStatus -eq 'DOMAIN_VALUE_PENDING_OR_OVERRIDDEN') 'Version/refresh/effective status wrong'
$updated=[IO.File]::ReadAllText((Join-Path $infDir 'GptTmpl.inf'))
Check ($updated -match 'PasswordHistorySize = 12' -and $updated -match 'SeNetworkLogonRight = \*S-1-5-11') 'Unrelated security settings changed'
$verified=Invoke-Worker 'gpoVerify' @{plan=$plan;mapping=$mapping;previous=$result}
Check ($verified.gpoPublished -and $verified.linkVerified) 'Read-only verification failed'
$beforeWrites=$script:writes
try{Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}|Out-Null;throw 'Replay accepted'}catch{if($_.Exception.Message -notlike 'GPO_ALREADY_STARTED*'){throw}}
Check ($script:writes -eq $beforeWrites) 'Replay wrote again'
$script:changed=$script:changed.AddSeconds(1)
try{Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$result}|Out-Null;throw 'Stale rollback accepted'}catch{if($_.Exception.Message -notlike 'ROLLBACK_CONFLICT*'){throw}}
$script:changed=$script:changed.AddSeconds(-1)
$rolled=Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$result}
Check ($rolled.state -eq 'ROLLED_BACK' -and !$script:links.ContainsKey($script:domainDn)) 'Rollback did not restore snapshot/remove link'
Check ([IO.File]::ReadAllText((Join-Path $infDir 'GptTmpl.inf')) -match 'MinimumPasswordLength = 8') 'Old password value not restored'
# Existing disabled link must return to its original state after rollback.
$script:links[$script:domainDn]=[pscustomobject]@{GpoId=$script:gpoId;Order=1;Enabled=$false;Enforced=$false}
$preview=Invoke-Worker 'gpoPreview' @{selection=$selection;mapping=$mapping};$plan.id=[guid]::NewGuid().ToString('N');$plan.preview=$preview;$script:refreshFails=$true
$partial=Invoke-Worker 'gpoApply' @{plan=$plan;mapping=$mapping;previous=$null}
Check ($partial.state -eq 'PUBLISHED_REFRESH_FAILED' -and $partial.gpoPublished -and $partial.refreshResults[0].state -eq 'FAILED') 'Refresh failure obscured successful GPO write'
$rolled=Invoke-Worker 'gpoRollback' @{plan=$plan;mapping=$mapping;previous=$partial}
Check ($rolled.state -eq 'ROLLED_BACK' -and !$script:links[$script:domainDn].Enabled) 'Existing disabled link was not restored'
Write-Host 'PASS: real GPO worker with AD doubles - discovery, preview, INF/CSE/version writes, backup, link creation, force refresh, independent verification, replay, stale rollback, existing-link restore and refresh failure.'
