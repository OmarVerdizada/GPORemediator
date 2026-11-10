# Real worker dispatch + writer + manifests against private filesystem fixtures.
# AD, GPMC, DNS and remote endpoints are mocked. No live domain is contacted.
param([switch]$AllControls,[switch]$ReviewedControlsOnly,[switch]$ExactPlans,[switch]$LockoutIncidentOnly,[switch]$PublicationRecoveryOnly,[string]$ReportPath)
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
function Check($ok,$name){if(!$ok){foreach($record in @($Error|Select-Object -First 3)){[Console]::Error.WriteLine(('Fixture diagnostic: '+$record.Exception.ToString()+' Stack: '+$record.ScriptStackTrace))};throw $name};Write-Output ('PASS '+$name)}
function Sysvol-Policies {return $script:folder}
function Gpo-Folder {param($Id) return $script:folder}
function Remote-GpoFolder {param($Server,$Id) return $script:folder}
function Resolve-DnsName {param($Name,$Type,$ErrorAction) [pscustomobject]@{IPAddress='127.0.0.1'}}
$script:endpointDword=0
$script:endpointPipesPresent=$false
function Invoke-Command {
 param($ComputerName,$Authentication,$ErrorAction,$ArgumentList,$ScriptBlock,$SessionOption)
 if($ArgumentList[-1] -eq $true -and $Data.mapping.id -eq '2.3.10.4'){
  return @{supported=$true;match=($script:endpointDword -eq 1);actual=('DisableDomainCreds='+$script:endpointDword);message='Fixture DWORD read.'}
 }
 if($ArgumentList[-1] -eq $true -and $Data.mapping.id -eq '2.3.10.7'){
  return @{supported=$true;match=$script:endpointPipesPresent;actual=$(if($script:endpointPipesPresent){'NullSessionPipes='}else{'NullSessionPipes=<not configured>'});registryValue=@{present=$script:endpointPipesPresent;values=@()};message='Fixture MultiString read.'}
 }
 throw 'Fixture attempted unmocked remoting; no endpoint connection is allowed'
}
function Get-ADDomain {param($Identity,$Server,$ErrorAction) return $domain}
function Get-ADDomainController {param($Filter,$Server) [pscustomobject]@{HostName=$cfg.domainController}}
function Get-ADReplicationPartnerMetadata {param($Target,$Scope,$ErrorAction) @()}
function Get-ADOrganizationalUnit {param($Identity,$Server) [pscustomobject]@{DistinguishedName=$Identity;Name='Pilot'}}
function Get-ADObject {param($Identity,$Server,$Properties,$Replace,$ErrorAction)
 if($Identity -like 'CN=*'){return [pscustomobject]@{DistinguishedName=$Identity;allowedAttributesEffective=@('versionNumber','gPCMachineExtensionNames','gPCUserExtensionNames');versionNumber=$script:version;gPCMachineExtensionNames=$script:extensions;gPCUserExtensionNames=$script:userExtensions;gPCWQLFilter='';flags=0;whenChanged=[datetime]'2026-01-01'}}
 return [pscustomobject]@{gPLink=$script:rawLinks;allowedAttributesEffective=@('gPLink','pwdHistoryLength','minPwdAge','minPwdLength','pwdProperties','lockoutDuration','lockoutThreshold','lockOutObservationWindow')}
}
function Set-ADObject {param($Identity,$Server,$Replace) $script:version=[int]$Replace.versionNumber;$script:extensions=[string]$Replace.gPCMachineExtensionNames}
function Get-GPO {param($Guid,$Domain,$Server) [pscustomobject]@{Id=[guid]$gpoId;DisplayName='Dedicated pilot';GpoStatus='AllSettingsEnabled'}}
function Get-GPPermission {param($Guid,[switch]$All,$Domain,$Server) [pscustomobject]@{Permission='GpoApply';Trustee=[pscustomobject]@{Name='Authenticated Users';Sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-11')}}}
function Get-ADDefaultDomainPasswordPolicy {param($Identity,$Server,$ErrorAction) [pscustomobject]$script:domainState}
function Set-ADDefaultDomainPasswordPolicy {
 [CmdletBinding()]param($Identity,$Server,$PasswordHistoryCount,$MinPasswordAge,$MinPasswordLength,$ComplexityEnabled,$ReversibleEncryptionEnabled,$LockoutDuration,$LockoutThreshold,$LockoutObservationWindow)
 if($script:domainWriteDenied){throw [UnauthorizedAccessException]::new('Fixture domain property write denied')}
 if($script:domainWriteNoOp){return}
 foreach($key in @($PSBoundParameters.Keys|Where-Object{$_ -in $script:domainState.Keys})){$script:domainState[$key]=$PSBoundParameters[$key]}
}

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
 $backupId=[guid]::NewGuid();$native=Join-Path (Join-Path $Path $backupId.ToString('B')) 'DomainSysvol/GPO';$null=New-Item -ItemType Directory -Path $native -Force;Copy-Item -Path (Join-Path $script:folder '*') -Destination $native -Recurse
 [pscustomobject]@{Id=$backupId}
}
function Import-GPO {param($BackupId,$TargetGuid,$Path,$Domain,$Server)
 Get-ChildItem -LiteralPath $script:folder -Force|Remove-Item -Recurse -Force
 Copy-Item -Path (Join-Path $Path 'snapshot/*') -Destination $script:folder -Recurse
 $script:version=$script:snapshot.version;$script:extensions=$script:snapshot.extensions;$script:userExtensions=$script:snapshot.userExtensions;$script:registry=$script:snapshot.registry.Clone()
}
function Invoke-GPUpdate {param($Computer,$Force,$RandomDelayInMinutes,$ErrorAction,$Target) $script:refreshes++}
function Test-NativeRestoreFormatting($Selection,$Mapping){
 $originalImport=(Get-Item Function:\Import-GPO).ScriptBlock
 $script:formatImportBase=$originalImport
 try{
  function Import-GPO {param($BackupId,$TargetGuid,$Path,$Domain,$Server)
   & $script:formatImportBase -BackupId $BackupId -TargetGuid $TargetGuid -Path $Path -Domain $Domain -Server $Server
   $file=Join-Path $script:folder 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf';$rows=@()
   foreach($line in ([IO.File]::ReadAllText($file) -split '\r?\n')){
    if([string]::IsNullOrWhiteSpace($line)){continue}
    if($line -match '^\s*(Se\w+)\s*=\s*(.*)$'){$key=$Matches[1];$values=[string[]]($Matches[2] -split ',');[array]::Reverse($values);$rows+=($key+' = '+($values -join ','))}else{$rows+=$line}
   }
   $blocks=@([regex]::Split(($rows -join "`r`n"),'(?m)(?=^\[)')|Where-Object{$_})
   $ordered=@($blocks|Where-Object{$_ -notmatch '^\[(Version|Privilege Rights)\]'})+@($blocks|Where-Object{$_ -match '^\[Version\]'})+@($blocks|Where-Object{$_ -match '^\[Privilege Rights\]'})
   [IO.File]::WriteAllText($file,($ordered -join "`r`n")+"`r`n",[Text.Encoding]::Unicode)
  }
  foreach($mode in @('new','legacy')){
   $s=$Selection.Clone();$s.scopeDn=$domainDn;$s.firstLink=$true
   $path=Join-Path $script:folder 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf';$null=New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force
   $base="[Unicode]`r`nUnicode=yes`r`n`r`n[Privilege Rights]`r`nSeSystemTimePrivilege = *S-1-5-32-544,*S-1-5-19`r`n`r`nSeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20`r`n`r`nSeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6`r`nSeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n"
   [IO.File]::WriteAllText($path,$base,[Text.Encoding]::Unicode);[IO.File]::WriteAllText((Join-Path $script:folder 'opaque.dat'),'keep')
   $script:extensions=Add-SecurityExtension '';$script:rawLinks='[LDAP://CN={'+$gpoId+'},CN=Policies,CN=System,'+$domainDn+';0]'
   $plan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$s;preview=(Preview $s $Mapping)}
   $Data=@{plan=$plan;mapping=$Mapping;consent=@{confirmation='APPLY'}};$Operation='gpoApply';$applied=& $dispatch
   Check ($applied.state -eq 'PUBLISHED') ('native restore fixture publication '+$mode)
   $directory=Run-Directory $plan;$manifestPath=Join-Path $directory 'manifest.json';$m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
   $backup=Join-Path (Join-Path $directory (([guid]$m.backupId).ToString('B'))) 'DomainSysvol/GPO'
   Remove-Item -LiteralPath (Join-Path $backup 'GPT.INI') -Force
   if($mode -eq 'legacy'){$m.PSObject.Properties.Remove('beforeRestoreContent');Save-Manifest $m $directory}
   $Operation='gpoRollback';$restored=& $dispatch
   Check ($restored.state -eq 'ROLLED_BACK' -and $null -eq $restored.currentValue -and @($restored.restoreChecks|Where-Object{$_.area -eq 'CONTENT' -and $_.state -eq 'MATCH'}).Count -eq 1) ('2.2.24 native SID ordering and empty-line changes verify complete restore '+$mode)
   Check ((Get-NormalizedGpoContentFingerprint $script:folder) -cne [string]$m.beforeContent) ('semantic restore never rewrites the legacy drift fingerprint '+$mode)
   $Operation='gpoVerify';$verified=& $dispatch;Check ($verified.state -eq 'ROLLED_BACK') ('read-only Verify retains authenticated formatted restore '+$mode)
   $Operation='gpoRefresh';$Data.refresh='Scope';$refresh=& $dispatch;Check ($refresh.state -eq 'ROLLED_BACK' -and $refresh.refreshResults.Count -gt 0) ('Scope gpupdate is permitted after verified native restore '+$mode)
   [IO.File]::WriteAllText((Join-Path $script:folder 'opaque.dat'),'external change');$Operation='gpoVerify';$changed=& $dispatch
   Check ($changed.state -eq 'ROLLBACK_DRIFT_DETECTED' -and $changed.message -match 'CONTENT') ('real post-restore file change still reports content drift '+$mode)
   $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json;$m.phase='ROLLBACK_REVIEW_REQUIRED';$m.PSObject.Properties.Remove('rollbackFingerprint');Save-Manifest $m $directory
   $unverified=& $dispatch;Check ($unverified.state -eq 'ROLLBACK_REVIEW_REQUIRED' -and $unverified.message -match 'No completed restore') ('unverified restore mismatch is not mislabeled later external drift '+$mode)
   [IO.File]::WriteAllText((Join-Path $script:folder 'opaque.dat'),'keep')
   if($mode -eq 'legacy'){
    [IO.File]::WriteAllText((Join-Path $backup 'opaque.dat'),'corrupt')
    $blocked=& $dispatch;Check ($blocked.state -eq 'ROLLBACK_REVIEW_REQUIRED' -and @($blocked.restoreChecks|Where-Object{$_.area -eq 'CONTENT' -and $_.state -eq 'UNAVAILABLE'}).Count -eq 1) 'corrupt legacy backup cannot authorize semantic restore equivalence'
    [IO.File]::WriteAllText((Join-Path $backup 'opaque.dat'),'keep')
   }
   $Operation='gpoRollbackInspect';$ready=& $dispatch;Check ($ready.canRestore -and $ready.manifestPhase -eq 'ROLLED_BACK') ('rollback availability recovers authenticated formatted snapshot '+$mode)
   $Operation='gpoVerify';$recovered=& $dispatch;Check ($recovered.state -eq 'ROLLED_BACK') ('legacy false-review operation recovers by read-only proof '+$mode)
   $compareFn=(Get-Item Function:\Compare-RestoreContent).ScriptBlock
   try{function Compare-RestoreContent {param($Plan,$Manifest) throw [UnauthorizedAccessException]::new('Private read failure')};$unavailable=& $dispatch;Check ($unavailable.state -eq 'ROLLBACK_REVIEW_REQUIRED' -and $unavailable.message -notmatch 'Private read failure') ('unavailable restore evidence does not assert external drift '+$mode)}finally{Set-Item Function:\Compare-RestoreContent $compareFn}
  }
 }finally{Set-Item Function:\Import-GPO $originalImport}
}
function Test-PublicationRecovery($Selection,$Mapping){
 $s=$Selection.Clone();$s.refresh='None'
 $originalVerifier=(Get-Item Function:\Verify-Published).ScriptBlock
 $script:publicationVerifier=$originalVerifier
 try{
  foreach($mode in @('checkpoint','legacy','direct','legacy-direct','legacy-unchanged')){
   $script:domainState.LockoutDuration=[timespan]::FromMinutes(30);$script:domainState.LockoutObservationWindow=[timespan]::FromMinutes(30);$script:domainState.LockoutThreshold=0
   New-GPLink -Guid ([guid]$s.gpoId) -Target $s.scopeDn -Domain $cfg.domain -Server $cfg.domainController -LinkEnabled Yes -Order 1|Out-Null
   $path=Security-Path $s.gpoId;$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
   $item=@(Mapping-Items $Mapping)[0]
   $initial=if($mode -eq 'legacy-unchanged'){'15'}else{'30'}
   Atomic-Text $path (Set-SecurityTemplateValue '' ([string]$item.section) ([string]$item.key) $initial) ([Text.Encoding]::Unicode)
   $foreign=Join-Path $script:folder 'unrelated-policy.txt';[IO.File]::WriteAllText($foreign,'retain')
   $plan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$s;preview=(Preview $s $Mapping)}
   $script:failPublication=$true
   function Verify-Published {param($Plan,$Map,[bool]$CheckEndpoints=$false) if($script:failPublication){$script:failPublication=$false;throw [Management.Automation.MethodInvocationException]::new('Fixture metadata invocation failure')};return & $script:publicationVerifier $Plan $Map $CheckEndpoints}
   $Operation='gpoApply';$Data=@{plan=$plan;mapping=$Mapping;consent=@{confirmation='APPLY'}};$failed=& $dispatch
   $directory=Run-Directory $plan;$manifestPath=Join-Path $directory 'manifest.json';$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
   Check ($failed.state -eq 'REVIEW_REQUIRED' -and $script:domainState.LockoutObservationWindow.TotalMinutes -eq 15 -and $manifest.failure.stage -eq 'PUBLICATION_CHECK' -and $manifest.postFingerprint) ('publication failure retains completed write checkpoint '+$mode)
   if($mode -like 'legacy*'){$manifest.postFingerprint=$null;Save-Manifest $manifest $directory}
   if($mode -eq 'legacy'){
    [IO.File]::WriteAllText($foreign,'external-change')
    $Operation='gpoVerify';$pending=& $dispatch
    Check ($pending.state -eq 'PUBLISHED' -and [IO.File]::ReadAllText($foreign) -eq 'external-change' -and !(Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json).postFingerprint) 'Live publication can verify without anchoring unrelated GPO drift for rollback'
    $Operation='gpoRefresh';$Data.refresh='Pdc';$refreshDrift=& $dispatch;Check ($refreshDrift.state -in @('REFRESH_SCHEDULED','REFRESH_COMPLETED') -and [IO.File]::ReadAllText($foreign) -eq 'external-change') 'Explicit refresh remains possible after current publication verification without restoring unrelated settings'
    $Operation='gpoVerify'
    [IO.File]::WriteAllText($foreign,'retain')
    $nativeForeign=Join-Path (Join-Path (Join-Path $directory (([guid]$manifest.backupId).ToString('B'))) 'DomainSysvol/GPO') 'unrelated-policy.txt'
    [IO.File]::WriteAllText($nativeForeign,'corrupt-backup');$pending=& $dispatch
    Check ($pending.state -eq 'PUBLISHED' -and [IO.File]::ReadAllText($foreign) -eq 'retain' -and !(Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json).postFingerprint) 'Corrupt retained backup cannot authorize an automatic full restore'
    [IO.File]::WriteAllText($nativeForeign,'retain')
    $script:domainState.LockoutObservationWindow=[timespan]::FromMinutes(20)
    $pending=& $dispatch;Check ($pending.state -eq 'PUBLISHED' -and $pending.effectiveStatus -eq 'ENDPOINT_MISMATCH' -and !(Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json).postFingerprint) 'Legacy verification retains external AD mismatch and leaves rollback unanchored'
    $script:domainState.LockoutObservationWindow=[timespan]::FromMinutes(15)
   }
   if($mode -in @('checkpoint','legacy')){
    $before=Fingerprint $s.gpoId $s.scopeDn
    $Operation='gpoVerify';$recovered=& $dispatch
    $receipt=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    Check ($recovered.state -eq 'PUBLISHED' -and $recovered.gpoPublished -and $recovered.linkVerified -and (Fingerprint $s.gpoId $s.scopeDn) -ceq $before -and $receipt.failure.stage -eq 'PUBLICATION_CHECK' -and $receipt.publicationRecovery.method) ('read-only Verify recovers publication without replay and retains failure '+$mode)
    $Operation='gpoRefresh';$Data.refresh='Pdc';$refreshed=& $dispatch
    Check ($refreshed.state -in @('REFRESH_SCHEDULED','REFRESH_COMPLETED') -and $script:domainState.LockoutObservationWindow.TotalMinutes -eq 15) ('recovered publication permits explicit gpupdate '+$mode)
   }
   if($mode -eq 'legacy-unchanged'){$Operation='gpoRollbackInspect';$assessment=& $dispatch;Check ($assessment.canRestore -and $assessment.domainSnapshotDiverges) 'Recovery exposes different pre-change GPO and AD values before optional gpupdate'}
   if($mode -eq 'checkpoint'){
    $access=(Get-Item Function:\Assert-SelectionAccess).ScriptBlock
    try{
     function Assert-SelectionAccess {param($Selection,$Mapping) throw [UnauthorizedAccessException]::new('Fixture restore access denied')}
     $Operation='gpoRollback';$denied=& $dispatch
     Check ($denied.state -eq 'FAILED_SAFE' -and $denied.domainPolicy.value -eq '15' -and $denied.domainPolicy.desiredValue -eq '30') 'Denied rollback reports actual AD and restoration target without claiming an effect'
    }finally{Set-Item Function:\Assert-SelectionAccess $access}
    $Operation='gpoVerify';$notRestored=& $dispatch
    Check ($notRestored.state -eq 'ROLLBACK_REVIEW_REQUIRED' -and $notRestored.domainPolicy.value -eq '15' -and $notRestored.domainPolicy.desiredValue -eq '30') 'Read-only Verify cannot hide a blocked rollback as successful Apply'
   }
   $Operation='gpoRollback';$restored=& $dispatch
   Check ($restored.state -eq 'ROLLED_BACK' -and $script:domainState.LockoutObservationWindow.TotalMinutes -eq 30 -and (Get-ItemCurrent $s.gpoId $Mapping $item) -eq $initial -and $restored.domainPolicy.value -eq '30' -and $restored.domainPolicy.desiredValue -eq '30' -and [IO.File]::ReadAllText($foreign) -eq 'retain') ('rollback restores the original GPO and reports actual AD 15 to 30 after publication failure '+$mode)
  }
 }finally{Set-Item Function:\Verify-Published $originalVerifier}
}
function Test-ExactLockoutIncident($Selection,$Mapping,$ExactFixtures){
 $script:domainState.LockoutDuration=[timespan]::FromMinutes(30);$script:domainState.LockoutObservationWindow=[timespan]::FromMinutes(30)
 $fingerprint=Fingerprint $Selection.gpoId $Selection.scopeDn;$beforeFiles=@(Get-ChildItem -LiteralPath $cfg.backupPath -Recurse -File).Count
 $dependencyPreview=Preview $Selection $Mapping
 Check ($dependencyPreview.dependency.code -eq 'DOMAIN_LOCKOUT_DEPENDENCY' -and $dependencyPreview.dependency.setting -eq '1.2.4' -and $dependencyPreview.dependency.value -eq 15 -and (Fingerprint $Selection.gpoId $Selection.scopeDn) -ceq $fingerprint -and @(Get-ChildItem -LiteralPath $cfg.backupPath -Recurse -File).Count -eq $beforeFiles -and $script:domainState.LockoutThreshold -eq 0) '30/30/0 incident returns actionable 1.2.4 prerequisite without backup/write/link'
 $incompatiblePlan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$Selection;preview=$dependencyPreview}
 $Operation='gpoApply';$Data=@{plan=$incompatiblePlan;mapping=$Mapping;consent=@{confirmation='APPLY'}};$blocked=$false;try{$null=& $dispatch}catch{$blocked=$_.Exception.Message -match 'DOMAIN_LOCKOUT_DEPENDENCY'}
 Check ($blocked -and (Fingerprint $Selection.gpoId $Selection.scopeDn) -ceq $fingerprint -and $script:domainState.LockoutDuration.TotalMinutes -eq 30 -and $script:domainState.LockoutObservationWindow.TotalMinutes -eq 30) 'Blocked dependency cannot write GPO or AD even through direct Apply'
 $reverse=Domain-ChangeDependency 'LockoutObservationWindow' '45'
 Check ($reverse.setting -eq '1.2.1' -and $reverse.value -eq 45) 'Window above duration proposes explicit duration review'
 Check ($null -eq (Domain-ChangeDependency 'LockoutDuration' '0')) 'Unlimited duration has no finite-window dependency'
 $windowFixture=$ExactFixtures|Where-Object{$_.mapping.id -eq '1.2.4' -and $_.selection.accountScope -eq 'Domain'}
 $windowS=$Selection.Clone();$windowS.setting='1.2.4';$windowS.value=15;$windowS.itemValues=@(@('15'))
 $windowMap=$windowFixture.mapping
 $windowPlan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$windowS;preview=(Preview $windowS $windowMap)}
 $Operation='gpoApply';$Data=@{plan=$windowPlan;mapping=$windowMap;consent=@{confirmation='APPLY'}};$windowResult=& $dispatch
 Check ($windowResult.state -eq 'PUBLISHED' -and $script:domainState.LockoutObservationWindow.TotalMinutes -eq 15 -and $script:domainState.LockoutDuration.TotalMinutes -eq 30 -and $script:domainState.LockoutThreshold -eq 0) 'Explicit 1.2.4 change updates only window, preserving duration and disabled threshold'
 $script:domainState.LockoutDuration=[timespan]::FromMinutes(15);$Operation='gpoRollback';$Data=@{plan=$windowPlan;mapping=$windowMap};$blockedResult=& $dispatch
 Check ($blockedResult.state -eq 'FAILED_SAFE' -and $script:domainState.LockoutObservationWindow.TotalMinutes -eq 15) 'Rollback rejects incompatible peer state before restoring GPO'
 $script:domainState.LockoutDuration=[timespan]::FromMinutes(30)
 # Stored duration is already 15, while AD still has 30: the original incident.
 $null=Write-Mapping @{selection=$Selection} $Mapping
 $durationPreview=Preview $Selection $Mapping
 Check (!$durationPreview.noChange -and $durationPreview.previousValue -eq '15' -and $durationPreview.domainPolicy.value -eq '30') 'GPO 15 / AD 30 with a live link is not NO_CHANGE'
 $durationPlan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$Selection;preview=$durationPreview}
 $Operation='gpoApply';$Data=@{plan=$durationPlan;mapping=$Mapping;consent=@{confirmation='APPLY'}};$durationResult=& $dispatch
 Check ($durationResult.state -eq 'PUBLISHED' -and $durationResult.domainPolicy.value -eq '15' -and $durationResult.currentLink.enabled -and $durationResult.currentLink.order -eq 1 -and $script:domainState.LockoutObservationWindow.TotalMinutes -eq 15 -and $script:domainState.LockoutThreshold -eq 0) 'Exact duration Apply changes AD 30 to 15, retains peers and records enabled priority-1 link'
 $script:domainState.LockoutDuration=[timespan]::FromMinutes(30);$Operation='gpoVerify';$observed=& $dispatch
 Check ($observed.effectiveStatus -eq 'ENDPOINT_MISMATCH' -and $observed.endpointChecks[0].state -eq 'MISMATCH') 'Re-verify AD 30/requested 15 never accepts benchmark minimum compliance'
 $script:domainState.LockoutDuration=[timespan]::FromMinutes(15);$Operation='gpoRollback';$restored=& $dispatch
 Check ($restored.state -eq 'ROLLED_BACK' -and $script:domainState.LockoutDuration.TotalMinutes -eq 30) 'Duration rollback restores actual AD snapshot 30'
 $Data=@{plan=$windowPlan;mapping=$windowMap}
 # Duration publication changed the same GPO after window publication; recovery
 # correctly requires the original window post-state, never overwrites drift.
 $Operation='gpoRollback';$blocked=$false;try{$null=& $dispatch}catch{$blocked=$_.Exception.Message -match 'ROLLBACK_CONFLICT'}
 Check ($blocked) 'Earlier full-GPO snapshot does not overwrite later GPO changes'
}
$catalog=(Get-Content (Join-Path $repo 'backend/data/gpo-production-mappings.json') -Raw|ConvertFrom-Json).mappings
try{
 $cases=@(@('1.1.1','LocalComputers'),@('1.1.1','Domain'),@('1.2.2','Domain'),@('2.2.24','LocalComputers'),@('2.3.1.1','LocalComputers'),@('2.3.10.4','LocalComputers'),@('2.3.10.7','LocalComputers'),@('18.4.4','LocalComputers'),@('17.1.1','LocalComputers'),@('19.5.1.1','Users'))
 foreach($entry in @($catalog|Where-Object{$_.domainPolicySensitive -and $_.id -notin @('1.1.1','1.2.2')})){$cases+=,@([string]$entry.id,'Domain')}
 foreach($manual in @($catalog|Where-Object automation -ne 'Automated')){$cases+=,@([string]$manual.id,'LocalComputers')}
 if($AllControls){$cases=@();foreach($entry in $catalog){$cases+=,@([string]$entry.id,$(if($entry.scope -eq 'User'){'Users'}else{'LocalComputers'}));if($entry.domainPolicySensitive){$cases+=,@([string]$entry.id,'Domain')}}}
 $reviewed=@()
 if($ReviewedControlsOnly){
  $reviewed=Get-Content -LiteralPath (Join-Path $repo 'work/audit/reviewed-values.json') -Raw|ConvertFrom-Json
  Check (@($reviewed).Count -eq 11) 'C# reviewed mapping fixtures cover every reviewed control'
  $cases=@();foreach($entry in $reviewed){$cases+=,@([string]$entry.mapping.id,'LocalComputers')}
 }
 $report=@()
 if($ExactPlans){
  $exact=Get-Content -LiteralPath (Join-Path $repo 'work/audit/exact-values.json') -Raw|ConvertFrom-Json
  Check (@($exact).Count -eq 413) 'C# exact mapping fixtures cover all 405 controls and both account scopes'
  $cases=@();foreach($entry in $exact){$cases+=,@([string]$entry.mapping.id,[string]$entry.selection.accountScope)}
 }
 if($LockoutIncidentOnly){if(!$ExactPlans){throw 'LockoutIncidentOnly requires ExactPlans'};$cases=@($cases|Where-Object{$_[0] -eq '1.2.1' -and $_[1] -eq 'Domain'})}
 if($PublicationRecoveryOnly){if(!$ExactPlans){throw 'PublicationRecoveryOnly requires ExactPlans'};$cases=@($cases|Where-Object{$_[0] -eq '1.2.4' -and $_[1] -eq 'Domain'})}
 foreach($case in $cases){
  $map=($catalog|Where-Object id -eq $case[0])|ConvertTo-Json -Depth 15|ConvertFrom-Json
  if($ReviewedControlsOnly){$map=($reviewed|Where-Object{$_.mapping.id -eq $case[0]}).mapping}
  if($ExactPlans){$approved=$exact|Where-Object{$_.mapping.id -eq $case[0] -and $_.selection.accountScope -eq $case[1]};$map=$approved.mapping}
  Check ($null -ne $map) ('mapping exists '+$case[0])
  if($map.automation -ne 'Automated'){$map.automation='Automated';if($map.handler -eq 'Manual'){$map.handler='SecurityTemplate'}}
  if($case[1] -eq 'LocalComputers' -and $map.domainPolicySensitive){$map.scope='Computer';$map.domainPolicySensitive=$false}
  foreach($item in $map.items){foreach($field in @('section','key','name','type','guid','state','mask','value')){if(!$item.PSObject.Properties[$field]){$item|Add-Member -NotePropertyName $field -NotePropertyValue $(if($field -eq 'type'){'String'}else{$null})}}}
  if(Test-Path $script:folder){Remove-Item -LiteralPath $script:folder -Recurse -Force}
  $null=New-Item -ItemType Directory -Path $script:folder
  [IO.File]::WriteAllText((Join-Path $script:folder 'GPT.INI'),"[General]`r`nVersion=0`r`n")
  $script:version=0;$script:extensions='';$script:userExtensions='';$script:rawLinks='';$script:registry=@{}
  $s=@{gpoId=$gpoId;scopeDn=$(if($case[1] -eq 'Domain'){$domainDn}else{$target});setting=$map.id;value=$map.suggested;customValue=$(if($map.requiresInput){if($map.inputDefault){[string]$map.inputDefault}else{'Authorized use only'}}else{''});refresh='None';firstLink=($case[1] -eq 'Domain');accountScope=$case[1];endpointScopeDn='';verificationUser=''}
  if($ReviewedControlsOnly){$approved=($reviewed|Where-Object{$_.mapping.id -eq $map.id});$s.itemValues=$approved.selection.itemValues;$s.reviewContext=$approved.selection.reviewContext}
  if($ExactPlans){$s.itemValues=Read-Field $approved.selection 'itemValues' $null;$s.reviewContext=Read-Field $approved.selection 'reviewContext' $null;$s.value=$approved.selection.value}
  $script:domainState=@{PasswordHistoryCount=0;MinPasswordAge=[timespan]::Zero;MinPasswordLength=7;ComplexityEnabled=$false;ReversibleEncryptionEnabled=$true;LockoutDuration=[timespan]::FromMinutes(30);LockoutThreshold=0;LockoutObservationWindow=[timespan]::FromMinutes(15)};$script:domainWriteDenied=$false;$script:domainWriteNoOp=$false
  if($map.id -eq '1.2.2' -and $case[1] -eq 'Domain'){$null=Write-Mapping @{selection=$s} $map}
  $Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$script:workerStage='VALIDATING';$preview=& $dispatch
  if($map.id -eq '1.2.2' -and $case[1] -eq 'Domain'){Check (!$preview.noChange -and $preview.previousValue -eq '5' -and $preview.domainPolicy.value -eq '0') 'GPO 5 / AD 0 is a real change, never NO_CHANGE'}else{Check ($null -eq $preview.previousValue -and $null -eq $preview.previousValueSource) ('unconfigured source '+$map.id)}
  Check ($preview.preflight.ready) ('readiness '+$map.id+' '+$case[1])
  $plan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$s;preview=$preview}
  $refreshBefore=$script:refreshes
  $Operation='gpoApply';$Data=@{plan=$plan;mapping=$map;consent=@{confirmation='APPLY'}};$result=& $dispatch
  Check ($result.state -eq 'PUBLISHED') ('backup/write/link/publication '+$map.id+' '+$case[1]+': '+$result.message)
  if($map.id -eq '2.3.10.4'){
   $receipt=Get-Content -LiteralPath (Join-Path (Run-Directory $plan) 'manifest.json') -Raw|ConvertFrom-Json
   Check ($receipt.beforeEndpointReadings.checks[0].actualValue -eq 'DisableDomainCreds=0') 'DisableDomainCreds pre-Apply registry reading is saved with the backup'
   $script:endpointDword=1
  }
  if($map.id -eq '2.3.10.7'){$script:endpointPipesPresent=$true}
  Check ($result.currentValueSource.gpoId -eq $gpoId -and $result.currentValueSource.gpoName -eq 'Dedicated pilot') ('configured source '+$map.id)
  # The stored value can match even when the selected target has no direct link.
  $savedLinks=$script:rawLinks;$script:rawLinks=''
  $unlinked=Preview $s $map
  Check (!$unlinked.noChange -and $null -eq $unlinked.existingLink -and $unlinked.previousValue -eq $result.currentValue) ('matching stored GPO without target link is not NO_CHANGE '+$map.id)
  $script:rawLinks=$savedLinks
  Check ($script:refreshes -eq $refreshBefore) 'Apply does not schedule unrequested endpoint refresh'
  if($case[1] -ne 'Users'){
   $Operation='gpoRefresh';$Data.refresh=if($case[1] -eq 'Domain'){'Pdc'}else{'Scope'};$result=& $dispatch
   Check ($result.state -eq 'REFRESH_SCHEDULED' -and $script:refreshes -eq $refreshBefore+1) ('explicit refresh schedules exactly one target '+$map.id)
  }
  if($map.id -eq '1.2.2' -and $case[1] -eq 'Domain'){
   Check ($script:domainState.LockoutThreshold -eq 5 -and $result.domainPolicy.value -eq '5') 'Apply writes and reads back the effective AD threshold'
   $script:domainState.LockoutThreshold=0;$Operation='gpoVerify';$observed=& $dispatch
   Check ($observed.gpoPublished -and $observed.currentValue -eq '5' -and $observed.effectiveStatus -eq 'ENDPOINT_MISMATCH' -and $observed.endpointChecks[0].actualValue -eq '0') 'User incident: GPO 5 / AD 0 is measured as mismatch with actual value 0'
   $Operation='gpoRollback';$blocked=$false;try{$null=& $dispatch}catch{$blocked=$_.Exception.Message -match 'ROLLBACK_CONFLICT'}
   Check ($blocked -and $script:domainState.LockoutThreshold -eq 0) 'External AD policy change blocks rollback without overwriting it'
   $script:domainState.LockoutThreshold=5
  }
  $Operation='gpoRollback';$result=& $dispatch
  Check ($result.state -eq 'ROLLED_BACK') ('snapshot rollback '+$map.id)
  $Operation='gpoVerify';$result=& $dispatch
  Check ($result.state -eq 'ROLLED_BACK') ('rollback read-back '+$map.id)
  if($map.id -eq '2.3.10.4'){
   Check ($result.effectiveStatus -eq 'ROLLBACK_ENDPOINT_MISMATCH' -and $result.endpointChecks[0].actualValue -eq 'DisableDomainCreds=1') '2.3.10.4 snapshot restore exposes unchanged endpoint policy'
   $script:endpointDword=0
   $result=& $dispatch
   Check ($result.effectiveStatus -eq 'ROLLBACK_ENDPOINT_SAMPLE_MATCH') '2.3.10.4 read-only verification recognizes return to the saved endpoint value'
  }
  if($map.id -eq '2.3.10.7'){
   $endpoint=$result.endpointChecks[0]
   Check ($result.effectiveStatus -eq 'ROLLBACK_ENDPOINT_MISMATCH' -and $endpoint.beforeActualValue -eq 'NullSessionPipes=<not configured>' -and $endpoint.actualValue -eq 'NullSessionPipes=[]' -and $endpoint.recoveryCommand -match 'DeleteValue') '2.3.10.7 distinguishes an absent baseline from a retained blank list and prepares guarded recovery'
   $script:endpointPipesPresent=$false
   $result=& $dispatch
   Check ($result.effectiveStatus -eq 'ROLLBACK_ENDPOINT_SAMPLE_MATCH' -and !(Read-Field $result.endpointChecks[0] 'recoveryCommand')) '2.3.10.7 confirms the restored absent value and offers no second repair'
  }
  if($map.id -eq '1.2.2' -and $case[1] -eq 'Domain'){Check ($script:domainState.LockoutThreshold -eq 0 -and $result.currentValue -eq '5') 'Rollback restores the recorded AD threshold separately from the GPO snapshot'}else{Check ($null -eq $result.currentValue -and $null -eq $result.currentValueSource) ('rollback clears configured value and source '+$map.id)}
  if($map.id -eq '1.2.2' -and $case[1] -eq 'Domain'){
   $failedPlan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$s}
   $Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$failedPlan.preview=& $dispatch
   $script:domainWriteDenied=$true;$Operation='gpoApply';$Data=@{plan=$failedPlan;mapping=$map;consent=@{confirmation='APPLY'}};$failed=& $dispatch
   $saved=Get-Content -LiteralPath (Join-Path (Run-Directory $failedPlan) 'manifest.json') -Raw|ConvertFrom-Json
   Check ($failed.state -eq 'REVIEW_REQUIRED' -and !$failed.gpoPublished -and $script:domainState.LockoutThreshold -eq 0 -and $saved.beforeDomainPolicy.value -eq '0' -and $saved.failure.stage -eq 'DOMAIN_POLICY_WRITE') 'Denied domain write never reports success and retains the pre-change AD snapshot'
   $script:domainWriteDenied=$false
   $failedPlan.id=[guid]::NewGuid().ToString('N');$Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$failedPlan.preview=& $dispatch
   $script:domainWriteNoOp=$true;$Operation='gpoApply';$Data=@{plan=$failedPlan;mapping=$map;consent=@{confirmation='APPLY'}};$noOp=& $dispatch
   $saved=Get-Content -LiteralPath (Join-Path (Run-Directory $failedPlan) 'manifest.json') -Raw|ConvertFrom-Json
   Check ($noOp.state -eq 'REVIEW_REQUIRED' -and !$noOp.gpoPublished -and $saved.failure.code -eq 'DOMAIN_POLICY_WRITE_MISMATCH' -and $script:domainState.LockoutThreshold -eq 0) 'A silent no-op AD setter cannot become a successful Apply'
   $script:domainWriteNoOp=$false
  }
  if($map.id -eq '2.2.6'){
   # A failed reviewed write followed by repeated Verify must retain its cause.
   $failedPlan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$s}
   $Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$failedPlan.preview=& $dispatch
   $writerFn=(Get-Item Function:\Write-Mapping).ScriptBlock
   $probeFn=(Get-Item Function:\Verify-EffectiveSamples).ScriptBlock
   try{
    function Write-Mapping {throw [UnauthorizedAccessException]::new('Access is denied for private fixture')}
    function Verify-EffectiveSamples {param($Plan,$Map) @(@{hostname='ws.example.test';state='UNAVAILABLE';actualValue=$null;message='Fixture endpoint unavailable; no network probe.'})}
    $Operation='gpoApply';$Data=@{plan=$failedPlan;mapping=$map;consent=@{confirmation='APPLY'}};$failed=& $dispatch
    Check ($failed.state -eq 'REVIEW_REQUIRED') 'reviewed 2.2.6 write denial remains review-required'
    Set-Item Function:\Write-Mapping $writerFn
    $unchanged=Fingerprint $s.gpoId $s.scopeDn
    foreach($attempt in 1..2){
     $Operation='gpoVerify';$observed=& $dispatch
     Check ($observed.state -eq 'REVIEW_REQUIRED' -and $observed.message -match 'Original failure \[GPO_NATIVE_ACCESS_DENIED\]' -and $observed.message -match 'WRITING') ('Verify retains original reviewed 2.2.6 failure '+$attempt)
     Check ($observed.message -notmatch 'Private fixture') 'verification never exposes raw native errors'
    }
    Check ((Fingerprint $s.gpoId $s.scopeDn) -ceq $unchanged) 'repeated Verify never retries the reviewed write'
    $Operation='gpoRefresh';$Data.refresh='Scope';$blocked=$false;try{$null=& $dispatch}catch{$blocked=$_.Exception.Message -match 'REFRESH_REVIEW_REQUIRED'}
    Check ($blocked) 'refresh stays blocked until interrupted publication is repaired'
    $repair=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;selection=$s}
    $Operation='gpoPreview';$Data=@{selection=$s;mapping=$map};$repair.preview=& $dispatch
    $Operation='gpoApply';$Data=@{plan=$repair;mapping=$map;consent=@{confirmation='APPLY'}};$repaired=& $dispatch
    Check ($repaired.state -eq 'PUBLISHED' -and $repaired.gpoPublished -and $repaired.linkVerified) 'fresh reviewed repair plan completes 2.2.6 publication and link'
    $Operation='gpoRefresh';$Data.refresh='Scope';$refreshed=& $dispatch
    Check ($refreshed.state -eq 'REFRESH_SCHEDULED') 'explicit gpupdate becomes available after reviewed repair publication'
    $Operation='gpoRollback';$restored=& $dispatch
    Check ($restored.state -eq 'ROLLED_BACK') 'reviewed repair retains snapshot rollback'
   }finally{Set-Item Function:\Write-Mapping $writerFn;Set-Item Function:\Verify-EffectiveSamples $probeFn}
  }
  if($ExactPlans -and $map.id -eq '1.2.1' -and $case[1] -eq 'Domain'){Test-ExactLockoutIncident $s $map $exact}
  if($ExactPlans -and $map.id -eq '1.2.4' -and $case[1] -eq 'Domain'){Test-PublicationRecovery $s $map}
  if(!$ExactPlans -and $map.id -eq '2.2.24'){Test-NativeRestoreFormatting $s $map}
  $report+=@{controlId=[string]$map.id;domain=([string]$map.id -split '\.')[0];scope=$case[1];state='PASS';steps=$(if($case[1] -eq 'Users'){@('preview','backup','write','link','source','rollback','verify')}else{@('preview','backup','write','link','source','refresh','rollback','verify')})}
 }
 if($ReportPath){$output=[IO.Path]::GetFullPath($ReportPath);$null=New-Item -ItemType Directory -Path (Split-Path $output -Parent) -Force;$report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $output -Encoding UTF8}
 if($LockoutIncidentOnly -or $PublicationRecoveryOnly){Write-Output 'PASS focused lockout chain: guided prerequisite, explicit AD 30 -> 15, exact verify, peer drift and snapshot rollback';return}
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
