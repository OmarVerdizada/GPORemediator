# Batch-only AD snapshot helpers. Private manifests and native directory doubles;
# no real domain cmdlet, GPO write, endpoint process or machine policy is invoked.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Check($ok,$name){if(!$ok){throw $name};Write-Output ('PASS '+$name)}
function Reject($Block,$Code){try{& $Block|Out-Null;throw 'Expected rejection'}catch{if($_.Exception.Message -notlike ($Code+'|*')){throw}}}
$temp=Join-Path $repo ('work/batch-domain-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
$cfg=@{domainController='dc.example.test'};$domainDn='DC=example,DC=test';$script:writes=0;$script:lastOptions=$null
$script:policy=@{LockoutDuration=[timespan]::FromMinutes(15);LockoutObservationWindow=[timespan]::FromMinutes(15);LockoutThreshold=5;MinPasswordLength=14;MinPasswordAge=[timespan]::FromDays(1);PasswordHistoryCount=24;ComplexityEnabled=$true;ReversibleEncryptionEnabled=$false}
function Get-ADDefaultDomainPasswordPolicy {param($Identity,$Server,$ErrorAction) $script:policy}
function Domain-PolicyAccess {param($Property) if($Property -eq 'Unapproved'){throw 'Unapproved property'}}
function Run-Directory {param($Plan) Join-Path $temp $Plan.id}
function Set-ADDefaultDomainPasswordPolicy {
 param($Identity,$Server,$ErrorAction,$LockoutDuration,$LockoutObservationWindow,$LockoutThreshold,$MinPasswordLength,$MinPasswordAge,$PasswordHistoryCount,$ComplexityEnabled,$ReversibleEncryptionEnabled)
 $script:writes++;$script:lastOptions=@{};foreach($key in $PSBoundParameters.Keys){$script:lastOptions[$key]=$PSBoundParameters[$key];if($script:policy.ContainsKey($key)){$script:policy[$key]=$PSBoundParameters[$key]}}
 if($script:policy.LockoutDuration.TotalMinutes -gt 0 -and $script:policy.LockoutDuration -lt $script:policy.LockoutObservationWindow){throw 'Invalid restored pair'}
}
$gpo='11111111-1111-1111-1111-111111111111'
$a=@{id=('a'*32);domain='example.test';domainController='dc.example.test';selection=@{gpoId=$gpo;scopeDn=$domainDn;setting='1.2.4'}}
$b=@{id=('b'*32);domain='example.test';domainController='dc.example.test';selection=@{gpoId=$gpo;scopeDn=$domainDn;setting='1.2.1'}}
try{
 foreach($pair in @(@{plan=$a;property='LockoutObservationWindow'},@{plan=$b;property='LockoutDuration'})){
  $folder=Run-Directory $pair.plan;$null=New-Item -ItemType Directory -Path $folder
  @{phase='PUBLISHED';mappingId=$pair.plan.selection.setting;beforeDomainPolicy=@{property=$pair.property;value='30'};afterDomainPolicy=@{property=$pair.property;value='15'}}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $folder 'manifest.json') -Encoding UTF8
 }
 $anchor=@{batchPlans=@($a,$b)};$entries=@(Domain-BatchSnapshots $anchor $a)
 Check ($entries.Count -eq 2 -and $script:writes -eq 0) 'batch recovery reads both authoritative AD before snapshots without writing'
 $manifest=@{beforeBatchDomainPolicies=$entries}
 Check ((Domain-RollbackMatches $manifest) -and !(Domain-RollbackMatches $manifest $true)) 'pre-restore drift guard checks every changed AD property'
 Domain-BatchRestore $entries
 Check ($script:writes -eq 1 -and $script:policy.LockoutDuration.TotalMinutes -eq 30 -and $script:policy.LockoutObservationWindow.TotalMinutes -eq 30) 'related account values restore together in one AD command'
 Check ($script:policy.LockoutThreshold -eq 5 -and !$script:lastOptions.ContainsKey('LockoutThreshold') -and !$script:lastOptions.ContainsKey('MinPasswordLength')) 'batch restore never guesses or writes unselected account settings'
 Check ((Domain-RollbackMatches $manifest $true) -and !(Domain-RollbackMatches $manifest)) 'restored snapshot checks all saved AD values independently of the GPO'
 $script:policy.LockoutDuration=[timespan]::FromMinutes(15);$script:policy.LockoutObservationWindow=[timespan]::FromMinutes(20);$before=$script:writes
 Reject {Domain-BatchSnapshots $anchor $a} 'ROLLBACK_CONFLICT';Check ($script:writes -eq $before) 'external AD drift blocks recovery before any write'
 Reject {Domain-BatchOptions @(@{property='Unapproved';value='0'})} 'ROLLBACK_CONFLICT'
 Reject {Domain-BatchOptions @(@{property='LockoutDuration';value='15'},@{property='LockoutObservationWindow';value='30'})} 'DOMAIN_LOCKOUT_DEPENDENCY'
 Check ($script:writes -eq $before) 'unknown properties and invalid saved pairs do not perform a partial restore'
 $script:policy.LockoutDuration=[timespan]::FromMinutes(30);$script:policy.LockoutObservationWindow=[timespan]::FromMinutes(30)
 function Compare-RestoreContent {param($Plan,$Manifest) @{matches=$true;expected='same';actual='same';message='Private snapshot fixture'}}
 function Gpo-Ad {param($Id) @{gPCMachineExtensionNames='machine';gPCUserExtensionNames='user'}}
 function Scope-Links {param($Dn) 'links'}
 function Selected-Link {param($Dn,$Id) @{enabled=$true;order=1;enforced=$false}}
 function Verification-Metadata {param($S) @{replicationConverged=$true}}
 function Mapping-Display {param($Id,$Map,$S,$Desired) $null}
 $a.preview=@{scopeLinks='links'};$manifest.beforeContent='same';$manifest.beforeExtensions='machine';$manifest.beforeUserExtensions='user';$manifest.beforeDomainPolicy=@{property='LockoutObservationWindow';value='30'}
 $check=Verify-Rollback $a @{} $manifest
 Check ($check.restored -and @($check.restoreChecks|Where-Object area -eq DOMAIN_POLICY).Count -eq 2) 'snapshot read-back includes an independent row for every AD restoration target'
 $script:policy.LockoutDuration=[timespan]::FromMinutes(15);$check=Verify-Rollback $a @{} $manifest
 Check (!$check.restored -and @($check.restoreChecks|Where-Object{$_.area -eq 'DOMAIN_POLICY' -and $_.state -eq 'MISMATCH'}).Count -eq 1) 'a mismatch in a later AD property cannot be hidden by the first restored property'
 # Execute the actual guarded rollback switch, including anchor selection,
 # manifest persistence, full snapshot restore and repeated recovery.
 $script:policy.LockoutDuration=[timespan]::FromMinutes(15);$script:policy.LockoutObservationWindow=[timespan]::FromMinutes(15)
 $cfg.domain='example.test';$cfg.emitProgress=$false;$script:fingerprint='final';$script:imports=0
 function Fingerprint {param($Id,$ScopeDn) $script:fingerprint}
 function Assert-SelectionAccess {param($S,$Map) @{checks=@()}}
 function Save-Manifest {param($Manifest,$Directory) $Manifest|ConvertTo-Json -Depth 30|Set-Content -LiteralPath (Join-Path $Directory 'manifest.json') -Encoding UTF8}
 function Import-GPO {param($BackupId,$TargetGuid,$Path,$Domain,$Server) $script:imports++;$script:fingerprint='restored'}
 function Set-GPLink {param($Guid,$Target,$Domain,$Server,$Order,$LinkEnabled,$Enforced)}
 $a.preview.existingLink=@{order=1;enabled=$true;enforced=$false};$a.preview.gpo=@{id=$gpo;name='Fixture policy'}
 $backup='22222222-2222-2222-2222-222222222222'
 foreach($pair in @(@{plan=$a;property='LockoutObservationWindow';post='first'},@{plan=$b;property='LockoutDuration';post='final'})){
  $null=New-Item -ItemType Directory -Path (Join-Path (Run-Directory $pair.plan) ('{'+$backup+'}\DomainSysvol\GPO')) -Force
  Save-Manifest @{plan=$pair.plan;mappingId=$pair.plan.selection.setting;phase='PUBLISHED';backupId=$backup;directory=(Run-Directory $pair.plan);postFingerprint=$pair.post;beforeContent='same';beforeExtensions='machine';beforeUserExtensions='user';beforeDomainPolicy=@{property=$pair.property;value='30'};afterDomainPolicy=@{property=$pair.property;value='15'}} (Run-Directory $pair.plan)
 }
 $switch=$ast.FindAll({param($n)$n -is [Management.Automation.Language.SwitchStatementAst]},$false)|Select-Object -Last 1
 $block=$switch.Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoRollback'"}|ForEach-Object{$_.Item2};$dispatch=[scriptblock]::Create($block.Extent.Text.TrimStart('{').TrimEnd('}'))
 $Data=@{plan=$a;mapping=@{id='1.2.4';scope='Domain';domainPolicySensitive=$true};rollbackAnchor=@{plan=$b;postFingerprint='final';batchPlans=@($a,$b)}}
 $before=$script:writes;$result=& $dispatch
 Check ($result.state -eq 'ROLLED_BACK' -and $script:imports -eq 1 -and $script:writes -eq $before+1) 'real rollback dispatcher uses final batch anchor, first GPO snapshot and one combined AD restoration'
 $saved=Get-Content -LiteralPath (Join-Path (Run-Directory $a) 'manifest.json') -Raw|ConvertFrom-Json
 Check ($saved.beforeBatchDomainPolicies.Count -eq 2 -and (Domain-RollbackMatches $saved $true)) 'batch AD baselines persist for independent re-verification after reconnect'
 $result=& $dispatch
 Check ($result.state -eq 'ROLLED_BACK' -and $script:imports -eq 2) 'explicit repeated batch recovery retains its verified snapshot baseline'
 $script:policy.LockoutDuration=[timespan]::FromMinutes(40);$before=$script:imports
 Reject {& $dispatch} 'ROLLBACK_CONFLICT';Check ($script:imports -eq $before) 'external AD change after restore blocks a repeated full-GPO import'
}finally{
 $full=[IO.Path]::GetFullPath($temp);$base=[IO.Path]::GetFullPath((Join-Path $repo 'work')).TrimEnd('\')+'\';if(!$full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe test cleanup'};Remove-Item -LiteralPath $full -Recurse -Force
}
