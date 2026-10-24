# Actual FGPP functions with a private filesystem and in-memory AD cmdlet doubles.
# No domain, user account, or PSO is contacted or changed.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$temp=Join-Path ([IO.Path]::GetTempPath()) ('gpr-fgpp-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
. (Join-Path $repo 'backend/PowerShell/FineGrainedPassword.ps1')
$cfg=@{domain='example.test';domainController='dc.example.test';backupPath=$temp}
$script:pso=$null;$script:subjects=@();$script:override=$false;$script:failSubjects=$false;$script:mutations=0
$script:users=@(1..201|ForEach-Object{[pscustomobject]@{DistinguishedName=('CN=User'+$_+',OU=Users,DC=example,DC=test');ObjectGUID=[guid]::NewGuid();SamAccountName=('user'+$_)}})
function Check($ok,$name){if(!$ok){throw $name};Write-Output ('PASS '+$name)}
function Scope($Dn){@{kind='OU';dn=$Dn}}
function Test-BackupRepository($Path){@{ready=$true}}
function Get-ADUser {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) $script:users}
function Get-ADFineGrainedPasswordPolicy {param($Filter,$Server,$Properties,$ErrorAction) if($script:pso){$script:pso}}
function Get-ADFineGrainedPasswordPolicySubject {param($Identity,$Server,$ErrorAction) $script:subjects|ForEach-Object{[pscustomobject]@{DistinguishedName=$_}}}
function Set-ADFineGrainedPasswordPolicy {
 param($Identity,$Precedence,$PasswordHistoryCount,$MinPasswordLength,$MinPasswordAge,$MaxPasswordAge,$ComplexityEnabled,$ReversibleEncryptionEnabled,$LockoutThreshold,$LockoutDuration,$LockoutObservationWindow,$Server,$ErrorAction)
 $script:mutations++
 foreach($key in @('Precedence','PasswordHistoryCount','MinPasswordLength','MinPasswordAge','MaxPasswordAge','ComplexityEnabled','ReversibleEncryptionEnabled','LockoutThreshold','LockoutDuration','LockoutObservationWindow')){$script:pso.$key=Get-Variable $key -ValueOnly}
}
function New-ADFineGrainedPasswordPolicy {
 param($Name,$Description,$ProtectedFromAccidentalDeletion,$Precedence,$PasswordHistoryCount,$MinPasswordLength,$MinPasswordAge,$MaxPasswordAge,$ComplexityEnabled,$ReversibleEncryptionEnabled,$LockoutThreshold,$LockoutDuration,$LockoutObservationWindow,$Server,$ErrorAction)
 $script:pso=[pscustomobject]@{Name=$Name;Description=$Description;ProtectedFromAccidentalDeletion=$ProtectedFromAccidentalDeletion;DistinguishedName=('CN='+$Name+',CN=Password Settings Container,CN=System,DC=example,DC=test');ObjectGUID=[guid]::NewGuid();Precedence=$Precedence;PasswordHistoryCount=$PasswordHistoryCount;MinPasswordLength=$MinPasswordLength;MinPasswordAge=$MinPasswordAge;MaxPasswordAge=$MaxPasswordAge;ComplexityEnabled=$ComplexityEnabled;ReversibleEncryptionEnabled=$ReversibleEncryptionEnabled;LockoutThreshold=$LockoutThreshold;LockoutDuration=$LockoutDuration;LockoutObservationWindow=$LockoutObservationWindow}
 $script:mutations++
}
function Add-ADFineGrainedPasswordPolicySubject {param($Identity,$Subjects,$Server,$ErrorAction) if($script:failSubjects){throw 'fixture denied subject write'};$script:subjects+=@($Subjects);$script:mutations++}
function Remove-ADFineGrainedPasswordPolicySubject {param($Identity,$Subjects,$Server,$Confirm,$ErrorAction) $script:subjects=@($script:subjects|Where-Object{$_ -notin $Subjects});$script:mutations++}
function Remove-ADFineGrainedPasswordPolicy {param($Identity,$Server,$Confirm,$ErrorAction) $script:pso=$null;$script:subjects=@();$script:mutations++}
function Get-ADUserResultantPasswordPolicy {param($Identity,$Server,$ErrorAction) if(!$script:override){$script:pso}else{[pscustomobject]@{Name='Stronger-existing-policy'}}}
function Plan($request){$p=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController;request=$request;preview=(Fgpp-Preview $request)};return ($p|ConvertTo-Json -Depth 30|ConvertFrom-Json)}
try{
 $r=[pscustomobject]@{scopeDn='OU=Users,DC=example,DC=test';name='GPOR-Pilot';precedence=100;passwordHistoryCount=24;minPasswordLength=14;minPasswordAgeDays=1;maxPasswordAgeDays=90;complexityEnabled=$true;reversibleEncryptionEnabled=$false;lockoutThreshold=5;lockoutDurationMinutes=15;lockoutObservationWindowMinutes=15}
 $p=Plan $r
 Check ($p.preview.users.Count -eq 201 -and $script:mutations -eq 0) 'read-only preview pins all 201 users without changing AD'
 $v=Fgpp-Execute apply $p
 Check ($v.state -eq 'VERIFIED' -and $v.users.Count -eq 201 -and $script:subjects.Count -eq 201) 'apply creates PSO, assigns snapshot in chunks, verifies every resultant policy'
 $script:override=$true;$v=Fgpp-Execute verify $p
 Check ($v.state -eq 'POLICY_ASSIGNED_REVIEW_REQUIRED') 'stronger existing policy does not produce false verification'
 $script:override=$false
 $p2=Plan $r;$r2=$r|ConvertTo-Json|ConvertFrom-Json;$r2.minPasswordLength=16;$p2=Plan $r2
 $v=Fgpp-Execute apply $p2
 Check ($v.state -eq 'VERIFIED' -and $script:pso.MinPasswordLength -eq 16) 'managed policy can be re-previewed and updated'
 $v=Fgpp-Execute rollback $p2
 Check ($v.state -eq 'ROLLED_BACK' -and $script:pso.MinPasswordLength -eq 14 -and $script:subjects.Count -eq 201) 'rollback restores previous managed values and subjects'
 $v=Fgpp-Execute verify $p2
 Check ($v.state -eq 'ROLLED_BACK') 'post-rollback read-back proves restored state'
 $script:pso.MinPasswordLength=18
 try{$null=Fgpp-Execute rollback $p;throw 'external drift accepted'}catch{if($_.Exception.Message -notlike 'FGPP_CHANGED*'){throw}}
 Check ($script:pso.MinPasswordLength -eq 18) 'external edits block destructive rollback'
 $script:pso.MinPasswordLength=14;$v=Fgpp-Execute rollback $p
 Check ($v.state -eq 'ROLLED_BACK' -and !$script:pso) 'rollback removes only the PSO created by that operation'
 $p=Plan $r;$script:users=@($script:users|Select-Object -Skip 1);$n=$script:mutations
 try{$null=Fgpp-Execute apply $p;throw 'membership drift accepted'}catch{if($_.Exception.Message -notlike 'FGPP_CHANGED*'){throw}}
 Check ($n -eq $script:mutations) 'OU membership drift blocks Apply before any AD mutation'
 $p=Plan $r;$script:failSubjects=$true;$v=Fgpp-Execute apply $p
 Check ($v.state -eq 'REVIEW_REQUIRED') 'partial PSO failure retains recovery manifest and uncertain status'
 $v=Fgpp-Execute verify $p
 Check ($v.state -eq 'REVIEW_REQUIRED') 'interrupted mutation cannot be marked verified'
 $script:failSubjects=$false;$script:pso.Description='Unrelated administrator policy'
 try{$null=Fgpp-Preview $r;throw 'external PSO adopted'}catch{if($_.Exception.Message -notlike 'FGPP_NOT_MANAGED*'){throw}}
 Check ($script:pso.Description -eq 'Unrelated administrator policy') 'unmanaged existing PSOs cannot be adopted or overwritten'
 $outside=Join-Path $temp 'outside';$null=New-Item -ItemType Directory -Path $outside
 $linkedPlan=@{id=[guid]::NewGuid().ToString('N');domain=$cfg.domain;domainController=$cfg.domainController}
 $junction=Join-Path (Join-Path $temp 'PasswordPolicies') $linkedPlan.id
 $null=New-Item -ItemType Junction -Path $junction -Target $outside
 try{
  try{$null=Fgpp-Directory $linkedPlan;throw 'junction accepted'}catch{if($_.Exception.Message -notlike 'BACKUP_PATH_INVALID*'){throw}}
  Check (@(Get-ChildItem -LiteralPath $outside).Count -eq 0) 'linked recovery directory is rejected without writing outside the backup tree'
 }finally{Remove-Item -LiteralPath $junction -Force}
}finally{
 $resolved=[IO.Path]::GetFullPath($temp)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-fgpp-*'){throw 'Unsafe fixture path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
