# Exercises the real password-pilot dispatcher with in-memory AD cmdlet doubles.
# This test does not connect to AD, create users or change directory policies.
$ErrorActionPreference='Stop'
$script:source=Get-Content (Join-Path $PSScriptRoot '../backend/PowerShell/Invoke-PasswordPilot.ps1') -Raw
$script:source=$script:source.Replace('[Console]::In.ReadToEnd()','$script:testInput').Replace('[Console]::Out.Write(','Write-Output (').Replace('exit 1','return')
$script:baseline=[pscustomobject]@{
  PasswordHistoryCount=12;MaxPasswordAge=[TimeSpan]::FromDays(90);MinPasswordAge=[TimeSpan]::Zero
  MinPasswordLength=8;ComplexityEnabled=$false;ReversibleEncryptionEnabled=$false
  LockoutThreshold=5;LockoutDuration=[TimeSpan]::FromMinutes(30);LockoutObservationWindow=[TimeSpan]::FromMinutes(30)
}
$script:user=[pscustomobject]@{ObjectGUID=[guid]'11111111-2222-3333-4444-555555555555';SamAccountName='pilot.user';DistinguishedName='CN=Pilot,OU=Tests,DC=example,DC=com';adminCount=0;SID='S-1-5-21-111-222-333-1100'}
$script:policy=$null;$script:assigned=$false;$script:writes=0
function Get-Module { param($ListAvailable) return $true }
function Import-Module { param($Name) }
function Get-ADDomain { param($Identity,$Server) return [pscustomobject]@{DNSRoot='example.com';DistinguishedName='DC=example,DC=com';NetBIOSName='EXAMPLE';DomainMode=7} }
function Get-ADDomainController { param($Identity,$Server) return [pscustomobject]@{IsReadOnly=$false;Domain='example.com'} }
function Get-ADUser { param($Identity,$Server,$Properties,$Filter) return $script:user }
function Get-ADUserResultantPasswordPolicy { param($Identity,$Server) if($script:assigned){return $script:policy} }
function Get-ADDefaultDomainPasswordPolicy { param($Identity,$Server) return $script:baseline }
function Get-ADFineGrainedPasswordPolicy { param($Identity,$Filter,$Server,$Properties) if($script:policy){return $script:policy} }
function New-ADFineGrainedPasswordPolicy {
  param($Name,$Description,$Precedence,$ComplexityEnabled,$ReversibleEncryptionEnabled,$MinPasswordLength,$PasswordHistoryCount,$MinPasswordAge,$MaxPasswordAge,$LockoutThreshold,$LockoutDuration,$LockoutObservationWindow,$Server,$PassThru)
  if(!(Test-Path -LiteralPath (Join-Path $script:backupRoot ('PasswordPilot/' + $script:plan.id + '.json')))){throw 'Write happened before backup'}
  $script:writes++
  $script:policy=[pscustomobject]@{ObjectGUID=[guid]::NewGuid();Name=$Name;Description=$Description;Precedence=$Precedence;ComplexityEnabled=$ComplexityEnabled;ReversibleEncryptionEnabled=$ReversibleEncryptionEnabled;MinPasswordLength=$MinPasswordLength;PasswordHistoryCount=$PasswordHistoryCount;MinPasswordAge=$MinPasswordAge;MaxPasswordAge=$MaxPasswordAge;LockoutThreshold=$LockoutThreshold;LockoutDuration=$LockoutDuration;LockoutObservationWindow=$LockoutObservationWindow;AppliesTo=@()}
  return $script:policy
}
function Add-ADFineGrainedPasswordPolicySubject { param($Identity,$Subjects,$Server,$Confirm) $script:writes++;$script:assigned=$true;$script:policy.AppliesTo=@($script:user.DistinguishedName) }
function Remove-ADFineGrainedPasswordPolicySubject { param($Identity,$Subjects,$Server,$Confirm) $script:writes++;$script:assigned=$false;$script:policy.AppliesTo=@() }
function Remove-ADFineGrainedPasswordPolicy { param($Identity,$Server,$Confirm) $script:writes++;$script:policy=$null }
function Check($Condition,[string]$Message){if(!$Condition){throw $Message}}
function Invoke-Pilot([string]$Operation,$Payload){
  $script:testInput=@{operation=$Operation;configuration=@{domain='example.com';domainController='dc01.example.com';backupPath=$script:backupRoot};payload=$Payload}|ConvertTo-Json -Depth 30 -Compress
  $raw=& ([scriptblock]::Create($script:source))
  return ($raw | ConvertFrom-Json)
}
$script:backupRoot=Join-Path $PSScriptRoot ('../work/password-ps-test-' + [guid]::NewGuid().ToString('N'))
$read=Invoke-Pilot 'passwordRead' @{user='pilot.user'}
Check $read.ok ('Read failed: ' + ($read|ConvertTo-Json -Compress))
Check ($script:writes -eq 0) 'Read performed an AD write'
$script:plan=[pscustomobject]@{id=[guid]::NewGuid().ToString('N');domain='example.com';domainController='dc01.example.com';setting='MinPasswordLength';value=14;before=$read.data;after=($read.data.values|ConvertTo-Json|ConvertFrom-Json)}
$script:plan.after.MinPasswordLength=14
$apply=Invoke-Pilot 'passwordApply' @{plan=$script:plan}
Check ($apply.ok -and $apply.data.verified) ('Apply failed: ' + ($apply|ConvertTo-Json -Compress))
Check ($script:policy.MinPasswordLength -eq 14 -and $script:policy.LockoutDuration -eq $script:baseline.LockoutDuration -and $script:policy.PasswordHistoryCount -eq 12) 'Unselected policy values changed'
$replay=Invoke-Pilot 'passwordApply' @{plan=$script:plan}
Check (!$replay.ok -and $script:writes -eq 2) 'Repeated apply mutated directory again'
$script:policy.AppliesTo+= 'CN=Other,OU=Tests,DC=example,DC=com'
$conflict=Invoke-Pilot 'passwordRollback' @{plan=$script:plan}
Check (!$conflict.ok -and $conflict.code -eq 'ROLLBACK_SHARED_POLICY') 'Shared policy was removed'
$script:policy.AppliesTo=@($script:user.DistinguishedName)
$script:policy.MinPasswordLength=15
$changed=Invoke-Pilot 'passwordRollback' @{plan=$script:plan}
Check (!$changed.ok -and $changed.code -eq 'ROLLBACK_CONFLICT') 'Edited policy was removed'
$script:policy.MinPasswordLength=14
$rollback=Invoke-Pilot 'passwordRollback' @{plan=$script:plan}
Check ($rollback.ok -and $rollback.data.verified -and !$script:assigned -and !$script:policy) ('Rollback failed: ' + ($rollback|ConvertTo-Json -Compress))
$script:user.adminCount=1
$privileged=Invoke-Pilot 'passwordRead' @{user='pilot.user'}
Check (!$privileged.ok -and $privileged.code -eq 'PRIVILEGED_TEST_USER') 'Privileged test user was accepted'
$script:user.adminCount=0
$script:plan.after.LockoutThreshold=7
$tampered=Invoke-Pilot 'passwordApply' @{plan=$script:plan}
Check (!$tampered.ok -and $tampered.code -eq 'PLAN_VALUES_INVALID') 'Unselected value mutation was accepted'
$script:baseline.MinPasswordAge=[TimeSpan]::FromHours(12)
$precision=Invoke-Pilot 'passwordRead' @{user='pilot.user'}
Check (!$precision.ok -and $precision.code -eq 'POLICY_PRECISION_UNSUPPORTED') 'Existing ages were silently rounded'
$script:baseline.MinPasswordAge=[TimeSpan]::Zero
$script:baseline.LockoutDuration=[TimeSpan]::FromMilliseconds(1500)
$precision=Invoke-Pilot 'passwordRead' @{user='pilot.user'}
Check (!$precision.ok -and $precision.code -eq 'POLICY_PRECISION_UNSUPPORTED') 'Existing lockout interval was silently rounded'
Write-Host 'Password PowerShell tests passed: read-only planning, backup before write, exact assignment, unchanged values, replay, shared/edited PSO conflicts, rollback, privileged account, precision.'
