# Executes the real endpoint probe locally with native commands mocked; never contacts AD.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend\PowerShell\GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Assert-Test($Condition,$Message){if(!$Condition){throw $Message}}
$script:auditOverride=1
function Get-ItemPropertyValue {param($LiteralPath,$Name,$ErrorAction) if($Name -eq 'SCENoApplyLegacyAuditPolicy'){return $script:auditOverride};throw 'Unexpected fixture registry read'}
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) [pscustomobject]@{DNSHostName='ws.example.local'}}
$cfg=@{domain='example.test';domainController='dc.example.local';allowedHosts=@('ws.example.local','dc.example.local')}
$plan=@{selection=@{scopeDn='OU=Endpoints,DC=example,DC=local'};preview=@{refreshComputers=@('dc.example.local');impact=@{affectedObjects=@{sampleHosts=@('ws.example.local','outside.example.local')}}}}
$map=@{handler='SecurityTemplate';scope='Computer';domainPolicySensitive=$false;requiresInput=$false;allowValueOverride=$false;comparator=$null;items=@(@{name= $null;guid= $null;section='Privilege Rights';key='SeSystemtimePrivilege';type='Principals';value=@('S-1-5-19','S-1-5-32-544')})}
$script:hosts=@();$script:nativeExit=0;$script:lsaOverride=$null;$script:ini="[Privilege Rights]`nSeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19"
. (Join-Path $root 'scripts/fixtures/Mock-LsaUserRights.ps1')
[GpoRemediator.ReadOnly.UserRightsV1]::Probe=[Func[string,string[]]]{
 param($name)
 if($script:nativeExit){throw [ComponentModel.Win32Exception]::new(5)}
 if($null -ne $script:lsaOverride){return ,([string[]]$script:lsaOverride)}
 $match=[regex]::Match($script:ini,'(?m)^'+[regex]::Escape($name)+'\s*=\s*(.*)$')
 if(!$match.Success){return ,([string[]]@())}
 return ,([string[]]@(($match.Groups[1].Value -split ',')|ForEach-Object{$_.Trim().TrimStart('*')}|Where-Object{$_}))
}
function Invoke-Command {param($ComputerName,$Authentication,$ArgumentList,$ScriptBlock) $script:hosts+=@($ComputerName);& $ScriptBlock @ArgumentList}
function secedit.exe {
    Assert-Test ($args -contains '/mergedpolicy') 'Effective probe omitted domain policy'
    $path=$args[[array]::IndexOf($args,'/cfg')+1]
    [IO.File]::WriteAllText($path,$script:ini)
    $global:LASTEXITCODE=$script:nativeExit
}
$checks=@(Verify-EffectiveSamples $plan $map)
Assert-Test ($checks.Count -eq 1 -and $checks[0].state -eq 'VERIFIED') 'SID ordering/asterisks produced false mismatch'
Assert-Test (($script:hosts -join ',') -eq 'ws.example.local') 'PDC outside scope or unauthorized host was probed'
$script:lsaOverride=@('S-1-5-32-544')
$lsacheck=@(Verify-EffectiveSamples $plan $map)[0]
Assert-Test ($lsacheck.state -eq 'MISMATCH' -and $lsacheck.message -match 'local LSA') 'Matching security export cannot conceal a different live LSA assignment'
$script:lsaOverride=$null
$script:ini="[Privilege Rights]`nSeSystemtimePrivilege = *S-1-5-32-544"
$checks=@(Verify-EffectiveSamples $plan $map)
Assert-Test ($checks[0].state -eq 'MISMATCH' -and $checks[0].actualValue -match 'S-1-5-32-544') 'Real mismatch lost its actual evidence'
$script:nativeExit=5
$deniedLsa=(@(Verify-EffectiveSamples $plan $map))[0]
Assert-Test ($deniedLsa.state -eq 'UNAVAILABLE' -and $null -eq $deniedLsa.actualValue -and $deniedLsa.message -match 'native error 5' -and $deniedLsa.message -match 'Stage READ') 'Native LSA denial lost its error code or became a measured value'
$script:nativeExit=0;$script:ini='[Privilege Rights]';$map.items[0].value=@()
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'VERIFIED') 'LSA no assigned accounts must match an explicitly empty assignment'
$map.items[0].value=@('S-1-5-32-546');$map.comparator='includes';$script:ini="[Privilege Rights]`nSeSystemtimePrivilege = *S-1-5-32-546,*S-1-5-113"
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'VERIFIED') 'Additional deny principals were treated as noncompliant'
$map.handler='AdvancedAudit';$map.items=@(@{name= $null;section= $null;key= $null;type= $null;guid='{0CCE9235-69AE-11D9-BED3-505054503030}';mask=1});$script:auditMask=3
function auditpol.exe {
 Assert-Test ($args.Count -eq 2 -and $args[0] -eq '/backup' -and $args[1] -like '/file:*') 'auditpol must export numeric backup format, not parse localized /get report'
 $file=([string]$args[1]).Substring('/file:'.Length);$script:lastAuditFile=$file
 [IO.File]::WriteAllLines($file,[string[]]@('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value',('WS,System,Lokalisiert,{0CCE9235-69AE-11D9-BED3-505054503030},Erfolg und Fehler,,'+$script:auditMask)))
 $global:LASTEXITCODE=$script:nativeExit
}
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'VERIFIED') 'Audit superset did not satisfy include Success'
$script:auditOverride=0
$overrideResult=@(Verify-EffectiveSamples $plan $map)[0]
Assert-Test ($overrideResult.state -eq 'PENDING' -and $overrideResult.message -match '2.3.2.1') 'Missing subcategory override was silently accepted as verified audit policy'
$script:auditOverride=1
$script:auditMask=2
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'MISMATCH') 'Missing required audit bit passed'
$script:auditMask=4
$auditResult=@(Verify-EffectiveSamples $plan $map)[0]
Assert-Test ($auditResult.state -eq 'MISMATCH' -and $auditResult.actualValue -match 'No Auditing') 'Explicit No Auditing must report an observed mismatch, not pending'
Assert-Test (!(Test-Path -LiteralPath $script:lastAuditFile)) 'Audit export temporary file was not cleaned up'
$script:auditMask=0
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'PENDING') 'Unchanged audit setting was accepted as explicit evidence'
$script:nativeExit=5
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'PENDING') 'Failed auditpol produced compliance evidence'
Assert-Test (!(Numeric-Complies 0 5 '<=')) 'Disabled lockout passed the maximum threshold'
Assert-Test (Numeric-Complies 3 5 '<=') 'Valid lockout threshold rejected'
Assert-Test (Included-Value 3 1 'AdvancedAudit') 'Audit inclusion failed'
Assert-Test (!(Included-Value 7 1 'AdvancedAudit')) 'Invalid audit mask accepted'
$script:nativeExit=0
function auditpol.exe {$global:LASTEXITCODE=0;$file=([string]$args[1]).Substring('/file:'.Length);[IO.File]::WriteAllLines($file,[string[]]@('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value','WS,System,Other,{11111111-1111-1111-1111-111111111111},Success,,1'))}
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'PENDING') 'Unrelated audit GUID was accepted as target evidence'
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) @()}
$script:hosts=@()
$outside=@(Verify-EffectiveSamples $plan $map)
Assert-Test ($outside.Count -eq 1 -and $outside[0].state -eq 'OUTSIDE_SCOPE' -and $outside[0].hostname -eq 'ws.example.local' -and !$script:hosts.Count) 'A removed endpoint must retain its identity without being probed'
# A native command scheduled by refresh must not trigger an immediate endpoint sample.
$refresh=($ast.FindAll({param($n)$n -is [Management.Automation.Language.SwitchStatementAst] -and $n.Condition.Extent.Text -eq '$Operation'},$true)|Select-Object -Last 1).Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoRefresh'"}|ForEach-Object{$_.Item2}
Assert-Test ($refresh.Extent.Text -notmatch 'Verify-Published \$plan \$map \$true') 'Scheduled refresh immediately verified stale endpoint state'
Write-Output 'PASS endpoint evidence: merged policy, scope boundary, SID normalization, missing data, native failures, audit/deny inclusion and asynchronous refresh'
# Reproduce independently observed Domain logging state. One compliant field
# must never certify the rest of a profile or a different profile.
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) [pscustomobject]@{DNSHostName='ws.example.local'}}
$script:firewallUnavailable=$false
$script:firewallPolicyMode='Match';$script:firewallMapping=$null
function Get-ItemPropertyValue {
 param($LiteralPath,$Name,$ErrorAction)
 if($script:firewallPolicyMode -eq 'Missing'){Write-Error 'Fixture missing policy' -ErrorId PropertyNotFound -ErrorAction Stop}
 if($script:firewallPolicyMode -eq 'Denied'){throw [UnauthorizedAccessException]::new('Fixture denied')}
 $entry=@($script:firewallMapping.items|Where-Object{$_.name -eq $Name})[0]
 if($script:firewallPolicyMode -eq 'Different'){return 'different-path'}
 return $entry.value[0]
}
function Get-Item {
 param($LiteralPath,$ErrorAction)
 $result=[pscustomobject]@{};$result|Add-Member ScriptMethod GetValueKind {param($name) if($script:firewallPolicyMode -eq 'WrongType'){return 'ExpandString'};return (@($script:firewallMapping.items|Where-Object{$_.name -eq $name})[0].type)};return $result
}
$script:firewallProfiles=@{
 Domain=[pscustomobject]@{Name='Domain';Enabled='True';DefaultInboundAction='Block';NotifyOnListen='False';LogFileName='%SystemRoot%\System32\logfiles\firewall\domainfw.log';LogMaxSizeKilobytes=16384;LogBlocked='False';LogAllowed='False'}
 Private=[pscustomobject]@{Name='Private';LogFileName='%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'}
}
function Get-NetFirewallProfile {
 param($Name,$PolicyStore,$ErrorAction)
 Assert-Test ($PolicyStore -eq 'ActiveStore') 'Firewall probe read the wrong policy store'
 if($script:firewallUnavailable){throw 'Fixture transport failure'}
 return $script:firewallProfiles[$Name]
}
$catalog=Get-Content (Join-Path $root 'backend/data/gpo-production-mappings.json') -Raw|ConvertFrom-Json
function Test-FirewallControl([string]$Id,[string]$ExpectedState){
 $mapping=$catalog.mappings|Where-Object{$_.id -eq $Id}
 $script:firewallMapping=$mapping
 foreach($item in $mapping.items){foreach($field in @('section','key','name','type','value','guid','state','mask')){if(!$item.PSObject.Properties[$field]){$item|Add-Member NoteProperty $field $null}}}
 $result=@(Verify-EffectiveSamples $plan $mapping)[0]
 Assert-Test ($result.state -eq $ExpectedState) ($Id+': expected '+$ExpectedState+', got '+($result|ConvertTo-Json -Compress))
 return $result
}
$null=Test-FirewallControl '9.1.5' 'VERIFIED'
$blocked=Test-FirewallControl '9.1.6' 'MISMATCH'
$allowed=Test-FirewallControl '9.1.7' 'MISMATCH'
Assert-Test ($blocked.actualValue -match 'Domain.LogBlocked=False' -and $allowed.actualValue -match 'Domain.LogAllowed=False') 'Disabled logging lost its measured mismatch'
$null=Test-FirewallControl '9.2.4' 'MISMATCH'
$script:firewallProfiles.Domain.LogMaxSizeKilobytes=32768
$null=Test-FirewallControl '9.1.5' 'VERIFIED'
$script:firewallProfiles.Domain.LogMaxSizeKilobytes=4096
$null=Test-FirewallControl '9.1.5' 'MISMATCH'
$script:firewallProfiles.Domain.LogFileName='%SYSTEMROOT%\system32\LOGFILES\firewall\DOMAINFW.LOG'
$null=Test-FirewallControl '9.1.4' 'VERIFIED'
$script:firewallProfiles.Private.LogFileName='%SYSTEMROOT%\system32\logfiles\firewall\privatefw.log'
$null=Test-FirewallControl '9.2.4' 'VERIFIED'
$script:firewallPolicyMode='Missing';$missingPolicy=Test-FirewallControl '9.2.4' 'MISMATCH'
Assert-Test ($missingPolicy.actualValue -match 'Policy Private.LogFilePath=<not configured>' -and $missingPolicy.actualValue -match 'Private.LogFileName=') 'ActiveStore match concealed a missing endpoint policy registry value'
$script:firewallPolicyMode='Different';$null=Test-FirewallControl '9.2.4' 'MISMATCH'
$script:firewallPolicyMode='WrongType';$null=Test-FirewallControl '9.2.4' 'MISMATCH'
$script:firewallPolicyMode='Denied';$deniedPolicy=Test-FirewallControl '9.2.4' 'UNAVAILABLE'
Assert-Test ($null -eq $deniedPolicy.actualValue -and $deniedPolicy.message -match 'FIREWALL_POLICY_READ_UNAVAILABLE') 'Registry read denial was treated as policy mismatch or successful evidence'
$script:firewallPolicyMode='Match'
$script:firewallProfiles.Domain.LogBlocked='True'
$null=Test-FirewallControl '9.1.6' 'VERIFIED'
$script:firewallProfiles.Domain.LogAllowed='NotConfigured'
$null=Test-FirewallControl '9.1.7' 'PENDING'
$script:firewallUnavailable=$true
$null=Test-FirewallControl '9.1.5' 'PENDING'
Write-Output 'PASS firewall reported-state regression: size equality/bounds, disabled logging mismatch, independent profiles, path case, unavailable evidence'
function Scope {param($Dn) [pscustomobject]@{dn=$Dn;kind='OU'}}
$cfg.domain='example.local'
function Get-GPO {param($Guid,$Domain,$Server) [pscustomobject]@{GpoStatus='AllSettingsEnabled'}}
$map=@{id='19.5.1.1';automation='Automated';handler='Registry';scope='User';domainPolicySensitive=$false;requiresInput=$false;allowValueOverride=$false;comparator=$null;items=@(@{name='Enabled';key='HKCU\Software\Policies\Test';type='DWORD';value=@('1');section=$null;guid=$null})}
$plan.selection=@{gpoId='11111111-1111-1111-1111-111111111111';scopeDn='OU=Users,DC=example,DC=local';endpointScopeDn='OU=Endpoints,DC=example,DC=local';verificationUser='';refresh='Scope'}
Validate-Selection $plan.selection $map
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'PENDING') 'OU-wide Apply without a sample user must remain endpoint-pending'
Write-Output 'PASS OU-wide user-policy selection without a verification user; optional HKCU evidence stays pending'

