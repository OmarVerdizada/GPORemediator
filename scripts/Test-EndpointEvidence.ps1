# Executes the real endpoint probe locally with native commands mocked; never contacts AD.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend\PowerShell\GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Assert-Test($Condition,$Message){if(!$Condition){throw $Message}}
$cfg=@{allowedHosts=@('ws.example.local','dc.example.local')}
$plan=@{selection=@{};preview=@{refreshComputers=@('dc.example.local');impact=@{affectedObjects=@{sampleHosts=@('ws.example.local','outside.example.local')}}}}
$map=@{handler='SecurityTemplate';scope='Computer';domainPolicySensitive=$false;requiresInput=$false;allowValueOverride=$false;comparator=$null;items=@(@{name= $null;guid= $null;section='Privilege Rights';key='SeSystemtimePrivilege';type='Principals';value=@('S-1-5-19','S-1-5-32-544')})}
$script:hosts=@();$script:nativeExit=0;$script:ini="[Privilege Rights]`nSeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19"
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
$script:ini="[Privilege Rights]`nSeSystemtimePrivilege = *S-1-5-32-544"
$checks=@(Verify-EffectiveSamples $plan $map)
Assert-Test ($checks[0].state -eq 'MISMATCH' -and $checks[0].actualValue -match 'S-1-5-32-544') 'Real mismatch lost its actual evidence'
$script:nativeExit=5
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'PENDING') 'Failed native export was treated as policy evidence'
$script:nativeExit=0;$script:ini='[Privilege Rights]';$map.items[0].value=@()
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'MISMATCH') 'Absent policy passed as an explicitly empty policy'
$map.items[0].value=@('S-1-5-32-546');$map.comparator='includes';$script:ini="[Privilege Rights]`nSeSystemtimePrivilege = *S-1-5-32-546,*S-1-5-113"
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'VERIFIED') 'Additional deny principals were treated as noncompliant'
$map.handler='AdvancedAudit';$map.items=@(@{name= $null;section= $null;key= $null;type= $null;guid='{0CCE9235-69AE-11D9-BED3-505054503030}';mask=1});$script:auditMask=3
function auditpol.exe {$global:LASTEXITCODE=$script:nativeExit;return @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value',('WS,System,Test,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,'+$script:auditMask))}
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'VERIFIED') 'Audit superset did not satisfy include Success'
$script:auditMask=2
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'MISMATCH') 'Missing required audit bit passed'
$script:nativeExit=5
Assert-Test ((@(Verify-EffectiveSamples $plan $map))[0].state -eq 'PENDING') 'Failed auditpol produced compliance evidence'
Assert-Test (!(Numeric-Complies 0 5 '<=')) 'Disabled lockout passed the maximum threshold'
Assert-Test (Numeric-Complies 3 5 '<=') 'Valid lockout threshold rejected'
Assert-Test (Included-Value 3 1 'AdvancedAudit') 'Audit inclusion failed'
Assert-Test (!(Included-Value 7 1 'AdvancedAudit')) 'Invalid audit mask accepted'
# A native command scheduled by refresh must not trigger an immediate endpoint sample.
$refresh=($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.SwitchStatementAst]}|Select-Object -Last 1).Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoRefresh'"}|ForEach-Object{$_.Item2}
Assert-Test ($refresh.Extent.Text -notmatch 'Verify-Published \$plan \$map \$true') 'Scheduled refresh immediately verified stale endpoint state'
Write-Output 'PASS endpoint evidence: merged policy, scope boundary, SID normalization, missing data, native failures, audit/deny inclusion and asynchronous refresh'
# End of endpoint-evidence regression assertions.

