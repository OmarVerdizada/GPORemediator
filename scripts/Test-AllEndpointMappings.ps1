# Executes every automatic control's real verifier with Windows/AD APIs mocked.
# Synthetic policy equality/inequality is not a live enforcement certification.
param([string]$ReportPath='work/audit/endpoint-controls.json',[switch]$ExactPlans)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
$catalog=Get-Content (Join-Path $repo 'backend/data/gpo-production-mappings.json') -Raw|ConvertFrom-Json
if($ExactPlans){$exact=Get-Content (Join-Path $repo 'work/audit/exact-values.json') -Raw|ConvertFrom-Json;$catalog.mappings=@($exact|ForEach-Object{$_.mapping})}
$cfg=@{domain='example.test';domainController='dc.example.test';allowedHosts=@('ws.example.test')};$domainDn='DC=example,DC=test'
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) [pscustomobject]@{DNSHostName='ws.example.test'}}
function Verification-User {param($Identity) [pscustomobject]@{SID=@{Value='S-1-5-21-100-200-300-1001'};Enabled=$true;DistinguishedName='CN=Pilot,OU=Users,DC=example,DC=test'}}
function Refresh-Targets {param($Strategy,$ScopeDn,$EndpointScopeDn,$PolicyScope) @('ws.example.test')}
function Invoke-Command {param($ComputerName,$Authentication,$ArgumentList,$ScriptBlock) & $ScriptBlock @ArgumentList}
. (Join-Path $repo 'scripts/fixtures/Mock-LsaUserRights.ps1')
[GpoRemediator.ReadOnly.UserRightsV1]::Probe=[Func[string,string[]]]{
 param($name)
 if($script:wrong){return ,([string[]]@('S-1-5-21-999-888-777-1001'))}
 $item=@($script:expected|Where-Object{$_.key -eq $name})[0]
 return ,([string[]]@(([string]$item.expected -split ',')|Where-Object{$_}))
}
function Test-Path {param($LiteralPath) if($LiteralPath -like 'Registry::*'){return $true};Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath}
function Get-ItemPropertyValue {param($LiteralPath,$Name,$ErrorAction) if($Name -eq 'SCENoApplyLegacyAuditPolicy' -and $script:map.handler -eq 'AdvancedAudit'){return 1};$entry=@($script:expected|Where-Object{$_.name -ceq $Name})[0];$value=$entry.expected;if($script:wrong){return '__mismatch__'};if($entry.type -eq 'MultiString'){return ,([string[]]@($value -split '\|'))};return $value}
function Get-Item {param($LiteralPath,$ErrorAction) $result=[pscustomobject]@{};$result|Add-Member ScriptMethod GetValueKind {param($name) return (@($script:expected|Where-Object{$_.name -ceq $name})[0].type)};return $result}
function secedit.exe {
 $file=$args[[array]::IndexOf($args,'/cfg')+1];$text=''
 foreach($item in $script:expected){$value=$item.expected;if($script:wrong){$value=if($item.type -eq 'Principals'){'*S-1-5-21-999-888-777-1001'}else{'__mismatch__'}};$text+="[$($item.section)]`r`n$($item.key) = $value`r`n"}
 [IO.File]::WriteAllText($file,$text);$global:LASTEXITCODE=0
}
function Get-LocalUser {
 param($ErrorAction)
 foreach($rid in @(500,501)){
  $item=@($script:expected|Where-Object{([string]$_.key -in @('EnableGuestAccount','NewGuestName') -and $rid -eq 501) -or ([string]$_.key -in @('EnableAdminAccount','NewAdministratorName') -and $rid -eq 500)}|Select-Object -First 1)
  if(!$item.Count){continue}
  $name=if([string]$item[0].key -like 'New*'){if($script:wrong){'other-account-name'}else{[string]$item[0].expected}}else{'renamed-built-in'}
  $enabled=if([string]$item[0].key -like 'Enable*'){[string]$item[0].expected -eq '1'}else{$false}
  if($script:wrong){$enabled=!$enabled}
  [pscustomobject]@{Name=$name;SID=('S-1-5-21-100-200-300-'+$rid);Enabled=$enabled;PrincipalSource='Local'}
 }
}
function auditpol.exe {
 if($args.Count -ne 2 -or $args[0] -ne '/backup' -or $args[1] -notlike '/file:*'){throw 'Unexpected native audit export arguments'}
 $file=([string]$args[1]).Substring('/file:'.Length);$lines=@('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
 foreach($item in $script:expected){$mask=if($script:wrong){4}else{$item.expected};$lines+="WS,System,Test,$($item.guid),State,,$mask"}
 [IO.File]::WriteAllLines($file,[string[]]$lines);$global:LASTEXITCODE=0
}
function Get-NetFirewallProfile {
 param($Name,$PolicyStore,$ErrorAction)
 if($PolicyStore -ne 'ActiveStore'){throw 'Wrong firewall policy store'}
 $properties=@{EnableFirewall='Enabled';DefaultInboundAction='DefaultInboundAction';DisableNotifications='NotifyOnListen';LogFilePath='LogFileName';LogFileSize='LogMaxSizeKilobytes';LogDroppedPackets='LogBlocked';LogSuccessfulConnections='LogAllowed';AllowLocalPolicyMerge='AllowLocalFirewallRules';AllowLocalIPsecPolicyMerge='AllowLocalIPsecRules'}
 $item=$script:expected[0];$value=switch($item.name){'DefaultInboundAction' {if($item.expected -eq '1'){'Block'}else{'Allow'}} 'DisableNotifications' {if($item.expected -eq '1'){'False'}else{'True'}} {$_ -in @('EnableFirewall','LogDroppedPackets','LogSuccessfulConnections','AllowLocalPolicyMerge','AllowLocalIPsecPolicyMerge')} {if($item.expected -eq '1'){'True'}else{'False'}} default {$item.expected}}
 if($script:wrong){$value='__mismatch__'}
 [pscustomobject]@{($properties[$item.name])=$value}
}
function Verification-Metadata {param($S) @{versionsMatch=$true;replicationConverged=$true}}
function Get-GPO {param($Guid,$Domain,$Server,$ErrorAction) @{GpoStatus='AllSettingsEnabled'}}
function Mapping-Matches {param($Id,$Map,$S) $true}
function Mapping-Display {param($Id,$Map,$S,$Desired) 'fixture'}
function Get-ItemCurrent {param($Id,$Map,$Item) Desired-Normalized $Map $Item $script:selection}
function Selected-Link {param($Dn,$Id) @{enabled=$true;order=1}}
function Get-ADDefaultDomainPasswordPolicy {
 param($Identity,$Server)
 $value=if($script:wrong){if($script:map.comparator -eq '<='){999999}else{0}}else{Desired-Normalized $script:map @($script:map.items)[0] $script:selection}
 @{PasswordHistoryCount=$value;MinPasswordAge=[timespan]::FromDays($value);MinPasswordLength=$value;ComplexityEnabled=(!$script:wrong);ReversibleEncryptionEnabled=$script:wrong;LockoutDuration=[timespan]::FromMinutes($value);LockoutThreshold=$value;LockoutObservationWindow=[timespan]::FromMinutes($value)}
}
$rows=@()
foreach($map in $catalog.mappings){
 if($map.automation -ne 'Automated' -or $map.handler -eq 'Manual'){$rows+=@{id=$map.id;status='NOT_SUPPORTED';cases=0};continue}
 foreach($item in $map.items){foreach($field in @('section','key','name','type','value','guid','state','mask')){if(!$item.PSObject.Properties[$field]){$item|Add-Member NoteProperty $field $null}}}
 $script:selection=@{gpoId='11111111-1111-1111-1111-111111111111';scopeDn=$(if($map.scope -eq 'User'){'OU=Users,DC=example,DC=test'}else{'OU=Endpoints,DC=example,DC=test'});endpointScopeDn='OU=Endpoints,DC=example,DC=test';verificationUser='EXAMPLE\Pilot';firstLink=$false;value=$(if($map.allowValueOverride){$map.suggested}else{0});customValue=$(if($map.requiresInput){'Policy test value'}else{''})}
 $plan=@{selection=$script:selection;preview=@{refreshComputers=@('ws.example.test');impact=@{affectedObjects=@{sampleHosts=@('ws.example.test')}}}}
 $script:expected=@(Endpoint-Expected $map $script:selection)
 try{
  foreach($wrong in @($false,$true)){
   $script:wrong=$wrong
   if($map.domainPolicySensitive){$result=Verify-Published $plan $map $true;$passed=$result.effective -eq 'DOMAIN_VALUE_MATCHES_ON_SELECTED_DC'}
   else{$result=@(Verify-EffectiveSamples $plan $map);$passed=$result.Count -eq 1 -and $result[0].state -eq 'VERIFIED'}
   if($passed -eq $wrong){throw ("Expected mismatch=$wrong; result="+($result|ConvertTo-Json -Depth 10 -Compress))}
  }
  $cases=2
  if($ExactPlans -and !$map.domainPolicySensitive){
   foreach($item in $script:expected|Where-Object{$_.type -in @('DWORD','Integer') -and $_.comparator -eq '=='}){
    $script:wrong=$false;$original=$item.expected;$item.expected=[string]$(if($map.id -like '9.*' -and $item.name -ne 'LogFileSize'){if($original -eq '1'){0}else{1}}else{[uint64]$original+1})
    $different=@(Verify-EffectiveSamples $plan $map)
    if($different[0].state -ne 'MISMATCH'){throw ('Different numeric value accepted for an exact plan: '+($different|ConvertTo-Json -Compress))}
    $item.expected=$original;$cases++
   }
  }
  foreach($item in $script:expected){
   $rule=if($item.comparator){$item.comparator}else{$map.comparator}
   if($map.domainPolicySensitive -or $rule -notin @('>=','<=','atMost')){continue}
   $script:wrong=$false;$original=$item.expected
   $item.expected=[string]$(if($rule -eq '>='){[int64]$original+1}elseif($rule -eq 'atMost'){0}else{[math]::Max(1,[int64]$original-1)})
   $result=@(Verify-EffectiveSamples $plan $map)
   if($result[0].state -ne 'VERIFIED'){throw ('Compliant numeric bound rejected: '+($result|ConvertTo-Json -Compress))}
   $item.expected=$original;$cases++
  }
  $rows+=@{id=$map.id;status='PASS';cases=$cases}
 }catch{$rows+=@{id=$map.id;status='FAIL';cases=2;error=$_.Exception.Message}}
}
$path=Join-Path $repo $ReportPath;$null=New-Item -ItemType Directory -Path (Split-Path $path) -Force
$rows|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $path -Encoding UTF8
$failed=@($rows|Where-Object{$_.status -eq 'FAIL'});$passed=@($rows|Where-Object{$_.status -eq 'PASS'})
Write-Output ('All endpoint fixtures: '+$passed.Count+' PASS, '+$failed.Count+' FAIL, '+@($rows|Where-Object{$_.status -eq 'NOT_SUPPORTED'}).Count+' unsupported; '+($rows|ForEach-Object{$_.cases}|Measure-Object -Sum).Sum+' synthetic cases; no live AD validation.')
if($failed.Count){$failed|ConvertTo-Json -Depth 12;throw 'Endpoint control regression failures'}
