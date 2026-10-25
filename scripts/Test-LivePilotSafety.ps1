$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-LivePilot.ps1'),[ref]$tokens,[ref]$errors)
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Reject($Block,$Name){try{& $Block;throw ('Accepted: '+$Name)}catch{if($_.Exception.Message -like 'Accepted:*'){throw}};Write-Output ('PASS '+$Name)}
$gpo='11111111-1111-1111-1111-111111111111';$ou='OU=Pilot,DC=example,DC=test'
$map=@{scope='Computer';automation='Automated';domainPolicySensitive=$false;requiresRestart=$false;requiresInput=$false}
$plan=@{selection=@{gpoId=$gpo;scopeDn=$ou};writeAuthorized=$true;preview=@{gpo=@{protected=$false};noChange=$false;preflight=@{ready=$true};verificationComputers=@('pc.example.test');impact=@{existingLinkScopes=@($ou);affectedObjects=@{computers=1;truncated=$false}}}}
$null=Assert-PilotUrl 'http://127.0.0.1:5080';Assert-PilotPlan $plan $map $gpo $ou 5
foreach($url in @('http://remote.example/','https://user:password@localhost/','http://localhost/path','file:///C:/test','http://localhost/?redirect=remote')){Reject {Assert-PilotUrl $url} 'nonlocal/ambiguous credential destination rejected'}
$plan.preview.gpo.protected=$true;Reject {Assert-PilotPlan $plan $map $gpo $ou 5} 'protected GPO rejected';$plan.preview.gpo.protected=$false
$plan.preview.impact.existingLinkScopes+= 'DC=example,DC=test';Reject {Assert-PilotPlan $plan $map $gpo $ou 5} 'GPO linked beyond pilot rejected';$plan.preview.impact.existingLinkScopes=@($ou)
$plan.preview.impact.affectedObjects.computers=200;Reject {Assert-PilotPlan $plan $map $gpo $ou 5} 'oversized/incomplete target inventory rejected';$plan.preview.impact.affectedObjects.computers=1
$map.requiresRestart=$true;Reject {Assert-PilotPlan $plan $map $gpo $ou 5} 'restart control cannot falsely certify pilot';$map.requiresRestart=$false
$plan.preview.noChange=$true;Reject {Assert-PilotPlan $plan $map $gpo $ou 5} 'no-op cannot certify write/rollback lifecycle'
Write-Output 'PASS safety helpers only; live AD pilot NOT RUN.'
