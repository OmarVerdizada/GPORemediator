# Real refresh dispatcher/helper with mocked remoting; never runs gpupdate or AD.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
$switch=$ast.FindAll({param($n)$n -is [Management.Automation.Language.SwitchStatementAst]},$false)|Select-Object -Last 1
$block=$switch.Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoRefresh'"}|ForEach-Object{$_.Item2}
$dispatch=[scriptblock]::Create($block.Extent.Text.TrimStart('{').TrimEnd('}'))
$temp=Join-Path ([IO.Path]::GetTempPath()) ('gpr-refresh-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $temp
$cfg=@{emitProgress=$false};$script:targets=@(1..201|ForEach-Object{'ws'+$_+'.example.test'});$script:missing=$null;$script:remoteCalls=0
function Check($ok,$name){if(!$ok){throw $name};Write-Output ('PASS '+$name)}
function Run-Directory($Plan){$temp}
function Refresh-Targets {param($Strategy,$ScopeDn,$EndpointScopeDn,$PolicyScope) $script:targets|Where-Object{$_ -ne $script:missing}}
function Verify-Published {param($Plan,$Map,$CheckEndpoints) @{published=$true;linked=$true;effective='ENDPOINT_VERIFICATION_PENDING'}}
function Endpoint-CredentialOptions {@{Credential='fixture-credential-not-a-secret'}}
function Invoke-Command {
 param($ComputerName,$Authentication,$Credential,$ThrottleLimit,$ScriptBlock,$ErrorAction)
 Check ($Credential -eq 'fixture-credential-not-a-secret' -and $Authentication -eq 'Kerberos') 'computer refresh uses explicit delegated credential across the second hop'|Out-Null
 Check ($ThrottleLimit -eq 16 -and @($ComputerName).Count -le 64) 'bounded refresh concurrency and batch size'|Out-Null
 $script:remoteCalls++
 foreach($name in $ComputerName){[pscustomobject]@{PSComputerName=$name;state='COMPLETED';message='fixture process completed'}}
}
try{
 $plan=@{preview=@{verificationComputers=$script:targets};selection=@{scopeDn='OU=Pilot,DC=example,DC=test';refresh='Scope'}}
 $all=@()
 for($offset=0;$offset -lt 201;$offset+=64){
  $Data=@{plan=$plan;mapping=@{scope='Computer'};previous=@{state='NO_CHANGE'};refresh='Scope';refreshOffset=$offset}
  $result=& $dispatch
  Check ($result.state -eq 'REFRESH_COMPLETED') 'process completion is separate from task scheduling'
  Check ($result.refreshCoverage.checked -eq [math]::Min($offset+64,201)) 'refresh coverage advances across bounded pages'
  $all+=@($result.refreshResults)
 }
 Check ($all.Count -eq 201 -and @($all.computer|Sort-Object -Unique).Count -eq 201 -and $script:remoteCalls -eq 4) 'all 201 pinned targets refreshed once in four bounded requests'
 $script:missing=$script:targets[0];$Data.refreshOffset=0;$result=& $dispatch
 Check ($result.state -eq 'REFRESH_PARTIAL' -and @($result.refreshResults|Where-Object state -eq 'FAILED').Count -eq 1) 'a removed endpoint is retained as a failure rather than silently shrinking coverage'
 $Data.refreshOffset=-1
 try{$null=& $dispatch;throw 'negative refresh offset accepted'}catch{if($_.Exception.Message -notlike 'INVALID_REQUEST*'){throw}}
 $script:missing=$null
 $Data.refresh='Pdc';$callsBefore=$script:remoteCalls
 try{$null=& $dispatch;throw 'OU plan accepted PDC refresh'}catch{if($_.Exception.Message -notlike 'PDC_REFRESH_SCOPE_INVALID*'){throw}}
 Check ($script:remoteCalls -eq $callsBefore) 'invalid PDC refresh is rejected before any endpoint command'
 $Data.refresh='Scope'
 function Verify-Rollback {param($Plan,$Map,$Manifest) @{restored=$true;published=$false;linked=$false;effective='ROLLBACK_ENDPOINT_PENDING'}}
 @{phase='ROLLED_BACK'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $temp 'manifest.json') -Encoding UTF8
 $rollbackTargets=@();for($offset=0;$offset -lt 201;$offset+=64){$Data.refreshOffset=$offset;$result=& $dispatch;Check ($result.state -eq 'ROLLED_BACK') 'rollback refresh preserves restored GPO status';$rollbackTargets+=@($result.refreshResults)}
 Check ($rollbackTargets.Count -eq 201 -and @($rollbackTargets|Where-Object state -ne 'COMPLETED').Count -eq 0) 'rollback completes computer processing across all pinned pages'


 # User refresh must schedule logged-on user processing, never run computer
 # policy under the remoting operator and never claim scheduling is completion.
 @{phase='PUBLISHED'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $temp 'manifest.json') -Encoding UTF8
 $script:targets=@('userhost1.example.test','userhost2.example.test');$script:userSchedules=@();$script:userScheduleDenied=$false
 function Invoke-GPUpdate {param($Computer,$Force,$RandomDelayInMinutes,$ErrorAction,$Target)
  $script:userSchedules+=@{computer=$Computer;target=$Target;force=$Force}
  if($script:userScheduleDenied){throw [UnauthorizedAccessException]::new('Fixture RPC scheduling denied')}
 }
 $plan.selection.accountScope='Users';$plan.selection.endpointScopeDn='OU=Endpoints,DC=example,DC=test';$plan.preview.verificationComputers=$script:targets
 $Data=@{plan=$plan;mapping=@{scope='User'};previous=@{state='PUBLISHED'};refresh='Scope'}
 $callsBefore=$script:remoteCalls;$result=& $dispatch
 Check ($result.state -eq 'REFRESH_SCHEDULED' -and $result.refreshResults.Count -eq 2 -and @($script:userSchedules|Where-Object{$_.target -ne 'User' -or !$_.force}).Count -eq 0) 'user refresh schedules Target User on each pinned session endpoint'
 Check ($script:remoteCalls -eq $callsBefore -and @($result.refreshResults|Where-Object state -eq 'COMPLETED').Count -eq 0) 'user task scheduling never becomes computer refresh or completed user processing'
 $script:missing=$script:targets[0];$script:userSchedules=@();$result=& $dispatch
 Check ($script:userSchedules.Count -eq 1 -and $script:userSchedules[0].computer -eq $script:targets[1] -and $result.state -eq 'REFRESH_PARTIAL') 'removed user session endpoints are not scheduled and remain visible as failures'
 $script:missing=$null
 $script:userScheduleDenied=$true;$result=& $dispatch
 Check ($result.state -eq 'REFRESH_PARTIAL' -and @($result.refreshResults|Where-Object state -eq 'FAILED').Count -eq 2) 'user RPC scheduling failures remain per-host failures'

}finally{
 $resolved=[IO.Path]::GetFullPath($temp)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-refresh-*'){throw 'Unsafe fixture path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
