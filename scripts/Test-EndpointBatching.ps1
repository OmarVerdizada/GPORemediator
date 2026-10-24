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
}finally{
 $resolved=[IO.Path]::GetFullPath($temp)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-refresh-*'){throw 'Unsafe fixture path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
