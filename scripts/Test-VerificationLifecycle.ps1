# Real source functions, isolated file fixtures and mocked directory calls only.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$temp=Join-Path $repo ('work/verification-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
Import-Module (Join-Path $repo 'backend/PowerShell/SecurityTemplate.psm1') -Force
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Assert-Test($Value,$Name){if(!$Value){throw $Name};Write-Output ('PASS '+$Name)}
$cfg=@{domainController='dc.example.test'};$domain=@{DNSRoot='example.test'};$domainDn='DC=example,DC=test'
$script:count=2;$script:remoteExtensions='fixture-extension';$script:unavailable=$false;$script:userExtensions='fixture-user-extension'
foreach($name in @('local','remote')){$null=New-Item -ItemType Directory -Path (Join-Path $temp $name);[IO.File]::WriteAllText((Join-Path $temp ($name+'/GPT.INI')),"[General]`r`nVersion=1`r`n");[IO.File]::WriteAllText((Join-Path $temp ($name+'/policy.txt')),'same')}
function Gpo-Folder {param($Id) Join-Path $temp 'local'}
function Gpo-Ad {param($Id) @{versionNumber=1;gPCMachineExtensionNames='fixture-extension';gPCUserExtensionNames='fixture-user-extension'}}
function Get-ADReplicationPartnerMetadata {param($Target,$Scope,$ErrorAction) @()}
function Get-ADDomainController {param($Filter,$Server) 1..$script:count|ForEach-Object{[pscustomobject]@{HostName=('dc'+$_+'.example.test')}}}
function Get-ADObject {param($Identity,$Server,$Properties,$ErrorAction) if($script:unavailable){throw 'fixture network unavailable'};@{versionNumber=1;gPCMachineExtensionNames=$script:remoteExtensions;gPCUserExtensionNames=$script:userExtensions}}
function Remote-GpoFolder {param($Server,$Id) Join-Path $temp 'remote'}
$selection=@{gpoId='11111111-1111-1111-1111-111111111111'}
try{
 $cfg.emitProgress=$true
 $stream=@(Verification-Metadata $selection 6>&1)
 $events=@($stream|Where-Object{$_ -is [Management.Automation.InformationRecord]})
 $payload=@($stream|Where-Object{$_ -isnot [Management.Automation.InformationRecord]})
 Assert-Test ($payload.Count -eq 1 -and $payload[0].replicationConverged) 'streamed checks do not contaminate the metadata return value'
 Assert-Test ($events.Count -eq 4 -and $events[0].MessageData.gpoCheck.state -eq 'CHECKING' -and $events[-1].MessageData.gpoCheck.state -eq 'VERIFIED') 'each controller emits checking and measured result before return'
 $serialized=@($events|ForEach-Object{'GPO_CHECK:'+($_.MessageData.gpoCheck|ConvertTo-Json -Depth 5 -Compress)})
 Assert-Test ($serialized.Count -eq 4 -and ($serialized[0].Substring(10)|ConvertFrom-Json).phase -eq 'REPLICATION') 'transport serializes product-owned information records as separate progress frames'
 $cfg.emitProgress=$false
 $pagePlan=@{preview=@{verificationComputers=@(1..201|ForEach-Object{'ws'+$_+'.example.test'})}}
 $seen=@();for($offset=0;$offset -lt 201;$offset+=25){$Data=@{verificationOffset=$offset};$page=@(Verification-Page $pagePlan @());Assert-Test ($page.Count -le 25) 'verification page remains bounded';$seen+=$page}
 Assert-Test ($seen.Count -eq 201 -and @($seen|Sort-Object -Unique).Count -eq 201) 'every pinned endpoint is checked exactly once across pages'
 $Data=@{verificationOffset=-1};try{$null=Verification-Page $pagePlan @();throw 'negative offset accepted'}catch{if($_.Exception.Message -notlike 'INVALID_REQUEST*'){throw}}
 $Data=@{}
 Assert-Test ((Verification-Metadata $selection).replicationConverged) 'equal versions and content converge'
 [IO.File]::WriteAllText((Join-Path $temp 'remote/policy.txt'),'different')
 Assert-Test (!(Verification-Metadata $selection).replicationConverged) 'equal versions with different SYSVOL content cannot converge'
 [IO.File]::WriteAllText((Join-Path $temp 'remote/policy.txt'),'same');$script:remoteExtensions='different'
 Assert-Test (!(Verification-Metadata $selection).replicationConverged) 'equal policy files with different CSE metadata cannot converge'
 $script:remoteExtensions='fixture-extension';$script:userExtensions='different'
 Assert-Test (!(Verification-Metadata $selection).replicationConverged) 'different user CSE metadata cannot converge'
 $script:userExtensions='fixture-user-extension'
 $script:remoteExtensions='fixture-extension';$script:unavailable=$true
 Assert-Test (!(Verification-Metadata $selection).replicationConverged) 'unreachable DC cannot prove convergence'
 $script:unavailable=$false;$script:count=51
 Assert-Test (!(Verification-Metadata $selection).replicationConverged) 'truncated DC population cannot prove full convergence'
 $script:count=50
 Assert-Test ((Verification-Metadata $selection).replicationConverged) 'exact supported DC bound is fully checked'
 # Parse launcher functions without starting a service or touching ProgramData.
 $launcher=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'GpoRemediator.ps1'),[ref]$tokens,[ref]$errors)
 foreach($fn in $launcher.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Get-StartupFailureCategory','Get-SafeStartupIssue')},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
 Assert-Test ((Get-StartupFailureCategory 'Runtime exit after readiness') -eq 'RUNTIME_EXIT_AFTER_READY') 'post-readiness exit has its own diagnosis'
 Assert-Test ((Get-SafeStartupIssue 'Runtime exit after readiness') -notmatch 'before readiness') 'post-readiness summary preserves observed chronology'
}finally{
 $resolved=[IO.Path]::GetFullPath($temp);$allowed=[IO.Path]::GetFullPath((Join-Path $repo 'work'))+[IO.Path]::DirectorySeparatorChar
 if(!$resolved.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture cleanup escaped work directory'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
