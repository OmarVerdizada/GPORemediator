# Offline regression: executes the installed worker functions against isolated
# policy files and mocked directory/GroupPolicy commands. Never contacts AD.
param([string]$ReportPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$sandbox=Join-Path $root ('work\mapping-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $sandbox
Import-Module (Join-Path $root 'backend\PowerShell\SecurityTemplate.psm1') -Force
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend\PowerShell\GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors|Out-String)}
foreach($fn in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
$cfg=[pscustomobject]@{domain='example.local';domainController='dc.example.local';allowedHosts=@('dc.example.local','ws.example.local')}
$domain=[pscustomobject]@{PDCEmulator='dc.example.local'}
$script:folder=$sandbox;$script:registry=@{};$script:bumps=0
function Gpo-Folder {param($Id) return $script:folder}
function Assert-VersionSync {param($Id) return @{version=1}}
function Bump-ComputerVersion {param($Id,$Extension) $script:bumps++}
function Set-GPRegistryValue {param($Guid,$Key,$ValueName,$Type,$Value,$Domain,$Server) $script:registry[$Key+'|'+$ValueName]=@{value=$Value;type=$Type}}
function Get-GPRegistryValue {param($Guid,$Key,$ValueName,$Domain,$Server,$ErrorAction) $keyName=$Key+'|'+$ValueName;if(!$script:registry.ContainsKey($keyName)){Write-Error 'Missing mocked policy' -ErrorId UnableToRetrievePolicyRegistryItem -ErrorAction Stop};return [pscustomobject]@{Value=$script:registry[$keyName].value}}
function Assert-Test($Condition,[string]$Message){if(!$Condition){throw $Message}}
$catalog=Get-Content (Join-Path $root 'backend\data\gpo-production-mappings.json') -Raw|ConvertFrom-Json
$report=@();$index=0
foreach($map in $catalog.mappings){
    $index++;if($map.automation -ne 'Automated' -or $map.handler -eq 'Manual'){ $report+=@{id=$map.id;handler=$map.handler;state='MANUAL_BLOCKED'};continue }
    # Backend serialization includes nullable GpoMappingItem members; the compact
    # embedded JSON omits them. Reproduce the worker's actual wire shape.
    foreach($item in $map.items){foreach($field in @('section','key','name','type','value','guid','state','mask')){if(!$item.PSObject.Properties[$field]){$item|Add-Member -NotePropertyName $field -NotePropertyValue $null}}}
    $script:folder=Join-Path $sandbox ([string]$map.id);$null=New-Item -ItemType Directory -Path $script:folder
    $script:registry=@{};$script:bumps=0
    $selection=[pscustomobject]@{gpoId='31b2f340-016d-11d2-945f-00c04fb984f9';scopeDn='DC=example,DC=local';value=$(if($map.allowValueOverride){$map.suggested}else{0});customValue=$(if($map.requiresInput){if($map.inputDefault){$map.inputDefault}else{'Policy test value'}}else{''});refresh='None';firstLink=$false}
    $plan=[pscustomobject]@{selection=$selection}
    try{
        Assert-Test (!(Mapping-Matches $selection.gpoId $map $selection)) ($map.id+': clean fixture unexpectedly matched')
        Assert-Test (Write-Mapping $plan $map) ($map.id+': initial write did not run')
        Assert-Test (Mapping-Matches $selection.gpoId $map $selection) ($map.id+': read-back mismatch')
        Assert-Test (!(Write-Mapping $plan $map)) ($map.id+': second write was not idempotent')
        $display=Mapping-Display $selection.gpoId $map $selection $false
        Assert-Test ($null -ne $display) ($map.id+': missing display')
        $items=@(Endpoint-Expected $map $selection)
        Assert-Test ($items.Count -eq @($map.items).Count) ($map.id+': endpoint recipe lost items')
        if($map.handler -in @('SecurityTemplate','AdvancedAudit')){Assert-Test ($script:bumps -eq 1) ($map.id+': version increment count incorrect')}
        if($map.allowValueOverride){
            foreach($v in @($map.minimum,$map.maximum)|Sort-Object -Unique){$selection.value=[int]$v;$null=Write-Mapping $plan $map;Assert-Test (Mapping-Matches $selection.gpoId $map $selection) ($map.id+': override read-back mismatch')}
        }
        $report+=@{id=$map.id;handler=$map.handler;state='PASS';items=@($map.items).Count;checks='write/read-back/idempotence/endpoint-recipe/value-bounds'}
    }catch{$report+=@{id=$map.id;handler=$map.handler;state='FAIL';error=$_.Exception.Message}}
}
# Target selection executes the worker resolver with directory enumeration mocked.
function Scope {param($Dn) return @{dn=$Dn}}
$script:targetCount=2
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize) if($script:targetCount -gt 100){return 1..101|ForEach-Object{[pscustomobject]@{DNSHostName=('ws'+$_+'.example.local')}}};return @([pscustomobject]@{DNSHostName='ws.example.local'},[pscustomobject]@{DNSHostName='unauthorized.example.local'})}
Assert-Test (@(Refresh-Targets 'None' 'DC=example,DC=local').Count -eq 0) 'None unexpectedly scheduled targets'
Assert-Test ((@(Refresh-Targets 'Pdc' 'DC=example,DC=local') -join ',') -eq 'dc.example.local') 'PDC target mismatch'
Assert-Test ((@(Refresh-Targets 'Scope' 'DC=example,DC=local') -join ',') -eq 'ws.example.local') 'Scope allowlist failed'
$script:targetCount=101
try{$null=Refresh-Targets 'Scope' 'DC=example,DC=local';throw 'Scope limit was bypassed'}catch{if($_.Exception.Message -notlike 'REFRESH_SCOPE_TOO_LARGE*'){throw}}
$script:targetCount=2
Write-Output 'PASS refresh options: None / Pdc / Scope, host allowlist and 100-host bound'

# Execute the actual refresh branch after rollback, including both-policy refresh.
$switchAst=$ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.SwitchStatementAst]}|Select-Object -Last 1
$refreshBlock=$switchAst.Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoRefresh'"}|ForEach-Object{$_.Item2}
$script:folder=Join-Path $sandbox 'rollback';$null=New-Item -ItemType Directory -Path $script:folder
[IO.File]::WriteAllText((Join-Path $script:folder 'policy.txt'),'restored snapshot')
$content=Get-NormalizedGpoContentFingerprint $script:folder
$manifest=@{phase='ROLLED_BACK';beforeContent=$content;beforeExtensions='security';backupId='fixture';directory=$script:folder}
$plan=[pscustomobject]@{selection=[pscustomobject]@{gpoId='31b2f340-016d-11d2-945f-00c04fb984f9';scopeDn='DC=example,DC=local';refresh='None'};preview=[pscustomobject]@{scopeLinks='old links'}}
function Run-Directory {param($Plan) return $script:folder}
function Gpo-Ad {param($Id) return @{gPCMachineExtensionNames='security'}}
function Scope-Links {param($Dn) return 'old links'}
function Verification-Metadata {param($S) return @{versionsMatch=$true}}
function Mapping-Display {param($Id,$Map,$S,$Desired) return 'restored'}
$script:refreshCalls=@()
$script:failRefresh=$false
function Invoke-GPUpdate {param($Computer,$Target,[switch]$Force,$RandomDelayInMinutes,$ErrorAction) if($script:failRefresh){throw 'Mocked scheduling failure'};$script:refreshCalls+=@{computer=$Computer;target=$Target;force=[bool]$Force}}
# Keep manifest outside the content tree, as the actual manifest lives in backup storage.
$script:runDirectory=Join-Path $sandbox 'run';$null=New-Item -ItemType Directory -Path $script:runDirectory
function Run-Directory {param($Plan) return $script:runDirectory}
$manifest|ConvertTo-Json|Set-Content (Join-Path $script:runDirectory 'manifest.json')
$Data=[pscustomobject]@{plan=$plan;mapping=@{scope='Computer'};refresh='Pdc';previous=@{state='ROLLED_BACK'}}
$result=& ([scriptblock]::Create($refreshBlock.Extent.Text.TrimStart('{').TrimEnd('}')))
Assert-Test ($result.state -eq 'ROLLED_BACK' -and $result.refreshResults.Count -eq 1) 'Rollback refresh did not preserve restoration status'
Assert-Test ($script:refreshCalls.Count -eq 1 -and $script:refreshCalls[0].force) 'Rollback refresh failed to use force'
Assert-Test (!$script:refreshCalls[0].target) 'Full snapshot rollback must refresh both policy halves'
[IO.File]::WriteAllText((Join-Path $script:folder 'policy.txt'),'external edit')
try{$null=& ([scriptblock]::Create($refreshBlock.Extent.Text.TrimStart('{').TrimEnd('}')));throw 'Rollback drift was accepted'}catch{if($_.Exception.Message -notlike 'ROLLBACK_DRIFT_DETECTED*'){throw}}
Assert-Test ($script:refreshCalls.Count -eq 1) 'Rollback drift scheduled a refresh'
Write-Output 'PASS rollback refresh: restored snapshot, explicit force and drift rejection'
[IO.File]::WriteAllText((Join-Path $script:folder 'policy.txt'),'restored snapshot')
$Data.refresh='Scope'
$result=& ([scriptblock]::Create($refreshBlock.Extent.Text.TrimStart('{').TrimEnd('}')))
Assert-Test ($result.state -eq 'ROLLED_BACK' -and $result.refreshResults[0].computer -eq 'ws.example.local') 'Rollback scope refresh ignored the host boundary'
$script:failRefresh=$true
$result=& ([scriptblock]::Create($refreshBlock.Extent.Text.TrimStart('{').TrimEnd('}')))
Assert-Test ($result.state -eq 'ROLLED_BACK' -and $result.refreshResults[0].state -eq 'FAILED') 'Scheduling failure was hidden or erased rollback state'
Write-Output 'PASS rollback scope refresh and per-host scheduling failure reporting'
if($ReportPath){$parent=Split-Path ([IO.Path]::GetFullPath($ReportPath)) -Parent;$null=New-Item -ItemType Directory -Force -Path $parent;$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ReportPath -Encoding UTF8}
$failures=@($report|Where-Object{$_.state -eq 'FAIL'})
$report|ForEach-Object{[pscustomobject]$_}|Group-Object handler|ForEach-Object{Write-Output ($_.Name+': '+$_.Count+' controls')}
Write-Output ('Offline mapping results: '+@($report|Where-Object{$_.state -eq 'PASS'}).Count+' PASS, '+@($report|Where-Object{$_.state -eq 'MANUAL_BLOCKED'}).Count+' manual, '+$failures.Count+' FAIL')
if($failures.Count){$failures|ForEach-Object{Write-Output ($_.id+': '+$_.error)};exit 1}
