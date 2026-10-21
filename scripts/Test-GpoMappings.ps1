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
$script:folder=$sandbox;$script:registry=@{};$script:bumps=0;$script:auditExtensions=''
function Gpo-Ad {param($Id) @{gPCMachineExtensionNames=$script:auditExtensions}}
function Gpo-Folder {param($Id) return $script:folder}
function Assert-VersionSync {param($Id) return @{version=1}}
function Bump-ComputerVersion {param($Id,$Extension) $script:bumps++;if($Extension -eq 'Audit'){$script:auditExtensions=Add-AuditExtension $script:auditExtensions}}
function Set-GPRegistryValue {param($Guid,$Key,$ValueName,$Type,$Value,$Domain,$Server) $script:registry[$Key+'|'+$ValueName]=@{value=$Value;type=$Type}}
function Get-GPRegistryValue {param($Guid,$Key,$ValueName,$Domain,$Server,$ErrorAction) $keyName=$Key+'|'+$ValueName;if(!$script:registry.ContainsKey($keyName)){Write-Error 'Missing mocked policy' -ErrorId UnableToRetrievePolicyRegistryItem -ErrorAction Stop};return [pscustomobject]@{Value=$script:registry[$keyName].value;Type=$script:registry[$keyName].type}}
$script:caseCount=0
function Assert-Test($Condition,[string]$Message){if(!$Condition){throw $Message};$script:caseCount++}
$catalog=Get-Content (Join-Path $root 'backend\data\gpo-production-mappings.json') -Raw|ConvertFrom-Json
$report=@();$index=0
foreach($map in $catalog.mappings){
    $script:caseCount=0
    $index++;if($map.automation -ne 'Automated' -or $map.handler -eq 'Manual'){ $report+=@{id=$map.id;handler=$map.handler;state='MANUAL_BLOCKED'};continue }
    # Backend serialization includes nullable GpoMappingItem members; the compact
    # embedded JSON omits them. Reproduce the worker's actual wire shape.
    foreach($item in $map.items){foreach($field in @('section','key','name','type','value','guid','state','mask')){if(!$item.PSObject.Properties[$field]){$item|Add-Member -NotePropertyName $field -NotePropertyValue $null}}}
    $script:folder=Join-Path $sandbox ([string]$map.id);$null=New-Item -ItemType Directory -Path $script:folder
    $script:registry=@{};$script:bumps=0;$script:auditExtensions=''
    $selection=[pscustomobject]@{gpoId='22222222-2222-2222-2222-222222222222';scopeDn='DC=example,DC=local';value=$(if($map.allowValueOverride){$map.suggested}else{0});customValue=$(if($map.requiresInput){if($map.inputDefault){$map.inputDefault}else{'Policy test value'}}else{''});refresh='None';firstLink=[bool]$map.domainPolicySensitive}
    $plan=[pscustomobject]@{selection=$selection}
    try{
        Assert-Test (!(Mapping-Matches $selection.gpoId $map $selection)) ($map.id+': clean fixture unexpectedly matched')
        Assert-Test (Write-Mapping $plan $map) ($map.id+': initial write did not run')
        Assert-Test (Mapping-Matches $selection.gpoId $map $selection) ($map.id+': read-back mismatch')
        Assert-Test (!(Write-Mapping $plan $map)) ($map.id+': second write was not idempotent')
        $display=Mapping-Display $selection.gpoId $map $selection $false
        Assert-Test ($null -ne $display) ($map.id+': missing display')
        if($map.handler -in @('Registry','RegistrySet')){
            foreach($item in $map.items){
                $rule=[string](Read-Field $item 'comparator' $map.comparator);if(!$rule){$rule=[string]$map.comparator}
                if($rule -notin @('>=','<=','atMost')){continue}
                $original=$script:registry[$item.key+'|'+$item.name].value
                $stronger=if($rule -eq '>='){[int64]$original+1}elseif($rule -eq 'atMost'){0}else{[math]::Max(1,[int64]$original-1)}
                $script:registry[$item.key+'|'+$item.name].value=$stronger
                Assert-Test (Mapping-Matches $selection.gpoId $map $selection) ($map.id+': stricter numeric policy rejected')
                Assert-Test (!(Write-Mapping $plan $map)) ($map.id+': stricter numeric policy was weakened')
                $script:registry[$item.key+'|'+$item.name].value=$original
            }
        }
        $items=@(Endpoint-Expected $map $selection)
        Assert-Test ($items.Count -eq @($map.items).Count) ($map.id+': endpoint recipe lost items')
        if($map.handler -in @('SecurityTemplate','AdvancedAudit')){Assert-Test ($script:bumps -eq 1) ($map.id+': version increment count incorrect')}
        if($map.allowValueOverride){
            foreach($v in @($map.minimum,$map.maximum)|Sort-Object -Unique){$selection.value=[int]$v;$null=Write-Mapping $plan $map;Assert-Test (Mapping-Matches $selection.gpoId $map $selection) ($map.id+': override read-back mismatch')}
        }
        $report+=@{id=$map.id;handler=$map.handler;state='PASS';items=@($map.items).Count;testsPassed=$script:caseCount;testsFailed=0;checks='write/read-back/idempotence/endpoint-recipe/value-bounds'}
    }catch{$report+=@{id=$map.id;handler=$map.handler;state='FAIL';testsPassed=$script:caseCount;testsFailed=1;error=$_.Exception.Message}}
}
# Execute C#-resolved custom mappings through the real writer/read-back functions.
$customPath=Join-Path $root 'work/audit/custom-values.json'
if(Test-Path -LiteralPath $customPath){$customFixtures=Get-Content -LiteralPath $customPath -Raw|ConvertFrom-Json;foreach($fixture in $customFixtures){
 $map=$fixture.mapping;$selection=$fixture.selection;$plan=@{selection=$selection}
 $script:folder=Join-Path $sandbox ('c'+$map.id.Replace('.',''));$null=New-Item -ItemType Directory -Path $script:folder -Force
 $script:registry=@{};$script:auditExtensions='';$script:bumps=0
 Assert-Test (Write-Mapping $plan $map) ($map.id+': custom mapping did not write')
 Assert-Test (Mapping-Matches $selection.gpoId $map $selection) ($map.id+': custom read-back mismatch')
 Assert-Test (!(Write-Mapping $plan $map)) ($map.id+': custom mapping was not idempotent')
 $null=Endpoint-Expected $map $selection
};Write-Output 'PASS custom DWORD, HKCU, audit None, account policy, principal list and registry set write/read-back/idempotence'}
# Preserve stronger existing deny/audit entries when the benchmark says "include".
$script:folder=Join-Path $sandbox 'incl';$null=New-Item -ItemType Directory -Path $script:folder
$map=$catalog.mappings|Where-Object{$_.id -eq '2.2.23'}
$path=Security-Path $selection.gpoId;$null=New-Item -ItemType Directory -Path (Split-Path $path) -Force
[IO.File]::WriteAllText($path,"[Privilege Rights]`r`nSeDenyBatchLogonRight = *S-1-5-113`r`n",[Text.Encoding]::Unicode)
$plan=@{selection=$selection};$null=Write-Mapping $plan $map
$current=Get-ItemCurrent $selection.gpoId $map $map.items[0]
Assert-Test ($current -eq 'S-1-5-113,S-1-5-32-546') 'Adding Guests removed an existing deny principal'
Assert-Test (!(Write-Mapping $plan $map)) 'Deny superset was rewritten'
$map=$catalog.mappings|Where-Object{$_.id -eq '17.2.5'}
$path=Audit-Path $selection.gpoId;$null=New-Item -ItemType Directory -Path (Split-Path $path) -Force
[IO.File]::WriteAllText($path,('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'+"`r`n"+(Audit-Row $map.items[0].name $map.items[0].guid 'Failure' 2)+"`r`n"))
$null=Write-Mapping $plan $map
Assert-Test ((Get-ItemCurrent $selection.gpoId $map $map.items[0]) -eq '3') 'Adding Success removed existing Failure auditing'
Assert-Test (!(Write-Mapping $plan $map)) 'Audit superset was rewritten'
$header='Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
$legacyRow='"","System","Audit User Account Management","'+[string]$map.items[0].guid+'","Success and Failure","","3"'
$sibling='"","System","Other fixture","{11111111-1111-1111-1111-111111111111}","Failure","","2"'
[IO.File]::WriteAllText($path,($header+"`r`n"+$legacyRow+"`r`n"+$sibling+"`r`n"))
Assert-Test (!(Mapping-Matches $selection.gpoId $map $selection)) 'Generic quoted CSV was accepted as canonical GPAC storage'
Assert-Test (Write-Mapping $plan $map) 'Old quoted CSV was not repaired despite equal values'
$repaired=[IO.File]::ReadAllText($path)
Assert-Test ($repaired -match ',System,"[^"\r\n]+",\{[a-f0-9-]+\},Success and Failure,,3') 'GPAC literal fields remain quoted'
$siblingRow=@(Get-Content -LiteralPath $path -Encoding UTF8|ConvertFrom-Csv|Where-Object {$_.'Subcategory GUID' -eq '{11111111-1111-1111-1111-111111111111}'})
Assert-Test ($siblingRow.Count -eq 1 -and $siblingRow[0].'Setting Value' -eq '2') 'Formatting repair changed an unrelated audit mask'
Assert-Test (!(Write-Mapping $plan $map)) 'Canonical audit repair was not idempotent'
$script:auditExtensions=''
Assert-Test (!(Mapping-Matches $selection.gpoId $map $selection)) 'Correct CSV without audit CSE was incorrectly classified no-change'
Assert-Test (Write-Mapping $plan $map) 'Missing audit CSE was not repaired'
Assert-Test (Mapping-Matches $selection.gpoId $map $selection) 'Repaired audit CSE did not verify'
$noneMap=$map|ConvertTo-Json -Depth 15|ConvertFrom-Json;$noneMap.comparator=$null;$noneMap.items[0].mask=0
$null=Write-Mapping $plan $noneMap
$noneRows=@(Get-Content -LiteralPath $path -Encoding UTF8|ConvertFrom-Csv)
Assert-Test ($noneRows[0].'Setting Value' -eq '4') 'Explicit No Auditing must use MS-GPAC value 4, not unchanged value 0'
Assert-Test (Mapping-Matches $selection.gpoId $noneMap $selection) 'Explicit No Auditing did not normalize to internal mask zero'
[IO.File]::WriteAllText($path,('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'+"`r`n"+(Audit-Row $map.items[0].name $map.items[0].guid 'Not Specified' 0)+"`r`n"))
Assert-Test (!(Mapping-Matches $selection.gpoId $noneMap $selection)) 'Unchanged GPO audit setting matched explicit No Auditing'
$map=$catalog.mappings|Where-Object{$_.id -eq '2.3.17.8'};$item=$map.items[0]
$script:registry=@{};$script:registry[$item.key+'|'+$item.name]=@{value=1;type='String'}
Assert-Test (!(Mapping-Matches $selection.gpoId $map $selection)) 'Wrong registry type passed publication verification'
$null=Write-Mapping $plan $map
Assert-Test (Mapping-Matches $selection.gpoId $map $selection) 'Wrong registry type was not repaired'
Write-Output 'PASS stronger deny/audit preservation and registry type repair'
$map=$catalog.mappings|Where-Object{$_.id -eq '18.10.93.4.2'}
$script:registry=@{}
$script:registry[$map.items[0].key+'|'+$map.items[0].name]=@{value=0;type='DWord'}
$script:registry[$map.items[1].key+'|'+$map.items[1].name]=@{value=200;type='DWord'}
$null=Write-Mapping @{selection=$selection} $map
Assert-Test ($script:registry[$map.items[1].key+'|'+$map.items[1].name].value -eq 200) 'Repairing one registry item weakened a compliant bound in another item'
Assert-Test (Mapping-Matches $selection.gpoId $map $selection) 'Partial multi-item repair did not satisfy the complete mapping'
Write-Output 'PASS partial multi-item repair preserves stricter compliant numeric siblings'

# Target selection executes the worker resolver with directory enumeration mocked.
function Scope {param($Dn) return @{dn=$Dn}}
$script:targetCount=2
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize) if($script:targetCount -gt 5000){return 1..5001|ForEach-Object{[pscustomobject]@{DNSHostName=('ws'+$_+'.example.local')}}};return @([pscustomobject]@{DNSHostName='ws.example.local'},[pscustomobject]@{DNSHostName='unauthorized.example.local'})}
Assert-Test (@(Refresh-Targets 'None' 'DC=example,DC=local').Count -eq 0) 'None unexpectedly scheduled targets'
Assert-Test ((@(Refresh-Targets 'Pdc' 'DC=example,DC=local' '' 'Domain') -join ',') -eq 'dc.example.local') 'PDC target mismatch'
Assert-Test ((@(Refresh-Targets 'Scope' 'DC=example,DC=local') -join ',') -eq 'ws.example.local') 'Scope allowlist failed'
Assert-Test ((@(Refresh-Targets 'Scope' 'OU=Users,DC=example,DC=local' 'OU=Endpoints,DC=example,DC=local' 'User') -join ',') -eq 'ws.example.local') 'User refresh did not use the independent endpoint OU'
try{$null=Refresh-Targets 'Pdc' 'OU=Users,DC=example,DC=local' '' 'User';throw 'User PDC refresh was allowed'}catch{if($_.Exception.Message -notlike 'USER_REFRESH_TARGET_INVALID*'){throw}}
try{$null=Refresh-Targets 'Pdc' 'OU=Servers,DC=example,DC=local' '' 'Computer';throw 'Computer OU PDC refresh was allowed'}catch{if($_.Exception.Message -notlike 'PDC_REFRESH_SCOPE_INVALID*'){throw}}
$script:targetCount=5001
try{$null=Refresh-Targets 'Scope' 'DC=example,DC=local';throw 'Scope limit was bypassed'}catch{if($_.Exception.Message -notlike 'REFRESH_SCOPE_TOO_LARGE*'){throw}}
$script:targetCount=2
Write-Output 'PASS refresh options: None / Domain-Pdc / Scope, host allowlist and 5,000-host bound'

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
$Data=[pscustomobject]@{plan=$plan;mapping=@{scope='Domain'};refresh='Pdc';previous=@{state='ROLLED_BACK'}}
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

# Exercise the actual full-snapshot rollback branch with a server-owned batch anchor.
$rollbackBlock=$switchAst.Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoRollback'"}|ForEach-Object{$_.Item2}
$script:batchFirst=Join-Path $sandbox 'batch-first';$script:batchLast=Join-Path $sandbox 'batch-last'
$null=New-Item -ItemType Directory -Path $script:batchFirst,$script:batchLast -Force
$plan=[pscustomobject]@{id='batch-first';selection=[pscustomobject]@{gpoId='31b2f340-016d-11d2-945f-00c04fb984f9';scopeDn='OU=Pilot,DC=example,DC=local'};preview=[pscustomobject]@{scopeLinks='old links';existingLink=$null}}
$anchorPlan=[pscustomobject]@{id='batch-last';selection=$plan.selection}
function Run-Directory {param($Plan) if($Plan.id -eq 'batch-last'){return $script:batchLast};return $script:batchFirst}
$firstManifest=@{phase='PUBLISHED';postFingerprint='batch-first';backupId='22222222-2222-2222-2222-222222222222';beforeContent=$content;beforeExtensions='security';directory=$script:batchFirst}
$firstManifest|ConvertTo-Json -Depth 5|Set-Content (Join-Path $script:batchFirst 'manifest.json')
@{phase='PUBLISHED';postFingerprint='batch-last'}|ConvertTo-Json|Set-Content (Join-Path $script:batchLast 'manifest.json')
$script:currentFingerprint='batch-last';$script:restoreCalls=0
function Fingerprint {param($Id,$ScopeDn) return $script:currentFingerprint}
function Restore-GPO {param($BackupId,$Path,$Domain,$Server) $script:restoreCalls++;$script:currentFingerprint='restored-'+$script:restoreCalls;[IO.File]::WriteAllText((Join-Path $script:folder 'policy.txt'),'restored snapshot')}
function Remove-GPLink {param($Guid,$Target,$Domain,$Server,[switch]$Confirm)}
$Data=[pscustomobject]@{plan=$plan;mapping=@{};rollbackAnchor=$null}
try{$null=& ([scriptblock]::Create($rollbackBlock.Extent.Text.TrimStart('{').TrimEnd('}')));throw 'Unanchored old snapshot was accepted'}catch{if($_.Exception.Message -notlike 'ROLLBACK_CONFLICT*'){throw}}
Assert-Test ($script:restoreCalls -eq 0) 'Old individual snapshot overwrote later batch changes'
$Data.rollbackAnchor=[pscustomobject]@{plan=$anchorPlan;postFingerprint='batch-last'}
$cfg|Add-Member -NotePropertyName emitProgress -NotePropertyValue $true -Force
$events=@(& ([scriptblock]::Create($rollbackBlock.Extent.Text.TrimStart('{').TrimEnd('}'))))
$result=$events[-1]
Assert-Test ($result.state -eq 'ROLLED_BACK' -and $script:restoreCalls -eq 1) 'Anchored batch did not restore the first full snapshot'
Assert-Test (@($events|Where-Object{$_.PSObject.Properties['gpoStage']}).Count -eq 3) 'Worker did not stream actual restore stages'
$events=@(& ([scriptblock]::Create($rollbackBlock.Extent.Text.TrimStart('{').TrimEnd('}'))))
Assert-Test ($events[-1].state -eq 'ROLLED_BACK' -and $script:restoreCalls -eq 2) 'Second rollback was not actually executed'
$saved=Get-Content -LiteralPath (Join-Path $script:batchFirst 'manifest.json') -Raw|ConvertFrom-Json
Assert-Test ($saved.rollbackFingerprint -eq 'restored-2' -and $saved.rollbackAttempts -eq 2) 'Repeated restore did not advance the baseline and attempt counter'
$saved.PSObject.Properties.Remove('rollbackFingerprint');$saved|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $script:batchFirst 'manifest.json')
$events=@(& ([scriptblock]::Create($rollbackBlock.Extent.Text.TrimStart('{').TrimEnd('}'))))
Assert-Test ($events[-1].state -eq 'ROLLED_BACK' -and $script:restoreCalls -eq 3) 'Legacy restored manifest was not independently checked and migrated'
$script:currentFingerprint='external edit'
try{$null=& ([scriptblock]::Create($rollbackBlock.Extent.Text.TrimStart('{').TrimEnd('}')));throw 'Batch rollback drift was accepted'}catch{if($_.Exception.Message -notlike 'ROLLBACK_CONFLICT*'){throw}}
Assert-Test ($script:restoreCalls -eq 3) 'Drift caused another restore'
Write-Output 'PASS batch rollback: first snapshot, final publication anchor, external drift rejection and streamed restore stages'
if($ReportPath){$parent=Split-Path ([IO.Path]::GetFullPath($ReportPath)) -Parent;$null=New-Item -ItemType Directory -Force -Path $parent;$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ReportPath -Encoding UTF8}
$failures=@($report|Where-Object{$_.state -eq 'FAIL'})
$report|ForEach-Object{[pscustomobject]$_}|Group-Object handler|ForEach-Object{Write-Output ($_.Name+': '+$_.Count+' controls')}
Write-Output ('Offline mapping results: '+@($report|Where-Object{$_.state -eq 'PASS'}).Count+' PASS, '+@($report|Where-Object{$_.state -eq 'MANUAL_BLOCKED'}).Count+' manual, '+$failures.Count+' FAIL')
if($failures.Count){$failures|ForEach-Object{Write-Output ($_.id+': '+$_.error)};exit 1}
