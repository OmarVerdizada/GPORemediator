# Execute trusted diagnostic functions and the actual remote probe against local doubles.
# No AD, registry, endpoint or delegation is changed.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
. (Join-Path $repo 'backend/PowerShell/PolicyDiagnostics.ps1')
function Check($Ok,$Name){if(!$Ok){throw $Name};Write-Output ('PASS '+$Name)}
$cfg=@{domain='example.test';domainController='dc.example.test';backupPath='C:\fixture-backups'};$domainDn='DC=example,DC=test'
$script:selected='11111111-1111-1111-1111-111111111111';$script:winner=$script:selected;$script:deny=$false;$script:rsopUnavailable=$false;$script:unknown=$false;$script:remoteCalls=0
function Refresh-Targets {'pc.example.test'}
function Endpoint-CredentialOptions {@{Credential='fixture'}}
function Verify-EffectiveSamples {@{hostname='pc.example.test';state='MISMATCH';actualValue='Test=0'}}
function Get-CimInstance {param($Namespace,$ClassName,$ErrorAction)
 if($script:rsopUnavailable){throw 'fixture access denied'}
 switch($ClassName){
  'RSOP_GPO' {[pscustomobject]@{guidName=$script:selected;name='Pilot';enabled=$true;accessDenied=$script:deny;filterAllowed=(!$script:deny)}}
  'RSOP_RegistryPolicySetting' {[pscustomobject]@{registryKey='Software\Policies\Test';valueName='Test';GPOID=$(if($script:unknown){'unresolved'}else{$script:winner});precedence=1;deleted=$false}}
 }
}
function Get-WinEvent {param($FilterHashtable,$MaxEvents,$ErrorAction) [pscustomobject]@{Id=5312;LevelDisplayName='Information';TimeCreated=(Get-Date);Message='Fixture logged processing evidence'}}
function Test-Path {param($LiteralPath,$ErrorAction) $false}
function Get-ItemProperty {param($LiteralPath,$ErrorAction) [pscustomobject]@{}}
function Invoke-Command {param($ComputerName,$Authentication,$Credential,$ArgumentList,$ScriptBlock,$ErrorAction)
 Check ($ComputerName -eq 'pc.example.test' -and $Authentication -eq 'Kerberos' -and $Credential -eq 'fixture') 'explicit credential and pinned endpoint'|Out-Null
 $script:remoteCalls++;& $ScriptBlock @ArgumentList
}
$selection=[pscustomobject]@{gpoId=$script:selected;scopeDn='OU=Pilot,DC=example,DC=test';endpointScopeDn=''}
$plan=@{selection=$selection;preview=@{impact=@{};verificationComputers=@('pc.example.test')}}
$map=[pscustomobject]@{handler='Registry';scope='Computer';domainPolicySensitive=$false;requiresRestart=$false;items=@([pscustomobject]@{key='HKLM\Software\Policies\Test';name='Test';type='DWord'})}
$v=Explain-Policy $plan $map 'pc.example.test'
Check ($v.state -eq 'SELECTED_GPO_RECORDED' -and $v.items[0].winningGpo -eq $script:selected -and $v.effectiveChecks[0].state -eq 'MISMATCH') 'logged source and current native value remain distinct evidence'
$script:winner='22222222-2222-2222-2222-222222222222';$v=Explain-Policy $plan $map 'pc.example.test'
Check ($v.state -eq 'CONFLICT_RECORDED' -and $v.items[0].state -eq 'OTHER_GPO_WINS') 'higher precedence competing GPO attributed by record'
$script:deny=$true;$v=Explain-Policy $plan $map 'pc.example.test'
Check (@($v.findings|Where-Object state -eq 'SECURITY_FILTER_DENIED').Count -eq 1 -and @($v.findings|Where-Object state -eq 'WMI_FILTER_DENIED').Count -eq 1) 'explicit recorded security and WMI filter failures surfaced'
$script:unknown=$true;$v=Explain-Policy $plan $map 'pc.example.test'
Check ($v.items[0].state -eq 'UNKNOWN_SOURCE') 'unresolved attribution never claims selected GPO'
$script:rsopUnavailable=$true;$v=Explain-Policy $plan $map 'pc.example.test'
Check ($v.state -eq 'PARTIAL_EVIDENCE' -and @($v.findings|Where-Object state -eq 'RSOP_UNAVAILABLE').Count -eq 1 -and $v.events.Count -eq 1) 'inaccessible RSoP retains independent native/event evidence'
$calls=$script:remoteCalls
try{$null=Explain-Policy $plan $map 'other.example.test';throw 'out of scope accepted'}catch{if($_.Exception.Message -notlike 'ENDPOINT_OUTSIDE_SCOPE*'){throw}}
Check ($calls -eq $script:remoteCalls) 'out of scope rejected before remote access'
function Selection-Access {@{executionUser='EXAMPLE\operator';checks=@(@{id='gpo-edit';label='GPO';state='DENIED'},@{id='link-write';label='Link';state='ALLOWED'})}}
function Gpo-Folder {'C:\fixture-sysvol\{11111111-1111-1111-1111-111111111111}'}
function Policy-WritePaths {'C:\fixture-sysvol\GPT.INI'}
function Test-FileSystemWrite {$false}
function Environment-Status {@{checks=@(@{id='backup';label='Backup';state='FAIL';required=$true;message='Exact workspace denied'})}}
function Get-ADObject {param($Identity,$Server,$Properties,$ErrorAction) [pscustomobject]@{allowedChildClassesEffective=@('msDS-PasswordSettings')}}
$v=Access-Report $selection $map
Check (!$v.ready -and $v.checks[0].target -like 'CN={11111111*' -and @($v.checks|Where-Object{$_.target -eq 'C:\fixture-sysvol\GPT.INI' -and $_.state -eq 'DENIED'}).Count -eq 1) 'access report retains exact AD/file targets and denied state'
Write-Output 'PASS GPO access and endpoint diagnostics; no live AD tested.'
