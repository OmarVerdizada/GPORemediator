# Production OU resolver with recorded directory data. No AD/network calls.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Check($ok,$message){if(!$ok){throw $message}}
$cfg=@{domain='example.local';domainController='dc.example.local';endpointTargeting='SelectedOu';allowedHosts=@('obsolete.example.local')}
$domain=@{PDCEmulator='dc.example.local'}
$script:count=200;$script:search=''
function Scope([string]$Dn){@{dn=$Dn}}
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize)
 Check ($SearchScope -eq 'Subtree') 'Child OU enumeration missing'
 Check ([string]$Filter -match 'Enabled') 'Disabled accounts were not excluded'
 Check ($ResultSetSize -eq 5001) 'Unbounded directory enumeration'
 $script:search=$SearchBase
 1..$script:count|ForEach-Object{[pscustomobject]@{DNSHostName=('pc'+$_+'.example.local')}}
}
$targets=@(Refresh-Targets 'Scope' 'OU=Workstations,DC=example,DC=local')
Check ($targets.Count -eq 200) '200-computer OU requires manual names or is truncated'
Check ($script:search -eq 'OU=Workstations,DC=example,DC=local') 'Wrong computer OU'
$null=Refresh-Targets 'Scope' 'OU=Users,DC=example,DC=local' 'OU=Clients,DC=example,DC=local' 'User'
Check ($script:search -eq 'OU=Clients,DC=example,DC=local') 'User refresh queried user OU instead of endpoint OU'
Check ((@(Refresh-Targets 'Pdc' 'DC=example,DC=local' '' 'Domain') -join ',') -eq 'dc.example.local') 'Automatic domain policy refresh omitted pinned PDC'
Check (@(Refresh-Targets 'None' 'OU=Workstations,DC=example,DC=local').Count -eq 0) 'Refresh ran implicitly'
$filtered=@(Filter-EndpointHosts @('pc1.example.local','other.evil.local','pc.example.local.evil','*.example.local','127.0.0.1','bad name.example.local'))
Check (($filtered -join ',') -eq 'pc1.example.local') 'Automatic mode accepted wildcard, malformed or foreign DNS host'
$cfg.endpointTargeting='ExplicitHosts';$cfg.allowedHosts=@('pc17.example.local')
Check ((@(Refresh-Targets 'Scope' 'OU=Workstations,DC=example,DC=local') -join ',') -eq 'pc17.example.local') 'Explicit host mode lost its restriction'
$cfg.Remove('endpointTargeting')
Check ((@(Refresh-Targets 'Scope' 'OU=Workstations,DC=example,DC=local') -join ',') -eq 'pc17.example.local') 'Legacy explicit list expanded silently'
$cfg.allowedHosts=@()
Check (@(Refresh-Targets 'Scope' 'OU=Workstations,DC=example,DC=local').Count -eq 200) 'Empty new configuration did not default to automatic OU'
$cfg.endpointTargeting='invalid'
try{$null=Refresh-Targets 'Scope' 'OU=Workstations,DC=example,DC=local';throw 'Invalid mode accepted'}catch{if($_.Exception.Message -notlike 'INVALID_ENDPOINT_TARGETING*'){throw}}
$cfg.endpointTargeting='SelectedOu';$script:count=5001
try{$null=Refresh-Targets 'Scope' 'OU=Workstations,DC=example,DC=local';throw 'Directory limit bypassed'}catch{if($_.Exception.Message -notlike 'REFRESH_SCOPE_TOO_LARGE*'){throw}}
Write-Output 'PASS automatic OU targeting: 200 hosts, subtree/user OU, PDC/None, DNS boundaries, explicit mode, legacy migration, invalid mode and bounded enumeration. No AD commands executed.'
