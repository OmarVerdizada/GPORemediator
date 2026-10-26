# Actual endpoint verifier; all SAM/CIM/AD/remoting functions are fixture doubles.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Check($ok,$message){if(!$ok){throw $message};Write-Output ('PASS '+$message)}
$cfg=@{domainController='dc.example.test';allowedHosts=@('ws.example.test')}
$plan=@{selection=@{scopeDn='OU=Pilot,DC=example,DC=test'};preview=@{impact=$null;verificationComputers=@('ws.example.test')}}
$map=@{handler='SecurityTemplate';scope='Computer';domainPolicySensitive=$false;requiresInput=$false;allowValueOverride=$false;comparator=$null;items=@(@{section='System Access';key='EnableGuestAccount';name=$null;guid=$null;type='Integer';value=@('0')})}
$script:useCim=$false;$script:readDenied=$false;$script:domainRole=3
$script:account=[pscustomobject]@{Name='pslguest';SID='S-1-5-21-100-200-300-501';Enabled=$false;PrincipalSource='Local'}
function Get-ADComputer {param($SearchBase,$SearchScope,$Filter,$Server,$Properties,$ResultSetSize,$ErrorAction) [pscustomobject]@{DNSHostName='ws.example.test'}}
function Invoke-Command {param($ComputerName,$Authentication,$Credential,$ErrorAction,$ArgumentList,$ScriptBlock) & $ScriptBlock @ArgumentList}
function Get-Command {param($Name,$ErrorAction) if($Name -ne 'Get-LocalUser'){throw 'Unexpected command lookup'};if(!$script:useCim){[pscustomobject]@{Name='Get-LocalUser'}}}
function Get-LocalUser {param($ErrorAction) if($script:readDenied){throw 'Access denied fixture'};return $script:account}
function Get-CimInstance {
 param($ClassName,$Filter,$Property,$ErrorAction)
 if($ClassName -eq 'Win32_ComputerSystem'){return [pscustomobject]@{DomainRole=$script:domainRole}}
 if($ClassName -ne 'Win32_UserAccount' -or $Filter -notmatch 'LocalAccount=True'){throw 'Unbounded or unexpected account query'}
 foreach($entry in @($script:account)){[pscustomobject]@{Name=$entry.Name;SID=$entry.SID;Disabled=(-not $entry.Enabled);LocalAccount=($entry.PrincipalSource -eq 'Local')}}
}
function secedit.exe {throw 'Built-in account checks must not export a temporary policy file'}
function Probe {return @(Verify-EffectiveSamples $plan $map)[0]}
$result=Probe
Check ($result.state -eq 'VERIFIED' -and $result.actualValue -match 'EnableGuestAccount=0.*pslguest.*-501') 'renamed disabled Guest is verified from its RID and actual enabled flag without an INF'
$script:account.Enabled=$true
Check ((Probe).state -eq 'MISMATCH') 'an enabled Guest is a real mismatch even if a configured INF might contain zero'
$script:account.Enabled=$false;$map.items[0].key='NewGuestName';$map.items[0].type='QuotedString';$map.items[0].value=@('pslguest')
Check ((Probe).state -eq 'VERIFIED') 'Guest rename is read from RID 501'
$map.items[0].value=@('different-name');Check ((Probe).state -eq 'MISMATCH') 'different live Guest name is a mismatch'
$map.items[0].key='NewAdministratorName';$map.items[0].value=@('psladmin');$script:account.SID='S-1-5-21-100-200-300-500';$script:account.Name='psladmin'
Check ((Probe).state -eq 'VERIFIED') 'Administrator rename is read from RID 500'
$script:readDenied=$true;Check ((Probe).state -eq 'PENDING') 'SAM read failure remains insufficient evidence'
$script:readDenied=$false;$script:account.PrincipalSource='Active Directory'
Check ((Probe).state -eq 'PENDING') 'domain RID 500 is not substituted for local-account evidence'
$script:account.PrincipalSource='Local';$script:account.Enabled=$null
Check ((Probe).state -eq 'PENDING') 'unknown enabled flag is not silently converted to disabled'
$script:account.Enabled=$false
$script:account.PrincipalSource='Local';$script:useCim=$true
Check ((Probe).state -eq 'VERIFIED') 'bounded local-account CIM fallback works when LocalAccounts is unavailable'
$script:domainRole=5;Check ((Probe).state -eq 'PENDING') 'CIM fallback refuses domain controllers'
$script:domainRole=$null;Check ((Probe).state -eq 'PENDING') 'CIM fallback refuses unknown endpoint roles'
$script:domainRole=3;$script:useCim=$false;$original=$script:account;$script:account=@($original,$original)
Check ((Probe).state -eq 'PENDING') 'ambiguous account identity is not accepted'
$script:account=@();Check ((Probe).state -eq 'PENDING') 'missing account state is not fabricated'
