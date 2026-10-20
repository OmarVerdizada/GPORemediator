# Synthetic DC fixtures only: no registry, domain or SYSVOL is changed.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Check($ok,$message){if(!$ok){throw $message}}
function Reject($action,$pattern){try{& $action|Out-Null;throw 'Expected failure'}catch{if($_.Exception.Message -notlike $pattern){throw}}}
$domain=@{DNSRoot='example.local'}
$script:settings=@{SysVol='C:\Relocated\SYSVOL_DFSR\sysvol';SysvolReady=1}
$script:exists=$true;$script:registryDenied=$false;$script:pathDenied=$false;$script:seen=''
function Get-CimInstance {throw 'Regression: delegated discovery must not require CIM'}
function Get-ItemProperty {param($LiteralPath,$Name,$ErrorAction)
 Check ($LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') 'Wrong configuration source'
 if($script:registryDenied){throw [UnauthorizedAccessException]::new('Registry access denied')}
 return [pscustomobject]$script:settings
}
function Test-Path {param($LiteralPath,$PathType,$ErrorAction)
 Check ($PathType -eq 'Container' -and $ErrorAction -eq 'Stop') 'Directory access errors must fail closed'
 $script:seen=$LiteralPath
 if($script:pathDenied){throw [UnauthorizedAccessException]::new('Policies access denied')}
 return $script:exists
}
Check ((Sysvol-Policies) -eq 'C:\Relocated\SYSVOL_DFSR\sysvol\example.local\Policies') 'Relocated active SYSVOL was ignored'
Check ((Gpo-Folder '11111111-aaaa-bbbb-cccc-222222222222') -eq 'C:\Relocated\SYSVOL_DFSR\sysvol\example.local\Policies\{11111111-AAAA-BBBB-CCCC-222222222222}') 'GPO path is not pinned to local active SYSVOL'
$script:settings.SysVol='%SystemRoot%\SYSVOL\sysvol'
Check ((Sysvol-Policies).StartsWith($env:SystemRoot+'\SYSVOL\sysvol\')) 'Expandable registry path failed'
$script:settings.SysvolReady=0;Reject {Sysvol-Policies} 'SYSVOL_UNAVAILABLE|*not ready*'
$script:settings.SysvolReady=1
foreach($bad in @('','relative\sysvol','\\other-dc\SYSVOL')){$script:settings.SysVol=$bad;Reject {Sysvol-Policies} 'SYSVOL_UNAVAILABLE|*local absolute*'}
$script:settings.SysVol='C:\Windows\SYSVOL\sysvol';$script:exists=$false
Reject {Sysvol-Policies} 'SYSVOL_UNAVAILABLE|*directory is unavailable*'
$script:exists=$true;$script:pathDenied=$true;Reject {Sysvol-Policies} '*Policies access denied*'
$script:pathDenied=$false;$script:registryDenied=$true;Reject {Sysvol-Policies} '*Registry access denied*'
Check (@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-CimInstance' -and $n.Extent.Text -match 'Win32_Share'},$true)).Count -eq 0) 'Worker still depends on share enumeration'
Write-Output 'PASS SYSVOL discovery: no CIM rights, relocated/DFSR path, expansion, local pinning, readiness and access failures. No AD commands executed.'
