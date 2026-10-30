$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$reproOutput=Join-Path $root 'work/review3174';$null=New-Item -ItemType Directory -Path $reproOutput -Force
$sandbox=Join-Path ([IO.Path]::GetTempPath()) ('gpr-audit-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $sandbox
try{
 Import-Module (Join-Path $root 'backend/PowerShell/SecurityTemplate.psm1') -Force
 $policy=Join-Path $sandbox 'Policy';$null=New-Item -ItemType Directory -Path $policy
 [IO.File]::WriteAllText((Join-Path $policy 'GPT.INI'),"[General]`r`nVersion=1`r`n")
 $hidden=Join-Path $policy 'Registry.pol';[IO.File]::WriteAllText($hidden,'before');[IO.File]::SetAttributes($hidden,[IO.FileAttributes]::Hidden)
 $hashBefore=Get-NormalizedGpoContentFingerprint $policy;[IO.File]::SetAttributes($hidden,[IO.FileAttributes]::Normal);[IO.File]::WriteAllText($hidden,'after');[IO.File]::SetAttributes($hidden,[IO.FileAttributes]::Hidden);$hashAfter=Get-NormalizedGpoContentFingerprint $policy
 $findings=@(@{test='hidden GPO file omitted from drift fingerprint';differentContents=$true;fingerprintChanged=($hashBefore -cne $hashAfter)})
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'GpoRemediator.ps1'),[ref]$tokens,[ref]$errors)
 $fn=$ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Stop-StaleProductInstance'},$true)[0];. ([scriptblock]::Create($fn.Extent.Text))
 $runtime='C:\new-audit-release\GpoRemediator.exe';$stateFile=Join-Path $sandbox 'not-created.json';$script:stopped=$false;$script:forced=$false
 function Get-RemediatorService {if(!$script:stopped){[pscustomobject]@{executablePath='C:\old-audit-release\GpoRemediator.exe';processId=999999}}}
 function Invoke-RemediatorServiceAction {param($Action) throw 'Service control is blocked by an active operation or maintenance. Wait for it to finish, then retry Stop.'}
 function Get-Process {param($Id,$ErrorAction) [pscustomobject]@{ProcessName='GpoRemediator';Id=999999}}
 function Stop-Process {param($Id,[switch]$Force,$ErrorAction) $script:forced=$Force.IsPresent;$script:stopped=$true}
 function Write-Log {param($Message,$Color)}
 Stop-StaleProductInstance
 $findings+=@{test='migration overrides idle-safe stop rejection';activeOperationStopRejected=$true;forcedStopInvoked=$script:forced;realProcessTerminated=$false}
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
 foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
 $script:statusReads=0;$cfg=@{domainController='dc.example.test';emitProgress=$false}
 function Get-GPO {param($Guid,$Domain,$Server) $script:statusReads++;@{GpoStatus='ComputerSettingsDisabled'}}
 function Mapping-Matches {param($Id,$Map,$S) $true}
 function Selected-Link {param($Dn,$Id) @{enabled=$true;order=1}}
 function Verification-Metadata {param($S) @{versionsMatch=$true;replicationConverged=$true}}
 function Mapping-Display {param($Id,$Map,$S,$Desired) '16384'}
 function Verify-EffectiveSamples {param($Plan,$Map) @(@{hostname='ws.example.test';state='VERIFIED';message='Fixture unchanged registry value';actualValue='16384'})}
 $plan=@{selection=@{gpoId='11111111-1111-1111-1111-111111111111';scopeDn='OU=Pilot,DC=example,DC=test';firstLink=$false};preview=@{}}
 $map=@{id='9.1.5';domainPolicySensitive=$false;scope='Computer'}
 $v=Verify-Published $plan $map $true
 $findings+=@{test='verification omits current GPO disabled status';gpoStatus='ComputerSettingsDisabled';statusReads=$script:statusReads;published=$v.published;linked=$v.linked;effective=$v.effective}
 # Real private ACLs: a safe root can contain an unsafe existing workspace.
 $backupRoot=Join-Path $sandbox 'Backups';$null=New-Item -ItemType Directory -Path $backupRoot
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $rootAcl=[Security.AccessControl.DirectorySecurity]::new();$rootAcl.SetAccessRuleProtection($true,$false)
 $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
 [IO.Directory]::SetAccessControl($backupRoot,$rootAcl)
 $work=Join-Path $backupRoot 'GpoWorkflow';$null=New-Item -ItemType Directory -Path $work
 $childAcl=[Security.AccessControl.DirectorySecurity]::new();$childAcl.SetAccessRuleProtection($true,$false)
 $childAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
 $childAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::Modify,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
 [IO.Directory]::SetAccessControl($work,$childAcl)
 $childUnsafe=Backup-AclIsUnsafe (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $work)
 $cfg.domain='example.test';$cfg.backupPath=$backupRoot;$domain=@{DNSRoot='example.test'};$dc=@{HostName='dc.example.test'};$script:aclReads=@()
 function Get-Acl {param($LiteralPath,$ErrorAction) $script:aclReads+=$LiteralPath;Microsoft.PowerShell.Security\Get-Acl -LiteralPath $LiteralPath}
 function Resolve-DnsName {param($Name,$Type,$ErrorAction) [pscustomobject]@{IPAddress='127.0.0.1'}}
 function Get-ADDomain {param($Identity,$Server,$ErrorAction) $domain}
 function Sysvol-Policies {$policy}
 function Get-ADReplicationPartnerMetadata {param($Target,$Scope,$ErrorAction) @()}
 $environment=Environment-Status
 $findings+=@{test='backup readiness checks safe root but not unsafe workspace ACL';childBroadModify=$childUnsafe;ready=$environment.ready;backupAclState=($environment.checks|Where-Object id -eq 'backup-acl').state;workspaceAclRead=($script:aclReads -contains $work)}
 $diag=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend/PowerShell/PolicyDiagnostics.ps1'),[ref]$tokens,[ref]$errors)
 $accessFn=$diag.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Access-Report'},$false)[0];. ([scriptblock]::Create($accessFn.Extent.Text))
 $script:domainAccessChecks=0
 function Selection-Access {param($S,$Map) @{executionUser='EXAMPLE\Operator';checks=@(@{id='gpo-edit';label='GPO';state='ALLOWED'})}}
 function Gpo-Folder {param($Id) $policy}
 function Policy-WritePaths {param($S,$Map) @()}
 function Environment-Status {@{checks=@()}}
 function Domain-PolicyAccess {param($Property) $script:domainAccessChecks++;throw 'DOMAIN_POLICY_ACCESS_DENIED|Fixture denial'}
 $cfg.domain='example.test';$domainDn='DC=example,DC=test';$dc=@{HostName='dc.example.test'}
 $report=Access-Report @{gpoId=$plan.selection.gpoId;scopeDn=$domainDn} @{id='1.2.1';scope='Domain';domainPolicySensitive=$true}
 $findings+=@{test='domain permission report omits AD property write authority';ready=$report.ready;domainWriteChecks=$script:domainAccessChecks;domainWriteAllowed=$false}
 $json=$findings|ConvertTo-Json -Depth 8;[IO.File]::WriteAllText((Join-Path $reproOutput 'powershell-repros.json'),$json,[Text.UTF8Encoding]::new($false));Write-Output $json
}finally{
 $resolved=[IO.Path]::GetFullPath($sandbox)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-audit-*'){throw 'Unsafe audit fixture cleanup path'}
 Get-ChildItem -LiteralPath $resolved -Recurse -File -Force|ForEach-Object{[IO.File]::SetAttributes($_.FullName,[IO.FileAttributes]::Normal)}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
