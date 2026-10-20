# Effective rights fixtures. Native AccessCheck uses only a private local test file.
# Directory/GroupPolicy APIs below are mocked; no domain or GPO is modified.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($fn.Extent.Text))}
function Check($ok,$message){if(!$ok){throw $message}}
function Reject($action,$code){try{& $action|Out-Null;throw ('Expected '+$code)}catch{if($_.Exception.Message -notlike ($code+'|*')){throw}}}
$sandbox=Join-Path $repo ('work/access-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $sandbox
try{
 $file=Join-Path $sandbox 'fixture.txt';[IO.File]::WriteAllText($file,'fixture')
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 function Set-FixtureAcl($rights,[bool]$deny=$false){
  $acl=[Security.AccessControl.FileSecurity]::new($file,[Security.AccessControl.AccessControlSections]::Access)
  $acl.SetAccessRuleProtection($true,$false)
  foreach($rule in @($acl.Access)){$acl.RemoveAccessRuleSpecific($rule)}
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,$rights,'Allow'))
  if($deny){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::Write,'Deny'))}
  ([IO.FileInfo]::new($file)).SetAccessControl($acl)
 }
 Set-FixtureAcl ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
 Check (!(Test-FileSystemModify $file)) 'Native AccessCheck treated read-only as modify'
 Set-FixtureAcl ([Security.AccessControl.FileSystemRights]::Modify)
 Check (Test-FileSystemModify $file) 'Native AccessCheck rejected modify'
 Set-FixtureAcl ([Security.AccessControl.FileSystemRights]::Modify) $true
 Check (!(Test-FileSystemModify $file)) 'Native AccessCheck ignored matching deny'
 Set-FixtureAcl ([Security.AccessControl.FileSystemRights]::FullControl)
 Write-Output 'PASS native Windows effective file access: read-only, modify and deny-over-allow'
 $cfg=@{domainController='dc.example.local';domain='example.local'};$domainDn='DC=example,DC=local'
 $selection=@{gpoId='11111111-1111-1111-1111-111111111111';scopeDn='OU=Pilot,'+$domainDn};$mapping=@{scope='Computer'}
 $script:existingLink=$null
 function Selected-Link {param($Dn,$Id) return $script:existingLink}
 $script:gpoAttributes=@('versionNumber','gPCMachineExtensionNames','gPCUserExtensionNames');$script:ouAttributes=@('gPLink');$script:directoryError=$false;$script:fileAllowed=$true;$script:fileError=$false
 function Get-ADObject {param($Identity,$Server,$Properties,$ErrorAction)
  if($script:directoryError){throw 'Fixture metadata unavailable'}
  Check ($Server -eq 'dc.example.local') 'Effective access query used an unpinned DC'
  Check ($Properties -eq 'allowedAttributesEffective') 'Guessed trustee access replaced DC effective attributes'
  [pscustomobject]@{allowedAttributesEffective=$(if($Identity -like 'CN=*'){$script:gpoAttributes}else{$script:ouAttributes})}
 }
 function Gpo-Folder {param($Id) return $sandbox}
 function Test-FileSystemModify {param($Path) if($script:fileError){throw 'Fixture ACL unavailable'};return $script:fileAllowed}
 Check (@((Assert-SelectionAccess $selection $mapping).checks|Where-Object{$_.state -eq 'ALLOWED'}).Count -eq 3) 'Allowed selection was blocked'
 $script:gpoAttributes=@('gPCMachineExtensionNames');Reject {Assert-SelectionAccess $selection $mapping} 'GPO_EDIT_ACCESS_DENIED'
 $script:gpoAttributes=@('versionNumber','gPCMachineExtensionNames');$script:ouAttributes=@('description');Reject {Assert-SelectionAccess $selection $mapping} 'OU_LINK_ACCESS_DENIED'
 $script:existingLink=@{enabled=$true;order=3};$null=Assert-SelectionAccess $selection $mapping
 $selection.firstLink=$true;Reject {Assert-SelectionAccess $selection $mapping} 'OU_LINK_ACCESS_DENIED'
 $selection.firstLink=$false;$script:existingLink=$null
 $script:ouAttributes=@('gPLink');$script:fileAllowed=$false;Reject {Assert-SelectionAccess $selection $mapping} 'SYSVOL_WRITE_ACCESS_DENIED'
 $script:fileAllowed=$true;$script:directoryError=$true;Reject {Assert-SelectionAccess $selection $mapping} 'GPO_ACCESS_UNVERIFIED'
 $script:directoryError=$false;$script:fileError=$true;Reject {Assert-SelectionAccess $selection $mapping} 'GPO_ACCESS_UNVERIFIED'
 $script:fileError=$false;$mapping.scope='User';$script:gpoAttributes=@('versionNumber','gPCUserExtensionNames');$null=Assert-SelectionAccess $selection $mapping
 $script:gpoAttributes=@('versionNumber','gPCMachineExtensionNames');Reject {Assert-SelectionAccess $selection $mapping} 'GPO_EDIT_ACCESS_DENIED'
 # The actual Preview entry must stop before reading/writing a plan on denial.
 function Validate-Selection {param($S,$Map)}
 $script:reads=0
 function Get-GPO {param($Guid,$Domain,$Server) $script:reads++;throw 'AFTER_ACCESS_GATE|Read-only fixture'}
 Reject {Preview $selection $mapping} 'GPO_EDIT_ACCESS_DENIED';Check ($script:reads -eq 0) 'Denied access reached plan work'
 Reject {Preview $selection $mapping $false} 'AFTER_ACCESS_GATE';Check ($script:reads -eq 1) 'Read-only scan incorrectly requires write delegation'
 $script:directoryCalls=0
 function Run-Directory {param($Plan) $script:directoryCalls++;throw 'UNEXPECTED|Directory creation reached'}
 $Data=@{plan=@{selection=$selection};mapping=$mapping}
 $switch=$ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.SwitchStatementAst]}|Select-Object -Last 1
 $apply=$switch.Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoApply'"}|ForEach-Object{$_.Item2}
 Reject {& ([scriptblock]::Create($apply.Extent.Text.TrimStart('{').TrimEnd('}')))} 'GPO_EDIT_ACCESS_DENIED'
 Check ($script:directoryCalls -eq 0) 'Apply created operation files before effective access recheck'
 # The access-only entry must not enter Preview or create a plan.
 $script:gpoAttributes=@('versionNumber','gPCUserExtensionNames');$script:reads=0
 $Data=@{selection=$selection;mapping=$mapping;accessOnly=$true};$previewCase=$switch.Clauses|Where-Object{$_.Item1.Extent.Text -eq "'gpoPreview'"}|ForEach-Object{$_.Item2}
 $accessResult=& ([scriptblock]::Create($previewCase.Extent.Text.TrimStart('{').TrimEnd('}')))
 Check ($accessResult.authorized -and $script:reads -eq 0) 'Selection access check entered Preview instead of returning read-only access'
 Write-Output 'PASS selection access gate: separate GPO/OU/SYSVOL denial, unknown metadata, user CSE, blocked Preview/Apply and read-only scan bypass. No AD commands executed.'
}finally{
 $full=[IO.Path]::GetFullPath($sandbox);$allowed=[IO.Path]::GetFullPath((Join-Path $repo 'work'))+'\'
 if(!$full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup'}
 if(Test-Path -LiteralPath $file){Set-FixtureAcl ([Security.AccessControl.FileSystemRights]::FullControl)}
 Remove-Item -LiteralPath $full -Recurse -Force
}
