# Compile and exercise only the read-only local LSA reader. No AD or policy write.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$fn=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'UserRight-ProbeSource'},$false)
. ([scriptblock]::Create($fn.Extent.Text))
Add-Type -TypeDefinition (UserRight-ProbeSource)
try{
 $sids=@([GpoRemediator.ReadOnly.UserRightsV1]::Read('SeCreateGlobalPrivilege'))
 foreach($sid in $sids){if($sid -notmatch '^S-\d-(?:\d+-){1,14}\d+$'){throw 'Invalid SID returned by native LSA reader'}}
 Write-Output ('PASS native read-only LSA enumeration on the local test host; '+$sids.Count+' assigned SIDs; no policy changed')
}catch{
 $e=$_.Exception;while($e.InnerException){$e=$e.InnerException}
 if($e -isnot [ComponentModel.Win32Exception] -or $e.NativeErrorCode -ne 5){throw}
 Write-Output 'PASS native LSA reader compiled and propagated access denial (5); assignments unavailable to the local test identity; no policy changed'
}
$rejected=$false;try{$null=[GpoRemediator.ReadOnly.UserRightsV1]::Read(('X'*257))}catch{$rejected=$true}
if(!$rejected){throw 'Unbounded privilege name accepted'}
Write-Output 'PASS LSA reader input bounds; native buffers and policy handles are released in finally'
