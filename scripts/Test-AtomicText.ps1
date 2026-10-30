# Real filesystem commits with injected ReplaceFile errors; no AD/policy writes.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$fn=$ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Atomic-Text'},$false)[0]
$source=$fn.Extent.Text.Replace('[IO.File]::Replace($temp,$Path,[System.Management.Automation.Language.NullString]::Value)','Invoke-FixtureReplace $temp $Path')
. ([scriptblock]::Create($source))
function Invoke-FixtureReplace($Source,$Destination){
 $script:calls++
 if($script:calls -le $script:failCount){
  if($script:code -eq 5){throw [UnauthorizedAccessException]::new('Injected access denial')}
  throw [IO.IOException]::new('Injected ReplaceFile failure',(-2147024896+$script:code))
 }
 [IO.File]::Replace($Source,$Destination,[System.Management.Automation.Language.NullString]::Value)
}
$sandbox=Join-Path ([IO.Path]::GetTempPath()) ('gpr-atomic-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $sandbox
try{
 foreach($case in @(@(0,0,1,$true),@(32,2,3,$true),@(33,1,2,$true),@(1175,99,4,$true),@(5,99,1,$true),@(32,99,4,$false),@(112,99,1,$false))){
  $script:code=$case[0];$script:failCount=$case[1];$script:calls=0;$path=Join-Path $sandbox 'manifest.json'
  [IO.File]::WriteAllText($path,'before');$succeeded=$true
  try{Atomic-Text $path 'after' ([Text.UTF8Encoding]::new($false))}catch{$succeeded=$false}
  if($succeeded -ne $case[3] -or $script:calls -ne $case[2] -or [IO.File]::ReadAllText($path) -ne $(if($succeeded){'after'}else{'before'})){throw ('Unsafe commit result for native error '+$script:code)}
  if(@(Get-ChildItem -LiteralPath $sandbox -Filter '*.tmp').Count){throw 'Commit left temporary contents behind'}
 }
 Write-Output 'PASS atomic text commits: normal replacement, transient sharing/lock recovery, bounded retries, 1175/access-denied durable fallback and unchanged original on sharing/disk failures; no live AD'
}finally{
 $resolved=[IO.Path]::GetFullPath($sandbox)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-atomic-*'){throw 'Unsafe fixture cleanup path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
