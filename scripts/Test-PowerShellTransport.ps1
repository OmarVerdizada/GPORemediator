# Run the installed bootstrap in a real Windows PowerShell 5.1 child process.
# Session/remoting are stubbed before bootstrap invocation; no AD/network probe runs.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$temp=Join-Path ([IO.Path]::GetTempPath()) ('gpr-transport-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$bootstrap=(Join-Path $repo 'backend/PowerShell/Invoke-GpoWorkflow.ps1').Replace("'","''")
$wrapper=Join-Path $temp 'fixture.ps1'
$stub=@'
function New-PSSessionOption {param($OpenTimeout,$OperationTimeout) @{fixture=$true}}
function New-PSSession {param($ComputerName,$Authentication,$SessionOption,$Credential) [pscustomobject]@{fixture=$true}}
function Remove-PSSession {param($Session,$ErrorAction)}
function Invoke-Command {
 param($Session,$ScriptBlock,$ArgumentList)
 if(!$Session.fixture){throw 'Fixture requires mocked session'}
 Write-Output ([pscustomobject]@{gpoStage='REPLICATION_ENDPOINT_CHECK'})
 Write-Information -MessageData @{gpoCheck=@{phase='GPO';state='VERIFIED';subject='fixture-gpo';message='Read-back fixture';actualValue='S-1-5-19,S-1-5-20,S-1-5-32-544'}} -InformationAction Continue
 if($env:GPR_TRANSPORT_TEST -eq 'error'){throw 'FIXTURE_DENIED|Fixture operation denied safely.'}
 [Console]::Out.Write('module banner without newline')
 @{state='PUBLISHED';message='Read-back fixture';gpoPublished=$true;linkVerified=$true;effectiveStatus='ENDPOINT_VERIFICATION_PENDING';refreshResults=@();currentValue='S-1-5-19,S-1-5-20,S-1-5-32-544'}
}
'@
try{
 [IO.File]::WriteAllText($wrapper,$stub+"`r`n& '$bootstrap'`r`n",[Text.UTF8Encoding]::new($true))
 foreach($case in @('success','error')){
  $start=[Diagnostics.ProcessStartInfo]::new('powershell.exe')
  $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $start.StandardOutputEncoding=[Text.Encoding]::UTF8;$start.StandardErrorEncoding=[Text.Encoding]::UTF8
  $start.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$wrapper+'"'
  $start.EnvironmentVariables['GPR_TRANSPORT_TEST']=$case
  $process=[Diagnostics.Process]::Start($start)
  try{
   $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
   $request=@{operation='gpoVerify';configuration=@{domain='example.test';domainController='dc.example.test'};payload=@{credential=@{userName='EXAMPLE\fixture';password='private-fixture-credential'};data=@{}}}|ConvertTo-Json -Depth 8 -Compress
   $bytes=[Text.Encoding]::UTF8.GetBytes($request);$process.StandardInput.BaseStream.Write($bytes,0,$bytes.Length);$process.StandardInput.Close();[Array]::Clear($bytes,0,$bytes.Length);$request=$null
   if(!$process.WaitForExit(20000)){$process.Kill();throw 'PowerShell fixture exceeded deadline'}
   $text=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
   $frames=@($text -split "`r?`n"|Where-Object{$_ -like 'GPO_RESULT:*'})
   if($frames.Count -ne 1){throw ('Expected exactly one result frame for '+$case)}
   $result=$frames[0].Substring(11)|ConvertFrom-Json
   if($text -match 'private-fixture-credential'){throw 'Credential appeared in protocol output'}
   if($case -eq 'success'){
    if(!$result.ok -or !$result.data.gpoPublished -or $result.data.currentValue -ne 'S-1-5-19,S-1-5-20,S-1-5-32-544'){throw 'Actual bootstrap did not preserve user-rights read-back'}
    if($text -notmatch 'module banner without newline' -or $text -notmatch 'GPO_CHECK:' -or $text -notmatch 'GPO_STAGE:REPLICATION_ENDPOINT_CHECK'){throw 'Noise/progress fixture was not exercised'}
    $legacyFailed=$false;try{$null=$text|ConvertFrom-Json -ErrorAction Stop}catch{$legacyFailed=$true}
    if(!$legacyFailed){throw 'Fixture did not reproduce legacy unframed JSON parsing failure'}
   }elseif($result.ok -or $result.code -ne 'FIXTURE_DENIED'){throw 'Bootstrap failure was not retained as a failed result'}
   Write-Output ('PASS real PowerShell bootstrap '+$case+': one framed result, live progress, no credential output and no remoting')
  }finally{$process.Dispose()}
 }
}finally{
 $resolved=[IO.Path]::GetFullPath($temp)
 if(!$resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'gpr-transport-*'){throw 'Unsafe fixture cleanup path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
