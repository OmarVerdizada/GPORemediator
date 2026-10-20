# Exercise the real native client with HTTP/process fixtures, never a live service.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'ServiceControl.ps1')
$originalProgramData=$env:ProgramData
$sandbox=Join-Path $repo ('work\service-control-'+[guid]::NewGuid().ToString('N'))
$env:ProgramData=$sandbox
$work=Join-Path $sandbox 'GpoRemediator\State'
$null=New-Item -ItemType Directory -Path $work -Force
$script:running=$true;$script:scenario='accepted';$script:postCount=0;$script:killCount=0;$script:reads=0;$script:admin=$true
function Assert-Fixture($condition,$name){if(!$condition){throw $name};Write-Output ('PASS '+$name)}
function Get-RemediatorService {
 $script:reads++
 if($script:scenario -eq 'cooperative' -and (Test-Path -LiteralPath (Join-Path $work 'stop.request.json'))){$script:running=$false}
 if($script:running){return [pscustomobject]@{url='http://127.0.0.1:5080';mode='Windows';processId=$(if($script:scenario -eq 'changed' -and $script:reads -ge 42){54321}else{12345});startedAt='2026-10-15T00:00:00Z';executablePath='C:\fixture\GpoRemediator.exe'}}
 return $null
}
function Invoke-WebRequest {
 param([switch]$UseBasicParsing,[switch]$UseDefaultCredentials,$Uri,$SessionVariable,$TimeoutSec,$WebSession,$Headers,$Method,$ContentType,$Body)
 if($Uri -like '*/api/session'){
  Set-Variable -Name $SessionVariable -Value 'fixture-session' -Scope 1
  return [pscustomobject]@{Content='{"csrfToken":"fixture-token"}'}
 }
 $script:postCount++
 Assert-Fixture ($UseDefaultCredentials -and $WebSession -eq 'fixture-session' -and $Headers['X-CSRF-Token'] -eq 'fixture-token' -and $Headers.Origin -eq 'http://127.0.0.1:5080') 'native request retains Windows credentials, session, CSRF and exact origin'
 if($script:scenario -in @('denied','busy')){
  $failure=New-Object Exception 'fixture rejection'
  $failure | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{StatusCode=$(if($script:scenario -eq 'busy'){423}else{403})})
  throw $failure
 }
 $script:running=$false
 return [pscustomobject]@{Content='{"action":"stop","accepted":true}'}
}
function Stop-Process {param($Id,[switch]$Force,$ErrorAction);$script:killCount++;if($script:scenario -ne 'emergency' -or $Id -ne 12345){throw 'Unexpected process termination'};$script:running=$false}
function Start-Sleep {param($Milliseconds)}
function New-Object {
 param([Parameter(Position=0)]$TypeName,[Parameter(Position=1)]$ArgumentList)
 if($TypeName -eq 'Security.Principal.WindowsPrincipal'){
  $principal=[pscustomobject]@{};$principal|Add-Member -MemberType ScriptMethod -Name IsInRole -Value {param($role);return $script:admin};return $principal
 }
 Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
}
try{
 $result=Invoke-RemediatorServiceAction -Action stop
 Assert-Fixture ($result.accepted -and !(Test-Path -LiteralPath (Join-Path $work 'stop.request.json'))) 'accepted stop does not recreate a marker already consumed by launcher'
 foreach($scenario in @('denied','busy')){
  $script:running=$true;$script:scenario=$scenario
  $message='';try{Invoke-RemediatorServiceAction -Action stop | Out-Null}catch{$message=$_.Exception.Message}
  Assert-Fixture ($message -match 'denied|blocked' -and $script:killCount -eq 0 -and !(Test-Path -LiteralPath (Join-Path $work 'stop.request.json'))) ($scenario+' stop is reported without force-kill or stop marker')
 }
 # Keep the production route aligned with the tested native-client security contract.
 $program=Get-Content -LiteralPath (Join-Path $repo 'backend\Program.cs') -Raw
 $start=$program.IndexOf('app.MapPost("/api/service/{action}"')
 $end=$program.IndexOf('string GpoToken',$start)
 $route=$program.Substring($start,$end-$start)
 Assert-Fixture ($route.Contains('new OperatorBootstrap()') -and $route.Contains('gate.BeginMaintenance(') -and $route.Contains('File.WriteAllText(stopMarker')) 'production lifecycle route retains authenticated bootstrap, idle-operation gate and persisted stop marker'
 $script:admin=$false;$message='';try{Stop-RemediatorEmergency}catch{$message=$_.Exception.Message}
 Assert-Fixture ($message -match 'Administrator' -and $script:killCount -eq 0 -and !(Test-Path -LiteralPath (Join-Path $work 'stop.request.json'))) 'emergency stop rejects a non-elevated caller without state changes'
 $script:admin=$true;$script:scenario='cooperative';Stop-RemediatorEmergency
 Assert-Fixture (!$script:running -and $script:killCount -eq 0) 'emergency marker lets healthy supervisor stop without process termination'
 Remove-Item -LiteralPath (Join-Path $work 'stop.request.json') -Force
 $script:running=$true;$script:reads=0;$script:scenario='changed';$message='';try{Stop-RemediatorEmergency}catch{$message=$_.Exception.Message}
 Assert-Fixture ($message -match 'changed' -and $script:killCount -eq 0) 'emergency stop refuses a changed registered process'
 $script:running=$true;$script:reads=0;$script:scenario='emergency';Stop-RemediatorEmergency
 Assert-Fixture (!$script:running -and $script:killCount -eq 1 -and (Test-Path -LiteralPath (Join-Path $work 'stop.request.json'))) 'explicit emergency stop terminates only revalidated fixture runtime and preserves supervisor stop marker'
}finally{
 $env:ProgramData=$originalProgramData
 $full=[IO.Path]::GetFullPath($sandbox);$allowed=[IO.Path]::GetFullPath((Join-Path $repo 'work'))+'\'
 if(!$full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture cleanup escaped workspace'}
 Remove-Item -LiteralPath $full -Recurse -Force
}
