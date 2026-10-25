param([string]$OutputDirectory='work/audit/final')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Tooling.ps1')
$sdk=Find-Dotnet;$python=(Get-Command python -ErrorAction Stop).Source;$node=(Get-Command node -ErrorAction Stop).Source
$out=[IO.Path]::GetFullPath((Join-Path $repo $OutputDirectory));$null=New-Item -ItemType Directory -Path $out -Force
$tests=New-Object 'System.Collections.Generic.List[object]'
function Run-Check([string]$Name,[string]$Executable,[string[]]$Arguments,[string]$Kind='offline regression'){
 $log=Join-Path $out ($Name+'.log');$start=[DateTimeOffset]::UtcNow
 $previousPreference=$ErrorActionPreference
 try{$ErrorActionPreference='Continue'; & $Executable @Arguments *> $log; $code=$LASTEXITCODE}
 finally{$ErrorActionPreference=$previousPreference}
 $tests.Add([pscustomobject]@{name=$Name;kind=$Kind;status=$(if($code -eq 0){'PASS'}else{'FAIL'});exitCode=$code;startedAt=$start.ToString('O');durationSeconds=[math]::Round(([DateTimeOffset]::UtcNow-$start).TotalSeconds,2);log=$OutputDirectory+'/'+$Name+'.log';logSha256=(Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash})
 $tests|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $out 'test-results.json') -Encoding UTF8
 Write-Output ($tests[-1].status+' '+$Name)
}
Push-Location $repo
try{
 Run-Check 'build-portable' 'powershell.exe' @('-NoProfile','-ExecutionPolicy','Bypass','-File','Build-Portable.ps1') 'build/package'
 foreach($project in @('SecurityRegression','WorkflowRegression','WorkspaceRegression','HardeningRegression')){Run-Check $project $sdk @('run','--project',('scripts/'+$project),'-c','Release')}
 foreach($script in @('Test-SecurityFiles','Test-DomainSignIn','Test-EndpointTargeting','Test-SelectionAccess','Test-SysvolDiscovery','Test-RemediationChain','Test-RuntimeIntegrity','Test-GpoMappings','Test-EndpointEvidence','Test-AllEndpointMappings','Test-VerificationLifecycle','Test-PowerShellSyntax','Test-ServiceControl','Test-PolicyDiagnostics','Test-LivePilotSafety','Test-LivePilotFlow','Test-ReleaseInstaller')){
  $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('scripts/'+$script+'.ps1'))
  if($script -eq 'Test-GpoMappings'){$arguments+=@('-ReportPath',($OutputDirectory+'/remediation-controls.json'))}
  if($script -eq 'Test-AllEndpointMappings'){$arguments+=@('-ReportPath',($OutputDirectory+'/endpoint-controls.json'))}
  Run-Check $script 'powershell.exe' $arguments
 }
 Run-Check 'frontend-syntax' $node @('-e',"const fs=require('fs'),cp=require('child_process');for(const x of fs.readdirSync('frontend/source').filter(x=>x.endsWith('.js'))){const r=cp.spawnSync(process.execPath,['--check','frontend/source/'+x],{stdio:'inherit'});if(r.status)process.exit(r.status)}") 'syntax'
 Run-Check 'Test-FineGrainedPassword' 'powershell.exe' @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','scripts/Test-FineGrainedPassword.ps1')
 Run-Check 'Test-EndpointBatching' 'powershell.exe' @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','scripts/Test-EndpointBatching.ps1')
 Run-Check 'Test-PasswordPolicyUi' $node @('scripts/Test-PasswordPolicyUi.cjs')
 Run-Check 'Test-AssuranceScale' $node @('scripts/Test-AssuranceScale.cjs')
 Run-Check 'Test-FrontendPolish' $node @('scripts/Test-FrontendPolish.cjs')
 Run-Check 'stylesheet-build' $node @('scripts/Build-Styles.cjs','--check')
 foreach($test in @('Test-Responsiveness','Test-FrontendSystem','Test-RemediationEvidence','Test-RecipeWorkspace','Test-GuidedRemediation','Test-GpoScopePicker','Test-ControlTargeting','Test-UX-Contract','Test-Studio-UI','Test-EnterpriseCenter','Test-ManualVerification','Test-ValueEditor','Test-ManualRemediation','Test-RecoveryUi','Test-WorkflowUi','Test-EndpointTargetingUi','Test-EnglishThemes')){Run-Check $test $node @('scripts/'+$test+'.cjs')}
 Run-Check 'mapping-generation' $python @('scripts/Build-ProductionMappings.py','--check')
 foreach($test in @('Test-ProductionMappings','Audit-PolicyScopes','Validate-ProductionPackage')){Run-Check $test $python @('scripts/'+$test+'.py')}
 Run-Check 'installed-admx-review' $python @('scripts/Audit-AdmxMappings.py','--output',($OutputDirectory+'/admx-review.json')) 'local ADMX comparison; not policy execution'
 Run-Check 'secret-guard-selftest' $python @('security/Secret-Pattern-Guard.py','--self-test')
 Run-Check 'secret-guard' $python @('security/Secret-Pattern-Guard.py','.')
 Run-Check 'domain-gpo-isolation' 'powershell.exe' @('-NoProfile','-ExecutionPolicy','Bypass','-File','security/Test-DomainGpoIsolation.ps1')
 Run-Check 'dependency-vulnerability-query' 'powershell.exe' @('-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/Test-DependencyAudit.ps1') 'dependency advisory query with completeness/vulnerability checks'
 Run-Check 'built-source-match' 'powershell.exe' @('-NoProfile','-ExecutionPolicy','Bypass','-File','scripts/Test-BuiltSourceMatch.ps1') 'current source/distribution compatibility'
 $failed=@($tests|Where-Object{$_.status -eq 'FAIL'})
 Write-Output ('Audit command checks: '+$tests.Count+' total, '+($tests.Count-$failed.Count)+' passed, '+$failed.Count+' failed. Live AD: NOT RUN.')
 if($failed.Count){exit 1}
}finally{Pop-Location}
