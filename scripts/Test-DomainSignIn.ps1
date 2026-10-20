# Execute only the domain SID predicate from the production worker; never contact AD.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'backend/PowerShell/GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Worker syntax invalid'}
$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-DomainExecutionIdentity'},$true)
if(!$definition){throw 'Production domain identity check missing'}
function Fail([string]$Code,[string]$Message){throw ($Code+'|'+$Message)}
. ([scriptblock]::Create($definition.Extent.Text))
Assert-DomainExecutionIdentity ([Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-1101')) 'S-1-5-21-100-200-300'
foreach($sid in @('S-1-5-21-400-500-600-1101','S-1-5-18',$null)){
    $identity=if($sid){[Security.Principal.SecurityIdentifier]::new($sid)}else{$null}
    try{Assert-DomainExecutionIdentity $identity 'S-1-5-21-100-200-300';throw 'Invalid domain account accepted'}catch{if($_.Exception.Message -notmatch '^AD_ACCOUNT_DOMAIN_MISMATCH\|'){throw}}
}
Write-Output 'PASS production domain identity: configured-domain user accepted; other-domain, SYSTEM and missing SID rejected. No AD commands executed.'
