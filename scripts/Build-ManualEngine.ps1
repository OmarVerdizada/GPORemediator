# Export the actual worker's function dependency closure as inspectable text.
# This build never invokes those functions or contacts a domain.
param([switch]$Check)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$files=@('backend/PowerShell/GpoWorkflow.Worker.ps1','backend/PowerShell/SecurityTemplate.psm1')
$functions=@{}
foreach($file in $files){
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $file),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 foreach($fn in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){$functions[$fn.Name]=$fn}
}
$selected=@{}
function Include-Function([string]$Name){
 if($selected.ContainsKey($Name)){return}
 $fn=$functions[$Name];if(!$fn){throw ('Missing worker function: '+$Name)}
 $selected[$Name]=$fn
 foreach($call in $fn.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)){
  $dependency=$call.GetCommandName();if($dependency -and $functions.ContainsKey($dependency)){Include-Function $dependency}
 }
}
foreach($name in @('Write-Mapping','Mapping-Display','Validate-Selection','Fingerprint','Selected-Link','Assert-VersionSync','Run-Directory','Save-Manifest')){Include-Function $name}
$text=(@($selected.Keys|Sort-Object|ForEach-Object{$selected[$_].Extent.Text.Replace("`r`n","`n")}) -join "`n`n")
$template=[IO.File]::ReadAllText((Join-Path $repo 'backend/PowerShell/ManualGpo.Template.ps1')).Replace("`r`n","`n")
$mappings=Get-Content -LiteralPath (Join-Path $repo 'backend/data/gpo-production-mappings.json') -Raw|ConvertFrom-Json
$payload=[ordered]@{functions=$text;template=$template;functionNames=@($selected.Keys|Sort-Object);mappings=@($mappings.mappings);userRightProbe=$functions['UserRight-ProbeSource'].Extent.Text}
$output="/* Generated from the production PowerShell worker. Run scripts/Build-ManualEngine.ps1; do not edit. */`nwindow.GpoManualEngine=Object.freeze("+($payload|ConvertTo-Json -Depth 5 -Compress)+");`n"
$path=Join-Path $repo 'frontend/source/manual-engine.js'
if($Check){if(!(Test-Path -LiteralPath $path) -or [IO.File]::ReadAllText($path).Replace("`r`n","`n") -cne $output){throw 'Manual PowerShell engine is stale. Run scripts/Build-ManualEngine.ps1.'}}
else{[IO.File]::WriteAllText($path,$output,(New-Object Text.UTF8Encoding($false)))}
Write-Output ('Manual engine: '+$selected.Count+' shared production functions; '+$(if($Check){'current'}else{'generated'})+'. No domain commands executed.')
