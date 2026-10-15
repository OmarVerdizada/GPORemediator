$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Tooling.ps1')
$sdk=Find-Dotnet
$json=& $sdk list (Join-Path $PSScriptRoot '../backend/GpoRemediator.csproj') package --vulnerable --include-transitive --format json
if($LASTEXITCODE -ne 0){throw 'Dependency query failed'}
$audit=($json -join "`n")|ConvertFrom-Json
if($audit.problems -or !$audit.projects){throw 'Dependency query incomplete; no clean advisory result can be claimed'}
$vulnerable=@(foreach($project in $audit.projects){foreach($framework in $project.frameworks){@($framework.topLevelPackages)+@($framework.transitivePackages)|Where-Object{$_ -and $_.vulnerabilities}}})
$json|Write-Output
if($vulnerable.Count){throw 'Vulnerable dependencies require review'}
Write-Output 'PASS complete dependency advisory response with no reported vulnerable package'
