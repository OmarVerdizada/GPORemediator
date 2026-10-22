$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Tooling.ps1')
$sdk=Find-Dotnet
$project=Join-Path $PSScriptRoot '../backend/GpoRemediator.csproj'
$json=@()
$exitCode=1
$previousErrorActionPreference=$ErrorActionPreference
try {
    # NuGet advisory lookups occasionally fail on a transient connection reset. Retry
    # the read-only query, but still fail closed when no complete response is obtained.
    $ErrorActionPreference='Continue'
    foreach($attempt in 1..3){
        $json=@(& $sdk list $project package --vulnerable --include-transitive --format json 2>&1 | ForEach-Object { "$_" })
        $exitCode=$LASTEXITCODE
        if($exitCode -eq 0){break}
        if($attempt -lt 3){Start-Sleep -Seconds (2*$attempt)}
    }
}
finally {
    $ErrorActionPreference=$previousErrorActionPreference
}
if($exitCode -ne 0){
    $detail=($json -join "`n").Trim()
    if($detail.Length -gt 1000){$detail=$detail.Substring(0,1000)}
    throw "Dependency query failed after 3 attempts. $detail"
}
$audit=($json -join "`n")|ConvertFrom-Json
if($audit.problems -or !$audit.projects){throw 'Dependency query incomplete; no clean advisory result can be claimed'}
$vulnerable=@(foreach($project in $audit.projects){foreach($framework in $project.frameworks){@($framework.topLevelPackages)+@($framework.transitivePackages)|Where-Object{$_ -and $_.vulnerabilities}}})
$json|Write-Output
if($vulnerable.Count){throw 'Vulnerable dependencies require review'}
Write-Output 'PASS complete dependency advisory response with no reported vulnerable package'
