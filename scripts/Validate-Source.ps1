param([switch]$IncludeBrowser)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Push-Location -LiteralPath $repo
try {
    . (Join-Path $PSScriptRoot 'Tooling.ps1')
    $dotnet=Find-Dotnet
    function Check-Exit([string]$Name) { if($LASTEXITCODE -ne 0){throw "$Name failed with exit code $LASTEXITCODE"} }
    & $dotnet build backend/GpoRemediator.csproj -c Release --nologo
    Check-Exit 'Backend build'
    foreach($project in @('SecurityRegression','WorkflowRegression','WorkspaceRegression','HardeningRegression')){
        & $dotnet run --project "scripts/$project" -c Release
        Check-Exit $project
    }
    foreach($script in @('Test-SecurityFiles','Test-DomainSignIn','Test-EndpointTargeting','Test-SelectionAccess','Test-SysvolDiscovery','Test-RuntimeIntegrity','Test-GpoMappings','Test-EndpointEvidence','Test-EndpointDiagnostics','Test-EndpointBatching','Test-AllEndpointMappings','Test-VerificationLifecycle','Test-PowerShellSyntax','Test-ServiceControl')){
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "scripts/$script.ps1"
        Check-Exit $script
    }
    Get-ChildItem frontend/source -Filter *.js | ForEach-Object { & node --check $_.FullName; Check-Exit $_.Name }
    & node scripts/Build-Styles.cjs --check
    Check-Exit 'Styles'
    foreach($test in @('Test-Responsiveness','Test-FrontendSystem','Test-EndpointResultUi','Test-RemediationEvidence','Test-RecipeWorkspace','Test-GuidedRemediation','Test-GpoScopePicker','Test-ControlTargeting','Test-UX-Contract','Test-Studio-UI','Test-EnterpriseCenter','Test-ManualVerification','Test-ValueEditor','Test-ManualRemediation')){
        & node "scripts/$test.cjs"
        Check-Exit $test
    }
    & python scripts/Build-ProductionMappings.py --check
    Check-Exit 'Mapping generation'
    foreach($script in @('scripts/Test-ProductionMappings.py','scripts/Audit-PolicyScopes.py','scripts/Validate-ProductionPackage.py')){
        & python $script
        Check-Exit $script
    }
    & python security/Secret-Pattern-Guard.py --self-test
    Check-Exit 'Secret guard self-test'
    & python security/Secret-Pattern-Guard.py .
    Check-Exit 'Secret guard'
    & (Join-Path $repo 'security/Test-DomainGpoIsolation.ps1')
    if(!(Test-FrontendDistMatchesSource)){throw 'Frontend/dist does not match source. Run Build-Portable.ps1.'}
    if(!(Test-PortableBackendMatchesSource)){throw 'Runtime does not match source. Run Build-Portable.ps1.'}
    if($IncludeBrowser){
        foreach($test in @('Test-RecoveryUi','Test-WorkflowUi','Test-EndpointTargetingUi','Test-EnglishThemes')){
            & node "scripts/$test.cjs"
            Check-Exit $test
        }
    }
    Write-Host 'PASS integrated source, package and regression checks. Live AD pilot remains separate.' -ForegroundColor Green
} finally { Pop-Location }
