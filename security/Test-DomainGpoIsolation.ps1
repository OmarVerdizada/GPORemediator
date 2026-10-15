param([string]$ProjectRoot=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
$source=Get-Content -LiteralPath (Join-Path $ProjectRoot 'backend\Infrastructure\GpoScriptWorkspaces.cs') -Raw
$bootstrap=Get-Content -LiteralPath (Join-Path $ProjectRoot 'backend\PowerShell\Invoke-GpoWorkflow.ps1') -Raw
$executor=Get-Content -LiteralPath (Join-Path $ProjectRoot 'backend\Infrastructure\WindowsPowerShellExecutor.cs') -Raw
$service=Get-Content -LiteralPath (Join-Path $ProjectRoot 'backend\Services\GpoWorkflowService.cs') -Raw
foreach($required in @('GPO_SCRIPT_TAMPERED','DomainPattern','ValidateGpo','PrivateFiles.ProtectTree','FixedTimeEquals','gpoRollback','gpoApply','gpoPreview','gpoRefresh','gpoVerify','ConvertFrom-Json')){
    if(!$source.Contains($required)){throw "Isolation source contract missing: $required"}
}
if(!$bootstrap.Contains('param([string]$RequestJson)')){throw 'Trusted PowerShell transport contract missing.'}
if(!$executor.Contains('GpoScriptWorkspaces.SelectScript')){throw 'Executor is not selecting isolated GPO scripts.'}
if([regex]::Matches($service,[regex]::Escape('GpoScriptWorkspaces.SyncInventory(')).Count -ne 2){throw 'Initial + refresh discovery must each sync all GPO folders.'}
$psTemplate=Join-Path $ProjectRoot 'security\Invoke-Gpo.Template.ps1'
$tokenList=$null;$parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($psTemplate,[ref]$tokenList,[ref]$parseErrors)
if($parseErrors.Count){throw ('Per-GPO launcher template PowerShell parse errors: '+($parseErrors|Out-String))}
Write-Host 'PASS: Domain/GPO source contracts and PowerShell template parser.' -ForegroundColor Green
if(Get-Command dotnet -ErrorAction SilentlyContinue){
    & dotnet build (Join-Path $ProjectRoot 'backend\GpoRemediator.csproj') -c Release --nologo
    if($LASTEXITCODE -ne 0){throw 'Windows/.NET10 backend build failed'}
}else{Write-Warning 'dotnet unavailable; C# build has not been verified.'}
