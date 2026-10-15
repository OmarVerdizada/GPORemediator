param([string]$Source=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path)
$ErrorActionPreference='Stop'
$Source=(Resolve-Path -LiteralPath $Source).Path
$project=Join-Path $Source 'scripts\HardeningRegression\SecurityRegression.csproj'
if(!(Test-Path -LiteralPath $project)){throw 'Security regression project not installed. Run Apply-All.cmd first.'}
$dotnet=Get-Command dotnet -ErrorAction Stop
if(-not ((& $dotnet.Source --list-sdks) -match '^10\.')){throw 'Install .NET 10 SDK on approved Windows build host.'}
& $dotnet.Source run --project $project --configuration Release
if($LASTEXITCODE -ne 0){throw 'Security regression tests failed.'}
$python=Get-Command python -ErrorAction Stop
& $python.Source (Join-Path $Source 'security\Secret-Pattern-Guard.py') --self-test
if($LASTEXITCODE -ne 0){throw 'Secret guard self-test failed.'}
& $python.Source (Join-Path $Source 'security\Secret-Pattern-Guard.py') $Source
if($LASTEXITCODE -ne 0){throw 'Secret pattern detected. Inspect repository for accidental secret.'}
Write-Host 'GPO Remediator secure code tests passed.' -ForegroundColor Green
