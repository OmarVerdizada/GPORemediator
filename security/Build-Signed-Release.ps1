# The PowerShell source must be signed BEFORE build, because scripts are compiled as embedded resources.
param(
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Thumbprint,
 [string]$Source=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
 [string]$TimestampServer=''
)
$ErrorActionPreference='Stop'
if(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core'){throw 'This release build requires Windows.'}
$Source=(Resolve-Path -LiteralPath $Source).Path
$cert=@(Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {$_.Thumbprint -eq $Thumbprint -and $_.HasPrivateKey}) | Select-Object -First 1
if(!$cert){throw 'Matching code-signing certificate with private key not found.'}
$cert=$cert[0]
if(-not ($cert.EnhancedKeyUsageList|Where-Object{$_.ObjectId -eq '1.3.6.1.5.5.7.3.3'})){throw 'Certificate lacks Code Signing extended key usage.'}
function Sign-File([string]$path){
 $args=@{FilePath=$path;Certificate=$cert;HashAlgorithm='SHA256'}
 if($TimestampServer){$args.TimestampServer=$TimestampServer}
 $signed=Set-AuthenticodeSignature @args
 if($signed.Status -ne 'Valid'){throw "Signature verification failed for $path : $($signed.Status)"}
}
foreach($file in @('Invoke-GpoWorkflow.ps1','GpoWorkflow.Worker.ps1','SecurityTemplate.psm1')){
 Sign-File (Join-Path $Source ('backend\PowerShell\'+$file))
}
& (Join-Path $Source 'Build-Portable.ps1')
if($LASTEXITCODE -ne 0){throw 'Portable build failed.'}
$runtime=Join-Path $Source 'runtime'
Sign-File (Join-Path $runtime 'GpoRemediator.exe')
$archive=Join-Path $Source 'release\GpoRemediator-runtime-win-x64.zip'
$stage=Join-Path $Source 'release\GpoRemediator-runtime-win-x64.signed-stage.zip'
try{
 if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Force}
 Compress-Archive -Path (Join-Path $runtime '*') -DestinationPath $stage -CompressionLevel Optimal
 Move-Item -LiteralPath $stage -Destination $archive -Force
 (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash | Set-Content -LiteralPath ($archive+'.sha256') -Encoding ASCII -NoNewline
}finally{if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Force}}
Write-Host 'Signed runtime created. Distribute only through an approved channel with pinned signer certificate and verify signatures on deployment.' -ForegroundColor Green
