$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'GpoRemediator.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Launcher parse failed'}
foreach($name in @('Test-ReleaseArchive','Test-RuntimeFileIntegrity')){
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if(!$function){throw "Missing production function $name"}
    # Load only these checked-in functions; never execute the launcher or live AD actions.
    Invoke-Expression $function.Extent.Text
}
$root=Join-Path $repo ('work\runtime-integrity-'+[guid]::NewGuid().ToString('N'))
$runtimeRoot=Join-Path $root 'installed'
$payload=Join-Path $root 'payload'
$null=New-Item -ItemType Directory -Path $runtimeRoot,$payload -Force
$runtimeArchive=Join-Path $root 'payload.zip';$runtimeArchiveHash=$runtimeArchive+'.sha256'
try{
    [IO.File]::WriteAllText((Join-Path $payload 'app.txt'),'verified')
    Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $runtimeArchive
    (Get-FileHash $runtimeArchive -Algorithm SHA256).Hash | Set-Content $runtimeArchiveHash -NoNewline
    Copy-Item -LiteralPath (Join-Path $payload 'app.txt') -Destination $runtimeRoot
    if(!(Test-RuntimeFileIntegrity)){throw 'Valid runtime rejected'}
    [IO.File]::WriteAllText((Join-Path $runtimeRoot 'injected.dll'),'untrusted')
    if(Test-RuntimeFileIntegrity){throw 'Extra runtime file accepted'}
    Remove-Item -LiteralPath (Join-Path $runtimeRoot 'injected.dll')
    [IO.File]::WriteAllText((Join-Path $runtimeRoot 'app.txt'),'changed')
    if(Test-RuntimeFileIntegrity){throw 'Altered runtime file accepted'}
    Remove-Item -LiteralPath (Join-Path $runtimeRoot 'app.txt')
    if(Test-RuntimeFileIntegrity){throw 'Missing runtime file accepted'}
    Write-Output 'PASS production runtime integrity: valid content, additional files, modified files and missing files'
}finally{
    $full=[IO.Path]::GetFullPath($root);$allowed=[IO.Path]::GetFullPath((Join-Path $repo 'work'))+'\'
    if(!$full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup path'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
