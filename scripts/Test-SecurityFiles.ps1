$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Secure-Files.ps1')
$root=Join-Path (Split-Path $PSScriptRoot -Parent) ('work\security-acl-'+[guid]::NewGuid().ToString('N'))
$protected=Join-Path $root 'protected'
$outside=Join-Path $root 'outside'
$null=New-Item -ItemType Directory -Path (Join-Path $protected 'child'),$outside -Force
$file=Join-Path $protected 'child\secret.txt'
[IO.File]::WriteAllText($file,'fixture')
$acl=(Get-Item -LiteralPath $file).GetAccessControl()
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'FullControl','Allow'))
(Get-Item -LiteralPath $file).SetAccessControl($acl)
Initialize-ProtectedDirectory -Path $protected
foreach($path in @($protected,(Join-Path $protected 'child'),$file)){
    $acl=(Get-Item -LiteralPath $path).GetAccessControl()
    if(!$acl.AreAccessRulesProtected){throw 'State inheritance was not disabled'}
    foreach($rule in $acl.Access){if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0'){throw 'Explicit Everyone access survived'}}
}
$link=Join-Path $protected 'junction'
$null=New-Item -ItemType Junction -Path $link -Target $outside
try{
    try{Initialize-ProtectedDirectory -Path $protected;throw 'Junction was accepted'}catch{if($_.Exception.Message -notmatch 'junction|symbolic'){throw}}
    Write-Output 'PASS private files: explicit broad permissions removed, child files protected, junction rejected'
}finally{
    # Remove the link itself first, then the verified, disposable workspace fixture.
    Remove-Item -LiteralPath $link -Force
    $full=[IO.Path]::GetFullPath($root);$allowed=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))+'\'
    if(!$full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup path'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
