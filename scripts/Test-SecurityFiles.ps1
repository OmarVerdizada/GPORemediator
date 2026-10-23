$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Secure-Files.ps1')
$root=Join-Path (Split-Path $PSScriptRoot -Parent) ('work\security-acl-'+[guid]::NewGuid().ToString('N'))
$protected=Join-Path $root 'protected'
$outside=Join-Path $root 'outside'
$null=New-Item -ItemType Directory -Path (Join-Path $protected 'child'),$outside -Force
$file=Join-Path $protected 'child\secret.txt'
[IO.File]::WriteAllText($file,'fixture')
$backup=Join-Path $protected 'Backups'
$null=New-Item -ItemType Directory -Path $backup -Force
$delegateSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-111111111-222222222-333333333-4444')
$backupAcl=(Get-Item -LiteralPath $backup).GetAccessControl()
$backupAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($delegateSid,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
(Get-Item -LiteralPath $backup).SetAccessControl($backupAcl)
$acl=(Get-Item -LiteralPath $file).GetAccessControl()
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'FullControl','Allow'))
(Get-Item -LiteralPath $file).SetAccessControl($acl)
Initialize-ProtectedDirectory -Path $protected -PreserveAclPaths @($backup)
Initialize-ProtectedDirectory -Path $backup -PreserveAclPaths @($backup)
foreach($path in @($protected,(Join-Path $protected 'child'),$file)){
    $acl=(Get-Item -LiteralPath $path).GetAccessControl()
    if(!$acl.AreAccessRulesProtected){throw 'State inheritance was not disabled'}
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'Protected file owner differs from the launcher identity'}
    foreach($rule in $acl.Access){if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0'){throw 'Explicit Everyone access survived'}}
}
$delegatedRule=@((Get-Item -LiteralPath $backup).GetAccessControl().Access | Where-Object {
    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $delegateSid.Value -and
    ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -ne 0
})
if($delegatedRule.Count -ne 1){throw 'Delegated backup ACL did not survive secure-state initialization'}
$link=Join-Path $protected 'junction'
$null=New-Item -ItemType Junction -Path $link -Target $outside
try{
    try{Initialize-ProtectedDirectory -Path $protected;throw 'Junction was accepted'}catch{if($_.Exception.Message -notmatch 'junction|symbolic'){throw}}
    Write-Output 'PASS private files: application state protected, delegated backup ACL preserved, junction rejected'
}finally{
    # Remove the link itself first, then the verified, disposable workspace fixture.
    Remove-Item -LiteralPath $link -Force
    $full=[IO.Path]::GetFullPath($root);$allowed=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))+'\'
    if(!$full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup path'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
