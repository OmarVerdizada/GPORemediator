# Windows PowerShell 5.1-compatible; no fallback to an unprotected state store.
function Initialize-ProtectedDirectory {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string[]]$PreserveAclPaths=@()
    )
    $full=[IO.Path]::GetFullPath($Path)
    $preserved=@($PreserveAclPaths | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') })
    $ancestor=$full
    while($ancestor){
        if(Test-Path -LiteralPath $ancestor){
            $item=Get-Item -LiteralPath $ancestor -Force
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Protected application directories cannot use junctions or symbolic links.'}
        }
        $ancestor=[IO.Path]::GetDirectoryName($ancestor)
    }
    $null=New-Item -ItemType Directory -Path $full -Force
    # Backup repositories are writable by the delegated AD operator. Their ACL is
    # administrator-managed and must survive every launcher restart. The rest of
    # the application state remains private to the launcher identity and SYSTEM.
    if($preserved -icontains $full.TrimEnd('\')){return}
    $directory=Get-Item -LiteralPath $full -Force
    $principals=@([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($principals[0])
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in $principals){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    $directory.SetAccessControl($acl)
    foreach($item in @(Get-ChildItem -LiteralPath $full -Force)){
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Protected application state contains a junction or symbolic link.'}
        if($item.PSIsContainer){Initialize-ProtectedDirectory -Path $item.FullName -PreserveAclPaths $preserved}
        else{
            $fileAcl=[Security.AccessControl.FileSecurity]::new();$fileAcl.SetOwner($principals[0]);$fileAcl.SetAccessRuleProtection($true,$false)
            foreach($sid in $principals){$fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow'))}
            $item.SetAccessControl($fileAcl)
        }
    }
}
