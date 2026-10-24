# Windows PowerShell 5.1-compatible; no fallback to an unprotected state store.
function Initialize-RemediatorState {
    param([Parameter(Mandatory=$true)][string]$Root)
    $backup=Join-Path $Root 'Backups'
    Initialize-ProtectedDirectory -Path $Root -PreserveAclPaths @($backup)
    foreach($name in @('Config','State','Data','Recovery','Scripts')) {
        Initialize-ProtectedDirectory -Path (Join-Path $Root $name)
    }
    Initialize-ProtectedDirectory -Path $backup -PreserveAclPaths @($backup)
    Repair-LegacyBackupInheritance -Path $backup
}

function Repair-LegacyBackupInheritance {
    param([Parameter(Mandatory=$true)][string]$Path)
    # Older startup code protected every backup child with just owner, SYSTEM,
    # Administrators. Root delegation could not reach those private descendants.
    # Re-enable inheritance only on this exact legacy ACL shape; retain custom
    # grants/denials and never rewrite the administrator-managed repository root.
    foreach($item in @(Get-ChildItem -LiteralPath $Path -Force)){
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Backup repository cannot contain junctions or symbolic links.'}
        $acl=$item.GetAccessControl()
        if($acl.AreAccessRulesProtected){
            $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            $expected=@($owner,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique
            $rules=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
            $legacy=$rules.Count -eq $expected.Count
            foreach($rule in $rules){
                if($rule.IdentityReference.Value -notin $expected -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl){$legacy=$false}
            }
            if($legacy){$acl.SetAccessRuleProtection($false,$true);$item.SetAccessControl($acl)}
        }
        if($item.PSIsContainer){Repair-LegacyBackupInheritance -Path $item.FullName}
    }
}

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
