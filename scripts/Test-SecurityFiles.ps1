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
$legacy=Join-Path $backup 'GpoWorkflow'
$null=New-Item -ItemType Directory -Path $legacy
$legacyFile=Join-Path $legacy 'manifest.json'
[IO.File]::WriteAllText($legacyFile,'{"fixture":true}')
Initialize-ProtectedDirectory -Path $legacy
$custom=Join-Path $backup 'custom-acl'
$null=New-Item -ItemType Directory -Path $custom
Initialize-ProtectedDirectory -Path $custom
$customAcl=(Get-Item -LiteralPath $custom).GetAccessControl()
$customAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($delegateSid,'Read','Allow'))
(Get-Item -LiteralPath $custom).SetAccessControl($customAcl)
$customBefore=$customAcl.Sddl
$acl=(Get-Item -LiteralPath $file).GetAccessControl()
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'FullControl','Allow'))
(Get-Item -LiteralPath $file).SetAccessControl($acl)
Initialize-ProtectedDirectory -Path $protected -PreserveAclPaths @($backup)
Initialize-ProtectedDirectory -Path $backup -PreserveAclPaths @($backup)
# Exercise the actual Control Panel and launcher startup calls, not just the
# helper in isolation. Neither test starts WPF, a backend, or touches ProgramData.
$stateRoot=$protected
foreach($entry in @('Control-Panel.ps1','GpoRemediator.ps1')){
    $tokens=$null;$errors=$null
    $entryAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot -Parent) $entry),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors|Out-String)}
    if($entry -eq 'Control-Panel.ps1'){
        $call=$entryAst.Find({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Initialize-RemediatorState'},$true)
        if(!$call){throw 'Control Panel must use the shared state initializer'}
        . ([scriptblock]::Create($call.Extent.Text))
    }else{
        $fn=$entryAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-SecureState'},$true)
        . ([scriptblock]::Create($fn.Extent.Text));Initialize-SecureState
    }
}
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
foreach($path in @($legacy,$legacyFile)){
    $legacyAcl=(Get-Item -LiteralPath $path).GetAccessControl()
    if($legacyAcl.AreAccessRulesProtected){throw 'Old private backup child still blocks root delegation'}
    if(!@($legacyAcl.GetAccessRules($false,$true,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IdentityReference.Value -eq $delegateSid.Value}).Count){throw 'Delegated root ACE was not inherited by legacy backup child'}
}
if((Get-Item -LiteralPath $custom).GetAccessControl().Sddl -ne $customBefore){throw 'Custom backup ACL was overwritten'}
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
