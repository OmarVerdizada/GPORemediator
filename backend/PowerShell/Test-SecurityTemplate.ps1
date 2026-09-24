$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'SecurityTemplate.psm1') -Force
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

$fixture = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
; preserve this comment and unrelated privilege
SeBackupPrivilege = *S-1-5-32-544
SeNetworkLogonRight = *S-1-5-32-544
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
[System Access]
MinimumPasswordAge = 2
'@
$edited = Set-SecurityTemplateValue $fixture 'Privilege Rights' 'SeNetworkLogonRight' '*S-1-5-11,*S-1-5-32-544'
Assert-True ((Get-TemplateEntry $edited 'Privilege Rights' 'SeNetworkLogonRight') -eq '*S-1-5-11,*S-1-5-32-544') 'User right was not updated.'
Assert-True ((Get-TemplateEntry $edited 'Privilege Rights' 'SeBackupPrivilege') -eq '*S-1-5-32-544') 'Unrelated right changed.'
Assert-True ((Get-TemplateEntry $edited 'System Access' 'MinimumPasswordAge') -eq '2') 'Unrelated section changed.'
Assert-True ($edited.Contains('; preserve this comment and unrelated privilege')) 'Comment was lost.'
Assert-True ($edited.Contains('MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1')) 'Unrelated registry line changed.'
$new = Set-SecurityTemplateValue '' 'Privilege Rights' 'SeNetworkLogonRight' '*S-1-5-11'
Assert-True ((Get-TemplateEntry $new 'Unicode' 'Unicode') -eq 'yes') 'Missing Unicode header.'
Assert-True ((Get-TemplateEntry $new 'Version' 'signature') -eq '"$CHICAGO$"') 'Missing template signature.'
$security = Set-SecurityTemplateValue $fixture 'Registry Values' 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse' '4,1'
Assert-True ((Get-TemplateEntry $security 'Registry Values' 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse') -eq '4,1') 'Security DWORD encoding invalid.'
$duplicateRejected = $false
try { $null = Set-TemplateEntry "[Privilege Rights]`nSeNetworkLogonRight=one`nSeNetworkLogonRight=two" 'Privilege Rights' 'SeNetworkLogonRight' 'three' }
catch { $duplicateRejected = $true }
Assert-True $duplicateRejected 'Duplicate setting should fail closed.'
$injectionRejected = $false
try { $null = Set-TemplateEntry '' 'Privilege Rights' 'SeNetworkLogonRight' "*S-1-5-11`nSeDebugPrivilege=*S-1-1-0" }
catch { $injectionRejected = $true }
Assert-True $injectionRejected 'Newline injection should fail closed.'
$extension=Add-SecurityExtension ''
Assert-True ($extension -eq '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]') 'Security extension metadata invalid.'
Assert-True ((Add-SecurityExtension $extension) -eq $extension) 'Security extension addition must be idempotent.'
$other='[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957D-509E-11D1-A7CC-0000F87571E3}]'
Assert-True ((Add-SecurityExtension $other).Contains($other)) 'Unrelated CSE metadata was lost.'
Assert-True ((Get-NextComputerVersion 65538) -eq 65539) 'User version must be preserved.'
Assert-True ((Get-NextComputerVersion 131071) -eq 65537) 'Computer version overflow must preserve user version and avoid zero.'
Assert-True ((Get-AdWindowsProfile 8192 'Windows Server 2022') -eq 'DomainController') 'SERVER_TRUST_ACCOUNT must override an alleged MemberServer role.'
Assert-True ((Get-AdWindowsProfile 4096 'Windows Server 2022') -eq 'MemberServer') 'Member server role classification failed.'
Assert-True ((Get-AdWindowsProfile 4096 'Windows 11 Enterprise') -eq 'Workstation') 'Workstation classification failed.'
$unknownRejected=$false
try { $null=Get-AdWindowsProfile 4096 '' } catch { $unknownRejected=$true }
Assert-True $unknownRejected 'Missing AD OS inventory must fail closed.'
$testRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\work\windows-provider-tests'))
$testFolder=Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($testFolder)
try {
    $gpt=Join-Path $testFolder 'GPT.INI'; $policy=Join-Path $testFolder 'policy.dat'
    [IO.File]::WriteAllText($gpt,"[General]`r`nVersion=1`r`n",[Text.Encoding]::ASCII)
    [IO.File]::WriteAllText($policy,'Unrelated policy must survive',[Text.Encoding]::Unicode)
    $before=Get-NormalizedGpoContentFingerprint $testFolder
    [IO.File]::WriteAllText($gpt,"[General]`r`nVersion=65538`r`n",[Text.Encoding]::ASCII)
    Assert-True ((Get-NormalizedGpoContentFingerprint $testFolder) -eq $before) 'GPT version-only restore change must not fail content verification.'
    [IO.File]::WriteAllText($policy,'Corrupted unrelated setting',[Text.Encoding]::Unicode)
    Assert-True ((Get-NormalizedGpoContentFingerprint $testFolder) -ne $before) 'Unrelated restored policy corruption must be detected.'
    [IO.File]::WriteAllText($policy,'Unrelated policy must survive',[Text.Encoding]::Unicode)
    [IO.File]::WriteAllText((Join-Path $testFolder 'extra.dat'),'Unexpected file',[Text.Encoding]::ASCII)
    Assert-True ((Get-NormalizedGpoContentFingerprint $testFolder) -ne $before) 'Unexpected file after restore must be detected.'
} finally {
    # Only remove this freshly created, resolved test directory inside the test workspace.
    $resolved=[IO.Path]::GetFullPath($testFolder)
    if (-not $resolved.StartsWith($testRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test cleanup path.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
$tokens=$null; $errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-PolicyOperation.ps1'),[ref]$tokens,[ref]$errors)
Assert-True ($errors.Count -eq 0) 'Main PowerShell adapter has syntax errors.'
'PASS: security template preservation, SID/DWORD entries, duplicate/injection rejection, CSE metadata, version rollover, AD role validation, complete rollback content fingerprint, and PowerShell parser.'
