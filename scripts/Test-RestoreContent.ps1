# Private-file regression for native Import-GPO representation changes. No AD.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'backend/PowerShell/SecurityTemplate.psm1') -Force
$temp=Join-Path $repo ('work/restore-content-'+[guid]::NewGuid().ToString('N'))
function Check($Condition,$Message){if(!$Condition){throw $Message};Write-Output ('PASS '+$Message)}
try{
 $before=Join-Path $temp 'before';$after=Join-Path $temp 'after';$relative='Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
 foreach($root in @($before,$after)){$null=New-Item -ItemType Directory -Force -Path (Split-Path (Join-Path $root $relative) -Parent);[IO.File]::WriteAllText((Join-Path $root 'GPT.INI'),"[General]`r`nVersion=42`r`n");[IO.File]::WriteAllText((Join-Path $root 'opaque.bin'),'keep')}
 $original="[Unicode]`r`nUnicode=yes`r`n`r`n[Privilege Rights]`r`nSeSystemTimePrivilege = *S-1-5-32-544,*S-1-5-19`r`n`r`nSeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20`r`n`r`nSeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6`r`nSeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n"
 $native=$original.Replace('*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6','*S-1-5-6,*S-1-5-20,*S-1-5-19,*S-1-5-32-544').Replace('*S-1-5-32-544,*S-1-5-19,*S-1-5-20','*S-1-5-20,*S-1-5-19,*S-1-5-32-544').Replace('*S-1-5-32-544,*S-1-5-19','*S-1-5-19,*S-1-5-32-544').Replace('*S-1-5-32-544,*S-1-5-11','*S-1-5-11,*S-1-5-32-544').Replace("`r`n`r`n","`r`n")
 $p=Join-Path $after $relative
 [IO.File]::WriteAllText((Join-Path $before $relative),$original,[Text.Encoding]::Unicode);[IO.File]::WriteAllText($p,$native,[Text.Encoding]::Unicode)
 Check ((Get-NormalizedGpoContentFingerprint $before) -cne (Get-NormalizedGpoContentFingerprint $after)) 'legacy content fingerprints retain SID ordering and whitespace for drift guards'
 $saved=Get-NormalizedGpoContentFingerprint $before -RestoreComparison
 Check ($saved -ceq (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'reported four SID-set reorderings and blank-line removal preserve restore identity'
 $version="[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n";$registry="[Registry Values]`r`nMACHINE\Software\Fixture\Keep=4,1`r`n"
 [IO.File]::WriteAllText((Join-Path $before $relative),$original+$registry,[Text.Encoding]::Unicode)
 [IO.File]::WriteAllText($p,$native.Replace($version,'').Replace('[Privilege Rights]',$registry+$version+'[Privilege Rights]'),[Text.Encoding]::Unicode)
 Check ((Get-NormalizedGpoContentFingerprint $before -RestoreComparison) -ceq (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'native Version and Privilege Rights relocation preserves other policy blocks and values'
 [IO.File]::WriteAllText((Join-Path $before $relative),$original,[Text.Encoding]::Unicode)
 [IO.File]::WriteAllText($p,$native.Replace('*S-1-5-11','*S-1-1-0'),[Text.Encoding]::Unicode)
 Check ($saved -cne (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'a different assigned SID remains a restore mismatch'
 [IO.File]::WriteAllText($p,$native.Replace('Revision=1','Revision=2'),[Text.Encoding]::Unicode)
 Check ($saved -cne (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'non-privilege security-template values remain protected'
 [IO.File]::WriteAllText($p,$native,[Text.Encoding]::UTF8);Check ($saved -cne (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'non-native template encoding remains byte-compared instead of proving equivalence'
 [IO.File]::WriteAllText($p,$native,[Text.Encoding]::Unicode)
 [IO.File]::WriteAllText((Join-Path $after 'opaque.bin'),'external change');Check ($saved -cne (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'unrelated binary or script content still blocks restore verification'
 [IO.File]::WriteAllText((Join-Path $after 'opaque.bin'),'keep')
 [IO.File]::WriteAllText($p,$native.Replace('[Version]',"SeNetworkLogonRight = *S-1-1-0`r`n[Version]"),[Text.Encoding]::Unicode)
 Check ($saved -cne (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'ambiguous duplicate user-right assignments cannot be canonicalized into success'
 [IO.File]::WriteAllText($p,$native.Replace('*S-1-5-11','unresolved-name'),[Text.Encoding]::Unicode)
 Check ($saved -cne (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'unknown principal syntax falls back to byte comparison'
 [IO.File]::WriteAllBytes($p,[byte[]]@(255,254,0));Check ($saved -cne (Get-NormalizedGpoContentFingerprint $after -RestoreComparison)) 'invalid UTF-16 input cannot normalize into a successful restore'
}finally{
 $full=[IO.Path]::GetFullPath($temp);$allowed=[IO.Path]::GetFullPath((Join-Path $repo 'work')).TrimEnd('\')+'\'
 if(!$full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup path'}
 if(Test-Path -LiteralPath $full){Remove-Item -LiteralPath $full -Recurse -Force}
}
