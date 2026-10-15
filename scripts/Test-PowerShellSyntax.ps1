$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$paths=@(& git -C $repo ls-files --cached --others --exclude-standard '*.ps1' '*.psm1')
foreach($relative in @($paths|Sort-Object -Unique)){
 $tokens=$null;$errors=$null
 $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $relative),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($relative+': '+($errors|Out-String))}
}
Write-Output ('PASS Windows PowerShell 5.1 syntax: '+@($paths|Sort-Object -Unique).Count+' source scripts/modules; none executed.')
