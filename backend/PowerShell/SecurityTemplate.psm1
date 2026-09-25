Set-StrictMode -Version Latest

function Get-TemplateEntry {
    param([AllowEmptyString()][string]$Text, [string]$Section, [string]$Key)
    $current = ''; $sections = 0; $found = @()
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            $current = $Matches[1]
            if ($current -ieq $Section) { $sections++ }
        } elseif ($current -ieq $Section -and $line -match '^\s*([^;=][^=]*?)\s*=(.*)$') {
            if ($Matches[1].Trim().Trim('"') -ieq $Key) { $found += $Matches[2].Trim() }
        }
    }
    if ($sections -gt 1 -or $found.Count -gt 1) { throw "TEMPLATE_AMBIGUOUS|Duplicate section or setting in the security template. Review it in GPMC before editing." }
    if ($found.Count -eq 1) { return $found[0] }
    return $null
}

function Set-TemplateEntry {
    param([AllowEmptyString()][string]$Text, [string]$Section, [string]$Key, [AllowEmptyString()][string]$Value)
    if ($Section -match '[\r\n\[\]]' -or $Key -match '[\r\n=]' -or $Value -match '[\r\n]') { throw 'TEMPLATE_INPUT|Invalid template field.' }
    $null = Get-TemplateEntry -Text $Text -Section $Section -Key $Key
    $lines = [Collections.Generic.List[string]]::new()
    if ($Text.Length -gt 0) { $lines.AddRange([string[]]($Text -split '\r?\n')) }
    $current = ''; $sectionStart = -1; $sectionEnd = $lines.Count; $entry = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*\[([^\]]+)\]\s*$') {
            if ($current -ieq $Section) { $sectionEnd = $i; break }
            $current = $Matches[1]
            if ($current -ieq $Section) { $sectionStart = $i }
        } elseif ($current -ieq $Section -and $lines[$i] -match '^\s*([^;=][^=]*?)\s*=(.*)$') {
            if ($Matches[1].Trim().Trim('"') -ieq $Key) { $entry = $i }
        }
    }
    $replacement = $Key + ' = ' + $Value
    if ($entry -ge 0) { $lines[$entry] = $replacement }
    elseif ($sectionStart -ge 0) { $lines.Insert($sectionEnd, $replacement) }
    else { $lines.Add('[' + $Section + ']'); $lines.Add($replacement) }
    return (($lines -join "`r`n").TrimEnd("`r", "`n") + "`r`n")
}

function Set-SecurityTemplateValue {
    param([AllowEmptyString()][string]$Text, [string]$Section, [string]$Key, [string]$Value)
    $result = Set-TemplateEntry $Text $Section $Key $Value
    if ($null -eq (Get-TemplateEntry $result 'Unicode' 'Unicode')) { $result = Set-TemplateEntry $result 'Unicode' 'Unicode' 'yes' }
    if ($null -eq (Get-TemplateEntry $result 'Version' 'signature')) { $result = Set-TemplateEntry $result 'Version' 'signature' '"$CHICAGO$"' }
    if ($null -eq (Get-TemplateEntry $result 'Version' 'Revision')) { $result = Set-TemplateEntry $result 'Version' 'Revision' '1' }
    return $result
}

function Add-ExtensionPair {
    param([AllowEmptyString()][string]$Current,[string]$Cse,[string]$Tool)
    $groups = [regex]::Matches($Current, '\[(?:\{[A-Fa-f0-9-]{36}\})+\]')
    if ((@($groups | ForEach-Object { $_.Value }) -join '') -cne $Current) { throw 'CSE_METADATA_INVALID|Unknown Group Policy extension metadata format; review the GPO manually.' }
    $updated = @(); $present = $false
    foreach ($group in $groups) {
        $ids = @([regex]::Matches($group.Value, '\{[A-Fa-f0-9-]{36}\}').Value)
        if ($ids[0] -ieq $Cse) {
            $present = $true
            if ($ids -inotcontains $Tool) { $ids += $Tool }
        }
        $updated += '[' + ($ids -join '') + ']'
    }
    if (-not $present) { $updated += '[' + $Cse + $Tool + ']' }
    return (($updated | Sort-Object) -join '')
}

function Add-SecurityExtension {
    param([AllowEmptyString()][string]$Current)
    return Add-ExtensionPair $Current '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
}

function Add-AuditExtension {
    param([AllowEmptyString()][string]$Current)
    # MS-GPAC assigns this pair to the Advanced Audit Configuration extension.
    return Add-ExtensionPair $Current '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}' '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}'
}

function Get-NextComputerVersion {
    param([uint32]$Version)
    $low = ($Version -band 65535) + 1
    if ($low -gt 65535) { $low = 1 }
    return [uint32](($Version -band 4294901760L) -bor $low)
}

function Get-NormalizedGpoContentFingerprint {
    param([string]$Directory)
    $folder=[IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $hashes=[Collections.Generic.List[string]]::new()
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        foreach ($file in (Get-ChildItem -LiteralPath $folder -Recurse -File | Sort-Object FullName)) {
            $relative=$file.FullName.Substring($folder.Length).ToLowerInvariant()
            if ($relative -eq '\gpt.ini') {
                $normalized=Set-TemplateEntry ([IO.File]::ReadAllText($file.FullName)) 'General' 'Version' '0'
                $hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-','')
            } else { $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
            $hashes.Add($relative+':'+$hash)
        }
        return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($hashes -join '|')))).Replace('-','')
    } finally { $sha.Dispose() }
}

function Get-AdWindowsProfile {
    param([int]$UserAccountControl,[string]$OperatingSystem)
    if (($UserAccountControl -band 8192) -ne 0) { return 'DomainController' }
    if ($OperatingSystem -match '^Windows Server ') { return 'MemberServer' }
    if ($OperatingSystem -match '^Windows ') { return 'Workstation' }
    throw 'TARGET_OS_UNKNOWN|AD does not identify a supported Windows operating system. Correct AD inventory before proceeding.'
}

Export-ModuleMember -Function Get-TemplateEntry, Set-TemplateEntry, Set-SecurityTemplateValue, Add-SecurityExtension, Add-AuditExtension, Get-NextComputerVersion, Get-NormalizedGpoContentFingerprint, Get-AdWindowsProfile
