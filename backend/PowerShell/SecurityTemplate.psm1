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

function Read-GpoTextFile {
    param([string]$Path)
    for($attempt=0;;$attempt++){
        try{return [IO.File]::ReadAllText($Path)}catch{
            $cause=$_.Exception.GetBaseException();$win32=$cause.HResult -band 65535
            if($cause -is [IO.IOException] -and $win32 -in @(2,3,32,33) -and $attempt -lt 3){Start-Sleep -Milliseconds 100;continue}
            if($cause -is [UnauthorizedAccessException]){throw 'GPO_FILE_ACCESS_DENIED|Read access to a required GPO file was denied. Check SYSVOL permissions on the selected DC.'}
            throw ('GPO_FILE_READ_FAILED|A required GPO file could not be read on the selected DC. Native error '+$win32+'. Check SYSVOL availability and file sharing/locks, then re-verify.')
        }
    }
}
function Get-RestoreTemplateText {
    param([string]$Path)
    # Import-GPO can reorder SID sets and remove empty lines. Unknown syntax
    # stays byte-compared; do not reinterpret arbitrary INF data as equivalent.
    try {
        $bytes=[IO.File]::ReadAllBytes($Path)
        # MS-GPSB requires UTF-16LE with BOM. Other encodings remain byte data.
        if($bytes.Length -lt 2 -or $bytes.Length -gt 8388608 -or $bytes[0] -ne 255 -or $bytes[1] -ne 254){return $null}
        $text=([Text.UnicodeEncoding]::new($false,$false,$true)).GetString($bytes,2,$bytes.Length-2)
        if($text.Contains([char]0)){return $null}
        $lines=[Collections.Generic.List[string]]::new();$rights=@{};$inside=$false;$section='';$metadata=@{};$target=$lines
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($line in ($text -split '\r\n|\n|\r')){
            if([string]::IsNullOrWhiteSpace($line)){continue}
            if($line -match '^\s*\[([^\]]+)\]\s*$'){
                $section=$Matches[1];if($section -cne $section.Trim() -or !$seen.Add($section)){return $null}
                $inside=$section -ieq 'Privilege Rights'
                if($inside){$target=$null}
                elseif($section -iin @('Unicode','Version')){$key=$section.ToUpperInvariant();$metadata[$key]=[Collections.Generic.List[string]]::new();$target=$metadata[$key];$target.Add($line)}
                else{$target=$lines;$target.Add($line)}
                continue
            }
            if($line -match '^\s*;'){continue}
            if(!$section -or $line -notmatch '=' -or $line.EndsWith('\') -or ([regex]::Matches($line,'"').Count % 2)){return $null}
            if(!$inside){$target.Add($line);continue}
            if($line -cmatch '[^\x00-\x7F]'){return $null}
            if($line -notmatch '^\s*(Se[A-Za-z0-9]+)\s*=\s*(.*)$'){return $null}
            $key=$Matches[1].ToUpperInvariant();$raw=$Matches[2];if($rights.ContainsKey($key)){return $null}
            $sids=@()
            if(![string]::IsNullOrWhiteSpace($raw)){
                foreach($part in ($raw -split ',')){
                    if($part.Trim() -notmatch '^\*?(S-\d-(?:\d+-){1,14}\d+)$'){return $null}
                    $sids+=([Security.Principal.SecurityIdentifier]$Matches[1]).Value
                }
            }
            $rights[$key]=(@($sids|Sort-Object -Unique) -join ',')
        }
        $result=[Collections.Generic.List[string]]::new()
        foreach($key in @('UNICODE','VERSION')){if($metadata.ContainsKey($key)){foreach($row in $metadata[$key]){$result.Add($row)}}}
        foreach($row in $lines){$result.Add($row)}
        if($rights.Count){$result.Add('[Privilege Rights]');foreach($key in @($rights.Keys|Sort-Object)){$result.Add($key+'='+$rights[$key])}}
        return ($result -join "`n")
    }catch{return $null}
}
function Get-NormalizedGpoContentFingerprint {
    param([string]$Directory,[switch]$RestoreComparison)
    $folder=[IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $hashes=[Collections.Generic.List[string]]::new()
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $entries=@(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop)
        $files=[Collections.Generic.List[object]]::new()
        while($entries.Count){
            $next=@()
            foreach($entry in $entries){
                if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'GPO_CONTENT_LINK|GPO content cannot redirect through a file or directory link.'}
                if($entry.PSIsContainer){$next+=@(Get-ChildItem -LiteralPath $entry.FullName -Force -ErrorAction Stop)}else{$files.Add($entry)}
            }
            $entries=$next
        }
        foreach ($file in ($files | Sort-Object FullName)) {
            $relative=$file.FullName.Substring($folder.Length).ToLowerInvariant()
            if ($relative -eq '\gpt.ini') {
                $normalized=Set-TemplateEntry (Read-GpoTextFile $file.FullName) 'General' 'Version' '0'
                $hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-','')
            } elseif($RestoreComparison -and $relative -eq '\machine\microsoft\windows nt\secedit\gpttmpl.inf' -and $null -ne ($restoreText=Get-RestoreTemplateText $file.FullName)) {
                $hash='restore-sid-set-v1:'+([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($restoreText))).Replace('-',''))
            } else { $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
            $hashes.Add($relative+':'+$hash)
        }
        return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($hashes -join '|')))).Replace('-','')
    } finally { $sha.Dispose() }
}

Export-ModuleMember -Function Get-TemplateEntry, Set-TemplateEntry, Set-SecurityTemplateValue, Add-SecurityExtension, Add-AuditExtension, Get-NextComputerVersion, Read-GpoTextFile, Get-NormalizedGpoContentFingerprint
