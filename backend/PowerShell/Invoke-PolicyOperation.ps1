# Windows PowerShell 5.1. The only input is a JSON document on stdin from the server.
# Never turn a payload value into command text or a ScriptBlock.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module (Join-Path $PSScriptRoot 'SecurityTemplate.psm1') -Force

function Stop-Policy([string]$Code, [string]$Message) { throw ($Code + '|' + $Message) }
function Assert-Gpo([string]$Id) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($Id, [ref]$guid)) { Stop-Policy 'GPO_INVALID' 'A GPO GUID is required.' }
    if ($guid.ToString() -in @('31b2f340-016d-11d2-945f-00c04fb984f9', '6ac1786c-016f-11d2-945f-00c04fb984f9')) {
        Stop-Policy 'PROTECTED_GPO' 'Default Domain Policy and Default Domain Controllers Policy cannot be changed by this application.'
    }
    if (@($cfg.approvedGpoIds | Where-Object { [guid]$_ -eq $guid }).Count -ne 1) { Stop-Policy 'GPO_NOT_APPROVED' 'The GPO GUID is not approved in server configuration.' }
    return $guid
}
function Get-ComputerTarget($Target) {
    if ($cfg.allowedHosts -inotcontains $Target.hostname -or $Target.domain -ine $cfg.domain) { Stop-Policy 'TARGET_NOT_APPROVED' 'The host/domain is outside the server allowlist.' }
    $hostname = [string]$Target.hostname
    if ($hostname -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$') { Stop-Policy 'HOST_INVALID' 'Only a DNS hostname is accepted.' }
    # -Filter script block treats the validated hostname as a value, never PowerShell code.
    $computers = @(Get-ADComputer -Filter { DNSHostName -eq $hostname } -Server $cfg.domainController -Properties DNSHostName,OperatingSystem,DistinguishedName,userAccountControl)
    if ($computers.Count -ne 1) { Stop-Policy 'TARGET_UNRESOLVED' 'The approved FQDN did not resolve to exactly one AD computer.' }
    $computer = $computers[0]
    $ou = ($computer.DistinguishedName -split '(?<!\\),', 2)[1]
    if ($cfg.authorizedOus -inotcontains $ou) { Stop-Policy 'OU_NOT_APPROVED' 'The actual computer OU is outside AuthorizedOus; exact OU authorization is required.' }
    # Role never comes from a browser-supplied profile. SERVER_TRUST_ACCOUNT is the AD DC marker.
    $actualProfile=Get-AdWindowsProfile ([int]$computer.userAccountControl) ([string]$computer.OperatingSystem)
    if ([string]$Target.profile -ine 'Auto' -and [string]$Target.profile -ine $actualProfile) { Stop-Policy 'TARGET_ROLE_MISMATCH' ('The selected profile does not match AD. Actual AD role is '+$actualProfile+'. Use Auto discovery or select that exact profile; DC policies cannot use the MemberServer pack.') }
    $result = [ordered]@{ id=$Target.id; hostname=$computer.DNSHostName; domain=$cfg.domain; ou=$ou; operatingSystem=$computer.OperatingSystem; profile=$actualProfile }
    return [pscustomobject]$result
}
function Get-ControlAdapter($Control) {
    if ($Control.policyType -eq 'USER_RIGHTS_ASSIGNMENT' -and $Control.technicalSettingName -eq 'SeNetworkLogonRight') {
        return @{ Kind='SecurityTemplate'; Section='Privilege Rights'; Key='SeNetworkLogonRight'; RsopClass='RSOP_UserPrivilegeRight' }
    }
    $approved = @{
        'LimitBlankPasswordUse' = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
        'EnableLUA' = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        'NoDriveTypeAutoRun' = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        'AutoAdminLogon' = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    }
    $expectedType=$(if ($Control.technicalSettingName -eq 'AutoAdminLogon') { 'String' } else { 'DWord' })
    if (-not $approved.ContainsKey([string]$Control.technicalSettingName) -or $Control.registryKey -ine $approved[[string]$Control.technicalSettingName] -or $Control.registryType -ine $expectedType) {
        Stop-Policy 'ADAPTER_UNSUPPORTED' 'This policy has no reviewed production adapter. Account policy/PSO, preferences, audit, firewall, and services require a separate intentional workflow.'
    }
    if ($Control.policyType -eq 'SECURITY_OPTION' -and $Control.technicalSettingName -in @('LimitBlankPasswordUse','EnableLUA')) {
        return @{ Kind='SecurityTemplate'; Section='Registry Values'; Key=($Control.registryKey -replace '^HKLM','MACHINE') + '\' + $Control.technicalSettingName; RsopClass='RSOP_RegistryValue' }
    }
    if ($Control.policyType -in @('REGISTRY_POLICY','ADMINISTRATIVE_TEMPLATE') -and $Control.technicalSettingName -in @('NoDriveTypeAutoRun','AutoAdminLogon')) {
        return @{ Kind='Registry'; RsopClass='RSOP_RegistryPolicySetting' }
    }
    Stop-Policy 'ADAPTER_UNSUPPORTED' 'The control type does not match its reviewed production adapter.'
}
function Get-GpoDirectory([string]$Id) {
    $guid = ([guid]$Id).ToString('B').ToUpperInvariant()
    return '\\' + $cfg.domainController + '\SYSVOL\' + $cfg.domain + '\Policies\' + $guid
}
function Get-GpoAd([string]$Id) {
    $dn = 'CN=' + ([guid]$Id).ToString('B').ToUpperInvariant() + ',CN=Policies,CN=System,' + $script:domainDn
    return Get-ADObject -Identity $dn -Server $cfg.domainController -Properties versionNumber,gPCMachineExtensionNames,gPCWQLFilter,flags,whenChanged
}
function Get-GpoVersion([string]$Id) {
    $ad = Get-GpoAd $Id
    $folder = Get-GpoDirectory $Id
    if (-not (Test-Path -LiteralPath (Join-Path $folder 'GPT.INI'))) { Stop-Policy 'SYSVOL_UNAVAILABLE' 'The GPO GPT.INI is unavailable on the pinned DC. Check DFSR and SYSVOL permissions.' }
    $hashes = [Collections.Generic.List[string]]::new()
    foreach ($file in (Get-ChildItem -LiteralPath $folder -Recurse -File | Sort-Object FullName)) {
        $hashes.Add($file.FullName.Substring($folder.Length) + ':' + (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash)
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($hashes -join '|')))).Replace('-','') }
    finally { $sha.Dispose() }
    return [string]$ad.versionNumber + ':' + $ad.whenChanged.ToUniversalTime().ToString('O') + ':' + $digest
}
function Get-GpoContentFingerprint([string]$Id) {
    # Restore-GPO legitimately assigns a new GPT version. Compare every other SYSVOL byte.
    return Get-NormalizedGpoContentFingerprint (Get-GpoDirectory $Id)
}
function Get-AllGpoLinks([string]$Id) {
    $links = @(); $escaped = [regex]::Escape(([guid]$Id).ToString('B'))
    foreach ($scope in $script:linkScopes) {
        $entries = @([regex]::Matches([string]$scope.gPLink, '\[LDAP://([^;]+);([0-3])\]', 'IgnoreCase'))
        for ($i=0; $i -lt $entries.Count; $i++) {
            if ($entries[$i].Groups[1].Value -match $escaped) {
                $options = [int]$entries[$i].Groups[2].Value
                $links += [pscustomobject]@{ target=[string]$scope.DistinguishedName; order=$i+1; enabled=(($options -band 1) -eq 0); enforced=(($options -band 2) -ne 0) }
            }
        }
    }
    return @($links | Sort-Object target,order)
}
function Get-GpoReference([string]$Id, $Target) {
    $gpo = Get-GPO -Guid ([guid]$Id) -Domain $cfg.domain -Server $cfg.domainController
    $ad = Get-GpoAd $Id
    $permissions = @(Get-GPPermission -Guid ([guid]$Id) -All -Domain $cfg.domain -Server $cfg.domainController)
    $security = @($permissions | Where-Object { $_.Permission -eq 'GpoApply' } | ForEach-Object { [string]$_.Trustee.Sid.Value } | Sort-Object)
    $inheritance = Get-GPInheritance -Target $Target.ou -Domain $cfg.domain -Server $cfg.domainController
    $guid = ([guid]$Id).ToString()
    return [pscustomobject][ordered]@{
        id=$guid; name=$gpo.DisplayName; links=@(Get-AllGpoLinks $Id); securityFiltering=$security
        wmiFilter=$(if ($ad.gPCWQLFilter) { [string]$ad.gPCWQLFilter } else { $null })
        approved=(@($cfg.approvedGpoIds | Where-Object { [guid]$_ -eq [guid]$Id }).Count -eq 1)
        dedicated=($gpo.DisplayName -match '(?i)Remediation'); protected=($guid -in @('31b2f340-016d-11d2-945f-00c04fb984f9','6ac1786c-016f-11d2-945f-00c04fb984f9'))
        inheritance=('OU inheritance blocked: ' + [string]$inheritance.GpoInheritanceBlocked + '; computer disabled: ' + [string](([int]$ad.flags -band 2) -ne 0))
        affectedComputers=$null; domainController=$cfg.domainController; version=(Get-GpoVersion $Id)
    }
}
function Get-GpoValue([string]$Id, $Control) {
    $adapter = Get-ControlAdapter $Control
    if ($adapter.Kind -eq 'Registry') {
        try { $value = Get-GPRegistryValue -Guid ([guid]$Id) -Domain $cfg.domain -Server $cfg.domainController -Key $Control.registryKey -ValueName $Control.technicalSettingName }
        catch {
            if ($_.FullyQualifiedErrorId -match 'ValueNotFound|RegistryValueNotFound|KeyNotFound|RegistryKeyNotFound') { return @() }
            throw
        }
        if ([string]$value.Type -ine $Control.registryType) { Stop-Policy 'REGISTRY_TYPE_MISMATCH' 'The GPO value has an unexpected registry type.' }
        return @([string]$value.Value)
    }
    $path = Join-Path (Get-GpoDirectory $Id) 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $entry = Get-TemplateEntry ([IO.File]::ReadAllText($path)) $adapter.Section $adapter.Key
    if ($null -eq $entry) { return @() }
    if ($Control.policyType -eq 'USER_RIGHTS_ASSIGNMENT') { return @(ConvertTo-Sids @($entry -split ',')) }
    if ($entry -notmatch '^4\s*,\s*(\d+)\s*$') { Stop-Policy 'REGISTRY_TYPE_MISMATCH' 'Security template DWORD value has an unexpected format.' }
    return @([string][uint32]$Matches[1])
}
function ConvertTo-Sids([object[]]$Accounts) {
    foreach ($account in $Accounts) {
        $text = ([string]$account).Trim().TrimStart('*')
        if ($text -eq '') { continue }
        if ($text -match '^S-1-') { ([Security.Principal.SecurityIdentifier]::new($text)).Value }
        else { ([Security.Principal.NTAccount]::new($text)).Translate([Security.Principal.SecurityIdentifier]).Value }
    }
}
function Test-EqualValue([object[]]$Actual, [object[]]$Expected) {
    return ((@($Actual | ForEach-Object { [string]$_ } | Sort-Object -Unique) -join '|') -ceq (@($Expected | ForEach-Object { [string]$_ } | Sort-Object -Unique) -join '|'))
}
function New-Verification([bool]$Success,[string]$Code,[string]$Message,[object[]]$Values,[bool]$Retryable=$false) {
    return @{ success=$Success; code=$Code; message=$Message; actualValue=@($Values | ForEach-Object { [string]$_ }); retryable=$Retryable; domainController=$cfg.domainController }
}
function Get-AppliedDomainGpoIds($Target) {
    # RSOP_GPLink is the authoritative logging-mode view of links that actually
    # participated on the endpoint. appliedOrder > 0 excludes merely linked,
    # disabled, security-filtered, and WMI-filtered links from the selector.
    $session = New-CimSession -ComputerName $Target.hostname -Authentication Kerberos
    try {
        $links = @(Get-CimInstance -CimSession $session -Namespace 'root\rsop\computer' -ClassName 'RSOP_GPLink' |
            Where-Object { $_.enabled -eq $true -and [uint32]$_.appliedOrder -gt 0 } |
            Sort-Object appliedOrder)
        $gpos = @(Get-CimInstance -CimSession $session -Namespace 'root\rsop\computer' -ClassName 'RSOP_GPO')
        $resolved = [Collections.Generic.List[string]]::new()
        foreach ($link in $links) {
            $reference = [string]$link.GPO
            $referenceGuid = [regex]::Match($reference, '\{?([a-fA-F0-9-]{36})\}?')
            $candidate = $null
            foreach ($gpo in $gpos) {
                $idText = [string]$gpo.id
                $guidText = [string]$gpo.guidName
                $gpoGuid = [regex]::Match(($guidText + ' ' + $idText), '\{?([a-fA-F0-9-]{36})\}?')
                $sameGuid = $referenceGuid.Success -and $gpoGuid.Success -and ([guid]$referenceGuid.Groups[1].Value -eq [guid]$gpoGuid.Groups[1].Value)
                $sameReference = ($idText -and $reference.IndexOf($idText, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                    ($guidText -and $reference.IndexOf($guidText, [StringComparison]::OrdinalIgnoreCase) -ge 0)
                if ($sameGuid -or $sameReference) {
                    $candidate = $gpo
                    break
                }
            }
            if ($null -eq $candidate) {
                # Local GPO and provider-specific references can be present in
                # RSoP. Only resolvable domain GPO GUIDs are actionable here.
                continue
            }
            if ($candidate.enabled -ne $true -or $candidate.accessDenied -eq $true -or $candidate.filterAllowed -ne $true) { continue }
            $match = [regex]::Match([string]$candidate.guidName, '\{?([a-fA-F0-9-]{36})\}?')
            if (-not $match.Success) { $match = [regex]::Match([string]$candidate.id, '\{([a-fA-F0-9-]{36})\}') }
            if ($match.Success) { $resolved.Add(([guid]$match.Groups[1].Value).ToString()) }
        }
        return @($resolved | Select-Object -Unique)
    } finally { Remove-CimSession $session }
}
function Get-RsopSetting($Target,$Control) {
    $adapter = Get-ControlAdapter $Control
    $session = New-CimSession -ComputerName $Target.hostname -Authentication Kerberos
    try {
        $settings = @(Get-CimInstance -CimSession $session -Namespace 'root\rsop\computer' -ClassName $adapter.RsopClass)
        if ($Control.policyType -eq 'USER_RIGHTS_ASSIGNMENT') { $matching = @($settings | Where-Object { $_.UserRight -eq $Control.technicalSettingName }) }
        elseif ($Control.policyType -eq 'SECURITY_OPTION') { $matching = @($settings | Where-Object { $_.Path -ieq $adapter.Key }) }
        else {
            $key = $Control.registryKey -replace '^HKLM\\',''
            $matching = @($settings | Where-Object { ($_.registryKey -replace '^(HKLM|HKEY_LOCAL_MACHINE)\\','') -ieq $key -and $_.valueName -ieq $Control.technicalSettingName -and -not $_.deleted })
        }
        $winners = @($matching | Where-Object { $_.precedence -eq 1 })
        if ($winners.Count -ne 1) { return @{ defined=($matching.Count -gt 0); status=$(if ($matching.Count -eq 0) { 'NOT_DEFINED' } else { 'AMBIGUOUS' }); gpoId=$null; value=@() } }
        $winner = $winners[0]
        $match = [regex]::Match([string]$winner.GPOID, '\{([a-fA-F0-9-]{36})\}')
        if (-not $match.Success) { return @{ defined=$true; status='AMBIGUOUS'; gpoId=$null; value=@() } }
        if ($Control.policyType -eq 'USER_RIGHTS_ASSIGNMENT') { $value = @(ConvertTo-Sids $winner.AccountList) }
        elseif ($Control.policyType -eq 'SECURITY_OPTION') {
            if ([int]$winner.Type -ne 4 -or [string]$winner.Data -notmatch '^\d+$') { Stop-Policy 'RSOP_FORMAT_UNKNOWN' 'RSoP security DWORD format is not supported; inspect the endpoint manually.' }
            $value = @([string][uint32]$winner.Data)
        } elseif ($Control.registryType -eq 'String') {
            if ([int]$winner.valueType -ne 1) { Stop-Policy 'RSOP_FORMAT_UNKNOWN' 'RSoP registry string type does not match the catalog.' }
            $value = @([Text.Encoding]::Unicode.GetString([byte[]]$winner.value).TrimEnd([char]0))
        } else {
            if ([int]$winner.valueType -ne 4 -or $winner.value.Length -ne 4) { Stop-Policy 'RSOP_FORMAT_UNKNOWN' 'RSoP registry DWORD format is not supported.' }
            $value = @([string][BitConverter]::ToUInt32([byte[]]$winner.value,0))
        }
        return @{ defined=$true; status='DETECTED'; gpoId=([guid]$match.Groups[1].Value).ToString(); value=$value }
    } finally { Remove-CimSession $session }
}
function Get-EndpointValue($Target,$Control) {
    $null = Get-ControlAdapter $Control
    # Structured values become arguments to a fixed scriptblock. No browser script is executed.
    $result = Invoke-Command -ComputerName $Target.hostname -Authentication Kerberos -ScriptBlock {
        param($Type,$RegistryKey,$ValueName,$RegistryType)
        $ErrorActionPreference='Stop'
        if ($Type -eq 'USER_RIGHTS_ASSIGNMENT') {
            $file = Join-Path $env:TEMP ('gpo-remediator-' + [guid]::NewGuid().ToString('N') + '.inf')
            $log = $file + '.log'
            try {
                & "$env:SystemRoot\System32\secedit.exe" /export /mergedpolicy /cfg $file /areas USER_RIGHTS /log $log /quiet | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Endpoint security-policy export failed.' }
                $line = @([IO.File]::ReadAllLines($file) | Where-Object { $_ -match '^\s*SeNetworkLogonRight\s*=' })
                if ($line.Count -gt 1) { throw 'Duplicate endpoint user-right assignment.' }
                if ($line.Count -eq 0) { return }
                foreach ($entry in (($line[0] -split '=',2)[1] -split ',')) {
                    $account=$entry.Trim().TrimStart('*')
                    if ($account -match '^S-1-') { ([Security.Principal.SecurityIdentifier]::new($account)).Value }
                    elseif ($account) { ([Security.Principal.NTAccount]::new($account)).Translate([Security.Principal.SecurityIdentifier]).Value }
                }
            } finally {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
                if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
            }
        } else {
            $path=$RegistryKey -replace '^HKLM\\',''
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
            try {
                $key=$base.OpenSubKey($path,$false)
                if ($null -eq $key) { return }
                try {
                    if ($key.GetValueNames() -inotcontains $ValueName) { return }
                    if ([string]$key.GetValueKind($ValueName) -ine $RegistryType) { throw 'Unexpected endpoint registry type.' }
                    $value=$key.GetValue($ValueName)
                    if ($RegistryType -eq 'String') { [string]$value }
                    else { [string][BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$value),0) }
                } finally { $key.Dispose() }
            } finally { $base.Dispose() }
        }
    } -ArgumentList $Control.policyType,$Control.registryKey,$Control.technicalSettingName,$Control.registryType
    return @($result | ForEach-Object { [string]$_ })
}
function Assert-GpoVersion([string]$Id,[string]$Expected) {
    if (-not $Expected -or (Get-GpoVersion $Id) -cne $Expected) { Stop-Policy 'GPO_CHANGED' 'GPO contents/version changed since the approved preview or backup. Analyze and preview again; automatic restore of later edits is blocked.' }
}
function Use-GpoLock([string]$Id,[scriptblock]$Action) {
    $directory=Join-Path $cfg.backupPath 'locks'
    $null=[IO.Directory]::CreateDirectory($directory)
    try { $handle=[IO.File]::Open((Join-Path $directory (([guid]$Id).ToString()+'.lock')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
    catch { Stop-Policy 'GPO_BUSY' 'Another remediation process holds the local GPO lock. Retry after that job finishes.' }
    try { & $Action } finally { $handle.Dispose() }
}
function Write-AtomicText([string]$Path,[string]$Text,[Text.Encoding]$Encoding) {
    $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $temporary=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllText($temporary,$Text,$Encoding)
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary,$Path,$null) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
function Set-GpoSecurityValue($Gpo,$Control,[object[]]$Value) {
    $adapter=Get-ControlAdapter $Control
    $ad=Get-GpoAd $Gpo.id
    $folder=Get-GpoDirectory $Gpo.id
    $gptPath=Join-Path $folder 'GPT.INI'
    $gpt=[IO.File]::ReadAllText($gptPath)
    $gptVersion=Get-TemplateEntry $gpt 'General' 'Version'
    $version=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ad.versionNumber),0)
    if ($null -eq $gptVersion -or [uint32]$gptVersion -ne $version) { Stop-Policy 'REPLICATION_PENDING' 'AD and SYSVOL versions differ on the pinned DC. Wait for replication recovery before writing.' }
    $next=Get-NextComputerVersion $version
    $extensions=Add-SecurityExtension ([string]$ad.gPCMachineExtensionNames)
    $path=Join-Path $folder 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    $old=$(if ([IO.File]::Exists($path)) { [IO.File]::ReadAllText($path) } else { '' })
    if ($Control.policyType -eq 'USER_RIGHTS_ASSIGNMENT') {
        $sids=@(ConvertTo-Sids $Value | Sort-Object -Unique)
        if ($sids.Count -eq 0 -or -not (Test-EqualValue $sids $Value)) { Stop-Policy 'SID_REQUIRED' 'Nonempty canonical SID values are required for user-right assignments.' }
        $text=($sids | ForEach-Object { '*'+$_ }) -join ','
    } else {
        if ($Value.Count -ne 1 -or [string]$Value[0] -notmatch '^\d+$') { Stop-Policy 'DWORD_REQUIRED' 'A single decimal DWORD is required.' }
        $text='4,'+[string][uint32]$Value[0]
    }
    $updated=Set-SecurityTemplateValue $old $adapter.Section $adapter.Key $text
    $newGpt=Set-TemplateEntry $gpt 'General' 'Version' ([string]$next)
    Assert-GpoVersion $Gpo.id $Gpo.version
    try {
        Write-AtomicText $path $updated ([Text.Encoding]::Unicode)
        Write-AtomicText $gptPath $newGpt ([Text.Encoding]::ASCII)
        $signed=[BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$next),0)
        Set-ADObject -Identity $ad.DistinguishedName -Server $cfg.domainController -Replace @{ versionNumber=$signed; gPCMachineExtensionNames=$extensions }
    } catch {
        Stop-Policy 'PARTIAL_WRITE_REQUIRES_REVIEW' 'A security-template or AD metadata write failed. Do not retry blindly: inspect AD/SYSVOL versions and recover from the recorded Backup-GPO snapshot in GPMC.'
    }
}
function Get-BackupPath($Data) {
    $root=[IO.Path]::GetFullPath($cfg.backupPath).TrimEnd('\')+'\'
    $path=[IO.Path]::GetFullPath([string]$Data.directory)
    if (-not $path.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { Stop-Policy 'BACKUP_PATH_INVALID' 'Backup is outside the configured backup directory.' }
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { Stop-Policy 'BACKUP_MISSING' 'The recorded full-GPO backup directory is missing.' }
    return $path
}

try {
    $request=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $cfg=$request.configuration; $p=$request.payload
    if (-not (Get-Module -ListAvailable ActiveDirectory)) { Stop-Policy 'RSAT_AD_MISSING' 'Install RSAT ActiveDirectory PowerShell tools on the Windows management host.' }
    if (-not (Get-Module -ListAvailable GroupPolicy)) { Stop-Policy 'RSAT_GPO_MISSING' 'Install Group Policy Management / RSAT GroupPolicy PowerShell tools on the Windows management host.' }
    Import-Module ActiveDirectory
    Import-Module GroupPolicy
    $domain=Get-ADDomain -Identity $cfg.domain -Server $cfg.domainController
    $script:domainDn=$domain.DistinguishedName
    $dc=Get-ADDomainController -Identity $cfg.domainController -Server $cfg.domainController
    if ($dc.IsReadOnly) { Stop-Policy 'READ_ONLY_DC' 'Select a writable domain controller in server configuration.' }
    $script:linkScopes=@()
    # Query every domain and site link for honest impact, including links outside the target OU.
    if ($request.operation -in @('analyze','inspect','verifyScope','preflight')) {
        $script:linkScopes=@(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $script:domainDn -Server $cfg.domainController -Properties gPLink)
        $rootDse=Get-ADRootDSE -Server $cfg.domainController
        $script:linkScopes+=@(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase ('CN=Sites,'+$rootDse.configurationNamingContext) -Server $cfg.domainController -Properties gPLink)
    }
    $data = switch ([string]$request.operation) {
        'environment' {
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
            $backupReady=$false; $backupMessage=''
            try {
                $null=[IO.Directory]::CreateDirectory([string]$cfg.backupPath)
                $probe=Join-Path ([string]$cfg.backupPath) ('.gpo-remediator-readiness-'+[guid]::NewGuid().ToString('N')+'.tmp')
                [IO.File]::WriteAllText($probe,'readiness')
                Remove-Item -LiteralPath $probe -Force
                $backupReady=$true; $backupMessage='Backup directory exists and is writable by the execution identity.'
            } catch { $backupMessage='Backup directory is not writable by the execution identity.' }
            $checks=@(
                @{ id='powershell'; label='Windows PowerShell 5.1'; status='PASS'; message=$PSVersionTable.PSVersion.ToString(); required=$true },
                @{ id='activeDirectory'; label='RSAT ActiveDirectory module'; status='PASS'; message='ActiveDirectory module imported successfully.'; required=$true },
                @{ id='groupPolicy'; label='RSAT GroupPolicy module'; status='PASS'; message='GroupPolicy module imported successfully.'; required=$true },
                @{ id='domain'; label='Active Directory domain'; status='PASS'; message=('Connected to '+$domain.DNSRoot+'.'); required=$true },
                @{ id='domainController'; label='Pinned writable domain controller'; status='PASS'; message=([string]$dc.HostName); required=$true },
                @{ id='backupPath'; label='Backup directory'; status=$(if($backupReady){'PASS'}else{'FAIL'}); message=$backupMessage; required=$true },
                @{ id='identity'; label='Execution identity'; status='PASS'; message=$identity; required=$true }
            )
            @{ mode='WINDOWS'; ready=$backupReady; identity=$identity; domainController=$cfg.domainController; checks=$checks; checkedAt=[DateTime]::UtcNow.ToString('O') }
        }
        'resolveTarget' {
            Get-ComputerTarget $p.target
        }
        'preflight' {
            $target=Get-ComputerTarget $p.target
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            $edit=$false; $warnings=@('Read-only permission estimates cannot prove effective SYSVOL/AD write access. Actual operations remain subject to Windows ACLs.','Link creation is unavailable; an administrator must provision and link approved GPOs.')
            if ($null -ne $p.gpo) {
                $null=Assert-Gpo $p.gpo.id
                $tokens=@($identity.User.Value)+@($identity.Groups | ForEach-Object { $_.Value })
                $perms=@(Get-GPPermission -Guid ([guid]$p.gpo.id) -All -Domain $cfg.domain -Server $cfg.domainController)
                $edit=@($perms | Where-Object { $_.Trustee.Sid.Value -in $tokens -and $_.Permission -in @('GpoEdit','GpoEditDeleteModifySecurity') }).Count -gt 0
                $null=Get-GpoVersion $p.gpo.id
            }
            $verify=$false; $errors=@()
            try {
                $check=Invoke-Command -ComputerName $target.hostname -Authentication Kerberos -ScriptBlock {
                    $ErrorActionPreference='Stop'
                    $null=Get-CimClass -Namespace 'root\rsop\computer' -ClassName RSOP_UserPrivilegeRight
                    [bool](Test-Path -LiteralPath "$env:SystemRoot\System32\secedit.exe")
                }
                $verify=($check -eq $true)
            } catch { $errors+='Endpoint WinRM/Kerberos or RSoP read access unavailable. Delegate endpoint rights and configure the management firewall.' }
            if ($null -ne $p.gpo -and -not $edit) { $errors+='GPMC permissions do not show GpoEdit for this service identity/group token on the selected GUID.' }
            @{ canRead=$true; canEdit=$edit; canLink=$false; canVerify=$verify; identity=$identity.Name; errors=@($errors); warnings=$warnings; domainController=$cfg.domainController }
        }
        'analyze' {
            $target=Get-ComputerTarget $p.target
            if ($p.control.profiles -inotcontains $target.profile) { Stop-Policy 'CONTROL_PROFILE_UNSUPPORTED' 'The control pack does not authorize remediation for the actual AD computer role.' }
            $null=Get-ControlAdapter $p.control
            $gpos=@(); $status='AMBIGUOUS'; $confidence='UNKNOWN'; $winner=$null; $value=@(); $defined=$false
            $message='Endpoint RSoP has not been read yet.'
            try {
                # Do not offer every GPO merely linked to the OU/domain. The
                # selector is built from GPOs that RSoP says were actually
                # applied to this computer during its latest policy cycle.
                $ids=@(Get-AppliedDomainGpoIds $target)
                foreach ($id in $ids) { $gpos += Get-GpoReference $id $target }

                $rsop=Get-RsopSetting $target $p.control
                $status=$rsop.status; $defined=$rsop.defined; $winner=$rsop.gpoId; $value=@($rsop.value)
                if ($status -eq 'DETECTED') {
                    $confidence='HIGH'; $message='Unique precedence=1 setting identified by endpoint RSoP; selectable GPOs are restricted to domain GPOs actually applied to this computer.'
                    if (@($gpos | Where-Object { $_.id -eq $winner }).Count -eq 0) {
                        # The winning setting must remain visible if the provider
                        # reports it but the link association is incomplete/stale.
                        $gpos += Get-GpoReference $winner $target
                    }
                } elseif ($status -eq 'NOT_DEFINED') {
                    $confidence='MEDIUM'; $message='The last endpoint RSoP contains no matching setting. The selector still shows only domain GPOs actually applied to this computer; local policy or stale RSoP may require manual review.'
                }
            } catch {
                $status='AMBIGUOUS'; $confidence='UNKNOWN'; $winner=$null; $gpos=@()
                $message='Source cannot be determined confidently: endpoint RSoP or GPO read access/format is unavailable. No GPO is offered for remediation until real applied-policy discovery succeeds.'
            }
            @{ status=$status; confidence=$confidence; message=$message; target=$target; applicableGpos=@($gpos | Sort-Object id -Unique); winningGpoId=$winner; currentValue=@($value); settingDefined=$defined; analyzedAt=[DateTime]::UtcNow.ToString('O') }
        }
        'inspect' {
            $null=Assert-Gpo $p.gpo.id; $target=Get-ComputerTarget $p.target
            @{ gpo=(Get-GpoReference $p.gpo.id $target); value=@(Get-GpoValue $p.gpo.id $p.control) }
        }
        'backup' {
            $null=Assert-Gpo $p.gpo.id; $target=Get-ComputerTarget $p.target
            if ($p.control.profiles -inotcontains $target.profile) { Stop-Policy 'CONTROL_PROFILE_UNSUPPORTED' 'The control pack does not authorize remediation for the actual AD computer role.' }
            Use-GpoLock $p.gpo.id {
                Assert-GpoVersion $p.gpo.id $p.gpo.version
                if ($p.jobId -notmatch '^[a-zA-Z0-9_-]{1,100}$') { Stop-Policy 'JOB_ID_INVALID' 'Invalid backup job identifier.' }
                $directory=Join-Path $cfg.backupPath $p.jobId
                $null=[IO.Directory]::CreateDirectory($directory)
                $before=@(Get-GpoValue $p.gpo.id $p.control)
                $endpointBefore=@(Get-EndpointValue $target $p.control)
                $contentFingerprint=Get-GpoContentFingerprint $p.gpo.id
                $securityExtensions=[string](Get-GpoAd $p.gpo.id).gPCMachineExtensionNames
                $backup=Backup-GPO -Guid ([guid]$p.gpo.id) -Domain $cfg.domain -Server $cfg.domainController -Path $directory -Comment ('GpoRemediator job '+$p.jobId)
                Assert-GpoVersion $p.gpo.id $p.gpo.version
                $manifest=@{ backupId=$backup.Id.ToString(); directory=$directory; previousValue=$before; target=$target; gpoId=$p.gpo.id; preWriteVersion=$p.gpo.version; endpointPreviousValue=$endpointBefore; contentFingerprint=$contentFingerprint; securityExtensionNames=$securityExtensions }
                $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $cfg.backupPath (([guid]$p.gpo.id).ToString()+'.ready.json')) -Encoding UTF8
                $manifest
            }
        }
        'apply' {
            $null=Assert-Gpo $p.gpo.id
            $adapter=Get-ControlAdapter $p.control
            if (-not (Test-EqualValue $p.value $p.control.expectedValue)) { Stop-Policy 'VALUE_NOT_APPROVED' 'Only the reviewed catalog expected value may be applied.' }
            Use-GpoLock $p.gpo.id {
                Assert-GpoVersion $p.gpo.id $p.gpo.version
                $ready=Join-Path $cfg.backupPath (([guid]$p.gpo.id).ToString()+'.ready.json')
                if (-not (Test-Path -LiteralPath $ready)) { Stop-Policy 'BACKUP_REQUIRED' 'A complete GPO backup is required before writing.' }
                $manifest=Get-Content -Raw -LiteralPath $ready | ConvertFrom-Json
                $null=Get-BackupPath $manifest
                $actualTarget=Get-ComputerTarget $manifest.target
                if ($p.control.profiles -inotcontains $actualTarget.profile) { Stop-Policy 'CONTROL_PROFILE_UNSUPPORTED' 'The control pack does not authorize remediation for the actual AD computer role.' }
                if ($manifest.preWriteVersion -cne $p.gpo.version) { Stop-Policy 'BACKUP_STALE' 'The rollback snapshot does not match the approved GPO version.' }
                if ($adapter.Kind -eq 'Registry') {
                    if ($p.value.Count -ne 1) { Stop-Policy 'REGISTRY_VALUE_REQUIRED' 'A single registry value is required.' }
                    if ($p.control.registryType -eq 'String') { $newValue=[string]$p.value[0] }
                    else {
                        if ([string]$p.value[0] -notmatch '^\d+$') { Stop-Policy 'DWORD_REQUIRED' 'A decimal DWORD value is required.' }
                        $newValue=[uint32]$p.value[0]
                    }
                    Set-GPRegistryValue -Guid ([guid]$p.gpo.id) -Domain $cfg.domain -Server $cfg.domainController -Key $p.control.registryKey -ValueName $p.control.technicalSettingName -Type $p.control.registryType -Value $newValue | Out-Null
                } else { Set-GpoSecurityValue $p.gpo $p.control @($p.value) }
                Remove-Item -LiteralPath $ready -Force
                @{ written=$true; version=(Get-GpoVersion $p.gpo.id) }
            }
        }
        'verifyGpo' {
            $null=Assert-Gpo $p.gpo.id
            $actual=@(Get-GpoValue $p.gpo.id $p.control)
            $ad=Get-GpoAd $p.gpo.id
            $gpt=Get-TemplateEntry ([IO.File]::ReadAllText((Join-Path (Get-GpoDirectory $p.gpo.id) 'GPT.INI'))) 'General' 'Version'
            $adVersion=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ad.versionNumber),0)
            $metadata=$null -ne $gpt -and [uint32]$gpt -eq $adVersion
            if ((Get-ControlAdapter $p.control).Kind -eq 'SecurityTemplate') {
                $metadata=$metadata -and (([string]$ad.gPCMachineExtensionNames).IndexOf('{827D319E-6EAC-11D2-A4EA-00C04F79F83A}',[StringComparison]::OrdinalIgnoreCase) -ge 0)
            }
            $success=(Test-EqualValue $actual $p.expected) -and $metadata
            New-Verification $success $(if($success){'GPO_VALUE_VERIFIED'}else{'GPO_VALUE_OR_METADATA_MISMATCH'}) 'Read-back of the selected GPO, matching AD/SYSVOL version, and required security CSE metadata on the pinned DC.' $actual
        }
        'verifyScope' {
            $null=Assert-Gpo $p.gpo.id; $target=Get-ComputerTarget $p.target
            $current=Get-GpoReference $p.gpo.id $target
            $inheritance=Get-GPInheritance -Target $target.ou -Domain $cfg.domain -Server $cfg.domainController
            $linked=@(@($inheritance.InheritedGpoLinks)+@($inheritance.GpoLinks) | Where-Object { $_.GpoId -eq [guid]$p.gpo.id -and $_.Enabled }).Count -gt 0
            $scopeSame=(($current.links | ConvertTo-Json -Depth 5 -Compress) -ceq ($p.gpo.links | ConvertTo-Json -Depth 5 -Compress)) -and
                (Test-EqualValue $current.securityFiltering $p.gpo.securityFiltering) -and $current.wmiFilter -ceq $p.gpo.wmiFilter -and $current.inheritance -ceq $p.gpo.inheritance
            $enabled=([int](Get-GpoAd $p.gpo.id).flags -band 2) -eq 0
            New-Verification ($linked -and $scopeSame -and $enabled) 'GPO_SCOPE_CHECK' 'GPO links, order, enforcement, filtering, inheritance and computer-enabled state compared with approved preview; effective application is verified separately through RSoP.' @()
        }
        'refresh' {
            $target=Get-ComputerTarget $p.target
            $result=Invoke-Command -ComputerName $target.hostname -Authentication Kerberos -ScriptBlock {
                & "$env:SystemRoot\System32\gpupdate.exe" /target:computer /force /wait:120 | Out-Null
                @{ exitCode=$LASTEXITCODE }
            }
            $success=$result.exitCode -eq 0
            New-Verification $success $(if($success){'POLICY_REFRESH_COMPLETED'}else{'POLICY_REFRESH_PENDING'}) 'Computer policy refresh invoked with a bounded wait; RSoP and endpoint checks determine compliance.' @() (-not $success)
        }
        'verifyRsop' {
            $null=Assert-Gpo $p.gpo.id; $target=Get-ComputerTarget $p.target
            $rsop=Get-RsopSetting $target $p.control
            $success=$rsop.status -eq 'DETECTED' -and $rsop.gpoId -eq $p.gpo.id -and (Test-EqualValue $rsop.value $p.expected)
            New-Verification $success $(if($success){'RSOP_VERIFIED'}else{'RSOP_REPLICATION_OR_PRECEDENCE_PENDING'}) 'RSoP must report the selected GUID as the unique precedence=1 source and contain the expected value. A mismatch may reflect replication, filtering, or another winning GPO.' @($rsop.value) (-not $success)
        }
        'verifyEndpoint' {
            $target=Get-ComputerTarget $p.target
            $actual=@(Get-EndpointValue $target $p.control); $success=Test-EqualValue $actual $p.expected
            New-Verification $success $(if($success){'ENDPOINT_VERIFIED'}else{'ENDPOINT_PENDING'}) 'Endpoint effective user-right export or 64-bit registry read compared against the expected value.' $actual (-not $success)
        }
        'restart' {
            $target=Get-ComputerTarget $p.target
            # Called exclusively by the job engine after explicit restart authorization.
            Restart-Computer -ComputerName $target.hostname -Protocol WSMan -WsmanAuthentication Kerberos -Force
            New-Verification $false 'RESTART_REQUESTED' 'Restart request sent. Endpoint return and post-restart verification are pending; retry verification after the host starts.' @() $true
        }
        'restore' {
            $null=Assert-Gpo $p.backup.gpoId
            if ($p.backupData.gpoId -ne $p.backup.gpoId) { Stop-Policy 'BACKUP_GPO_MISMATCH' 'Backup metadata does not match the requested GPO GUID.' }
            $directory=Get-BackupPath $p.backupData
            Use-GpoLock $p.backup.gpoId {
                Assert-GpoVersion $p.backup.gpoId $p.backup.postWriteVersion
                Restore-GPO -BackupId ([guid]$p.backupData.backupId) -Path $directory -Domain $cfg.domain -Server $cfg.domainController | Out-Null
                @{ restored=$true }
            }
        }
        'verifyRollback' {
            $null=Assert-Gpo $p.backup.gpoId
            $actual=@(Get-GpoValue $p.backup.gpoId $p.control)
            $contentMatches=(Get-GpoContentFingerprint $p.backup.gpoId) -ceq $p.backupData.contentFingerprint
            $extensionsMatch=([string](Get-GpoAd $p.backup.gpoId).gPCMachineExtensionNames) -ieq $p.backupData.securityExtensionNames
            $success=(Test-EqualValue $actual $p.backup.previousValue) -and $contentMatches -and $extensionsMatch
            New-Verification $success $(if($success){'GPO_ROLLBACK_VERIFIED'}else{'GPO_ROLLBACK_MISMATCH'}) 'Full SYSVOL content was compared with the pre-change fingerprint (normalizing only GPT version), including unrelated policies; computer CSE metadata and the previous setting were also checked. Endpoint convergence is verified separately.' $actual
        }
        default { Stop-Policy 'OPERATION_DENIED' 'Unknown operation.' }
    }
    [Console]::Out.Write((@{ ok=$true; data=$data } | ConvertTo-Json -Depth 40 -Compress))
    exit 0
} catch {
    $message=[string]$_.Exception.Message
    if ($message -match '^([A-Z][A-Z0-9_]+)\|(.+)$') { $code=$Matches[1]; $safe=$Matches[2] }
    else {
        $code='WINDOWS_OPERATION_FAILED'
        $safe='Windows operation failed. Check AD/SYSVOL permissions, writable DC connectivity, WinRM/Kerberos and RSoP availability. No effective-policy success was asserted. Error category: '+[string]$_.CategoryInfo.Category
    }
    [Console]::Out.Write((@{ ok=$false; code=$code; message=$safe } | ConvertTo-Json -Compress))
    exit 1
}
