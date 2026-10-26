# Runs on the pinned writable DC using the authenticated remoting identity.
param([string]$Operation,$Configuration,$Data,[string]$SecurityModule,[Management.Automation.PSCredential]$EndpointCredential=$null)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue';$InformationPreference='SilentlyContinue'
Set-StrictMode -Version Latest
function Fail([string]$Code,[string]$Message){throw ($Code+'|'+$Message)}
if(!(Get-Module -ListAvailable ActiveDirectory)){Fail 'AD_MODULE_MISSING' 'The selected domain controller does not expose the ActiveDirectory PowerShell module.'}
if(!(Get-Module -ListAvailable GroupPolicy)){Fail 'GROUP_POLICY_MODULE_MISSING' 'The selected domain controller does not expose the GroupPolicy PowerShell module/GPMC feature.'}
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop
Import-Module (New-Module -Name RemediatorSecurityTemplate -ScriptBlock ([scriptblock]::Create($SecurityModule))) -Force
$cfg=$Configuration
function Hash([string]$Text){$sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','')}finally{$sha.Dispose()}}
$domain=Get-ADDomain -Identity $cfg.domain -Server $cfg.domainController
function Assert-DomainExecutionIdentity([Security.Principal.SecurityIdentifier]$UserSid,[string]$DomainSid){
    if(!$UserSid -or !$UserSid.AccountDomainSid -or $UserSid.AccountDomainSid.Value -ine $DomainSid){Fail 'AD_ACCOUNT_DOMAIN_MISMATCH' 'Sign in with a user from the configured AD domain.'}
}
$executionIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
Assert-DomainExecutionIdentity $executionIdentity.User ([string]$domain.DomainSID)
$dc=Get-ADDomainController -Identity $cfg.domainController -Server $cfg.domainController
if($dc.IsReadOnly -or $dc.Domain -ine $domain.DNSRoot -or $env:COMPUTERNAME -ine ($dc.HostName -split '\.')[0]){Fail 'WRITABLE_DC_REQUIRED' 'Execution must be on the selected writable DC in the configured domain.'}
$domainDn=[string]$domain.DistinguishedName
$protectedBuiltInGpoIds=@(
    '31b2f340-016d-11d2-945f-00c04fb984f9',
    '6ac1786c-016f-11d2-945f-00c04fb984f9'
)
function Gpo-Ad([string]$Id){
    $dn='CN='+([guid]$Id).ToString('B').ToUpperInvariant()+',CN=Policies,CN=System,'+$domainDn
    return Get-ADObject -Identity $dn -Server $cfg.domainController -Properties versionNumber,gPCMachineExtensionNames,gPCUserExtensionNames,flags,whenChanged,gPCWQLFilter
}
function Sysvol-Policies {
    # Read the DC's configured active location, including relocated/DFSR SYSVOL.
    # Win32_Share enumeration requires unrelated CIM rights for delegated users.
    $settings=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name SysVol,SysvolReady -ErrorAction Stop
    if([int]$settings.SysvolReady -ne 1){Fail 'SYSVOL_UNAVAILABLE' 'Netlogon reports SYSVOL is not ready on the selected DC.'}
    $root=[Environment]::ExpandEnvironmentVariables([string]$settings.SysVol)
    if($root -notmatch '^[A-Za-z]:\\'){Fail 'SYSVOL_UNAVAILABLE' 'Netlogon SYSVOL must identify a local absolute drive path on the selected DC.'}
    $policies=Join-Path ([IO.Path]::GetFullPath($root)) ($domain.DNSRoot+'\Policies')
    if(!(Test-Path -LiteralPath $policies -PathType Container -ErrorAction Stop)){Fail 'SYSVOL_UNAVAILABLE' ('The configured local SYSVOL Policies directory is unavailable: '+$policies)}
    return $policies
}
function Gpo-Folder([string]$Id){
    return Join-Path (Sysvol-Policies) ([guid]$Id).ToString('B').ToUpperInvariant()
}
function Scopes {
    $items=@(Get-ADOrganizationalUnit -Filter * -Server $cfg.domainController -Properties gPLink -ResultSetSize 5001)
    if($items.Count -gt 5000){Fail 'DIRECTORY_TOO_LARGE' 'More than 5000 OUs exist. Discovery needs a narrower configured domain.'}
    return @([pscustomobject]@{dn=$domainDn;name=$domain.DNSRoot;kind='Domain';rawLinks=(Scope-Links $domainDn)})+@($items|Sort-Object Name|ForEach-Object{[pscustomobject]@{dn=[string]$_.DistinguishedName;name=[string]$_.Name;kind='OU';rawLinks=[string]$_.gPLink}})
}
function Scope([string]$Dn){
    if($Dn -ieq $domainDn){return [pscustomobject]@{dn=$domainDn;name=$domain.DNSRoot;kind='Domain'}}
    $ou=Get-ADOrganizationalUnit -Identity $Dn -Server $cfg.domainController
    if(!$ou.DistinguishedName.EndsWith(','+$domainDn,[StringComparison]::OrdinalIgnoreCase)){Fail 'SCOPE_OUTSIDE_DOMAIN' 'The selected OU is outside the configured domain.'}
    return [pscustomobject]@{dn=[string]$ou.DistinguishedName;name=[string]$ou.Name;kind='OU'}
}
function Verification-User([string]$Identity){
    $value=$Identity.Trim();$sam=$value
    if($value.Contains('\')){$parts=$value.Split('\',2);if($parts[0] -ine [string]$domain.NetBIOSName){Fail 'VERIFICATION_USER_OUTSIDE_DOMAIN' 'The verification user must belong to the configured domain.'};$sam=$parts[1]}
    elseif($value.Contains('@')){$parts=$value.Split('@',2);if($parts[1] -ine [string]$domain.DNSRoot){Fail 'VERIFICATION_USER_OUTSIDE_DOMAIN' 'The verification user must belong to the configured domain.'};$sam=$parts[0]}
    if([string]::IsNullOrWhiteSpace($sam) -or $sam.Length -gt 256 -or $sam.IndexOfAny([char[]]@("`r","`n",[char]0)) -ge 0){Fail 'VERIFICATION_USER_INVALID' 'Enter a valid DOMAIN\\user or user@domain identity.'}
    try{return Get-ADUser -Identity $sam -Server $cfg.domainController -Properties Enabled,SID -ErrorAction Stop}catch{Fail 'VERIFICATION_USER_NOT_FOUND' 'The verification user could not be resolved in the configured domain.'}
}
function Scope-Links([string]$Dn){return [string](Get-ADObject -Identity $Dn -Server $cfg.domainController -Properties gPLink).gPLink}
function All-LinkScopes {
    $configDn=(Get-ADRootDSE -Server $cfg.domainController).configurationNamingContext
    $sites=@(Get-ADObject -Filter {objectClass -eq 'site'} -SearchBase ('CN=Sites,'+$configDn) -Server $cfg.domainController -Properties gPLink -ResultSetSize 1001)
    if($sites.Count -gt 1000){Fail 'DIRECTORY_TOO_LARGE' 'Site-link discovery exceeds the supported limit.'}
    return @(Scopes)+@($sites|ForEach-Object{[pscustomobject]@{dn=[string]$_.DistinguishedName;rawLinks=[string]$_.gPLink}})
}
function Selected-Link([string]$Dn,[string]$Id){
    $links=@((Get-GPInheritance -Target $Dn -Domain $cfg.domain -Server $cfg.domainController).GpoLinks|Where-Object{[guid]$_.GpoId -eq [guid]$Id})
    if($links.Count -gt 1){Fail 'LINK_AMBIGUOUS' 'Multiple direct links refer to this GPO.'}
    if($links.Count -eq 1){$l=$links[0];return [pscustomobject]@{target=$Dn;order=[int]$l.Order;enforced=[bool]$l.Enforced;enabled=[bool]$l.Enabled}}
    return $null
}
function Link([string]$Raw,[string]$Id,[string]$Dn){
    $entries=@([regex]::Matches($Raw,'\[LDAP://([^;]+);([0-3])\]','IgnoreCase'))
    for($i=0;$i -lt $entries.Count;$i++){
        if($entries[$i].Groups[1].Value -match [regex]::Escape(([guid]$Id).ToString('B'))){
            $flags=[int]$entries[$i].Groups[2].Value
            return [pscustomobject]@{target=$Dn;order=0;enforced=(($flags-band 2)-ne 0);enabled=(($flags-band 1)-eq 0)}
        }
    }
    return $null
}
function Gpo-Choice($Gpo){
    $id=$Gpo.Id.ToString();$status=[string]$Gpo.GpoStatus
    # Built-in GPO IDs only add the protected-change acknowledgement. They never
    # constrain which GPO can be selected for a control.
    return @{id=$id;name=[string]$Gpo.DisplayName;protected=($id -in $protectedBuiltInGpoIds);selectable=($status -ne 'AllSettingsDisabled')}
}
function Mapping-Items($Map){return @($Map.items)}
function Desired-Item($Map,$Item,$S){
    if([bool]$Map.requiresInput){return [string]$S.customValue}
    if([bool]$Map.allowValueOverride){return [string]$S.value}
    $values=@($Item.value)
    if(([string]$Item.type).ToUpperInvariant() -eq 'MULTISTRING'){return [string[]]$values}
    if($values.Count -eq 0){return ''}
    return [string]$values[0]
}
function Registry-Type([string]$Type){
    switch($Type.ToUpperInvariant()){'DWORD'{'DWord'}'QWORD'{'QWord'}'MULTISTRING'{'MultiString'}'EXPANDSTRING'{'ExpandString'}'BINARY'{'Binary'}default{'String'}}
}
function Principal-Sid([string]$Name){
    $n=$Name.Trim();$known=@{
      'administrators'='S-1-5-32-544';'guests'='S-1-5-32-546';'remote desktop users'='S-1-5-32-555';
      'authenticated users'='S-1-5-11';'local service'='S-1-5-19';'network service'='S-1-5-20';'service'='S-1-5-6';
      'enterprise domain controllers'='S-1-5-9';'local account'='S-1-5-113';'local account and member of administrators group'='S-1-5-114';
      'window manager\window manager group'='S-1-5-90-0';'nt virtual machine\virtual machines'='S-1-5-83-0';'iis_iusrs'='S-1-5-32-568'
    }
    if($n -match '^\*?(S-\d-(?:\d+-){1,14}\d+)$'){return $Matches[1]}
    if($known.ContainsKey($n.ToLowerInvariant())){return $known[$n.ToLowerInvariant()]}
    try{return ([Security.Principal.NTAccount]$n).Translate([Security.Principal.SecurityIdentifier]).Value}catch{Fail 'PRINCIPAL_RESOLUTION_FAILED' ('Could not resolve policy principal: '+$n)}
}
function Principals-Desired($Values){return ((@($Values)|ForEach-Object{'*'+(Principal-Sid ([string]$_))}) -join ',')}
function Normalize-Principals([AllowNull()][string]$Raw){
    if($null -eq $Raw){return $null};if([string]::IsNullOrWhiteSpace($Raw)){return ''}
    $sids=@();foreach($p in ($Raw -split ',')){if(![string]::IsNullOrWhiteSpace($p)){$sids+=Principal-Sid ($p.Trim().TrimStart('*'))}}
    return (($sids|Sort-Object -Unique)-join ',')
}
function Security-Path([string]$Id){return Join-Path (Gpo-Folder $Id) 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'}
function Audit-Path([string]$Id){return Join-Path (Gpo-Folder $Id) 'Machine\Microsoft\Windows NT\Audit\audit.csv'}
function Csv-Field([AllowNull()][string]$Value){$v=if($null -eq $Value){''}else{$Value};return '"'+$v.Replace('"','""')+'"'}
function Audit-Row([string]$Name,[string]$Guid,[string]$State,[int]$Mask){
    # MS-GPAC permits a quoted Subcategory, but System/GUID/SettingValue are
    # literal tokens. Quoting every field is parseable generic CSV, not GPAC.
    return (',System,'+(Csv-Field $Name)+','+([guid]$Guid).ToString('B')+','+$State+',,'+[string]$Mask)
}
function Audit-CanonicalLines([string[]]$Lines){
    $header='Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    if(!$Lines.Count -or $Lines[0] -cne $header){Fail 'AUDIT_POLICY_INVALID' 'Advanced-audit CSV header is invalid.'}
    $result=New-Object 'System.Collections.Generic.List[string]';$result.Add($header)
    for($index=1;$index -lt $Lines.Count;$index++){
      if([string]::IsNullOrWhiteSpace($Lines[$index])){continue}
      $rows=@(@($header,$Lines[$index])|ConvertFrom-Csv)
      if($rows.Count -ne 1){Fail 'AUDIT_POLICY_INVALID' 'Advanced-audit CSV row could not be parsed.'}
      $row=$rows[0]
      if([string]$row.'Policy Target' -eq 'System'){
        $mask=0;$guid=[guid]::Empty
        if(![guid]::TryParse([string]$row.'Subcategory GUID',[ref]$guid) -or ![int]::TryParse([string]$row.'Setting Value',[ref]$mask) -or $mask -lt 0 -or $mask -gt 4 -or [string]$row.'Exclusion Setting' -ne ''){Fail 'AUDIT_POLICY_INVALID' 'Advanced-audit system row is invalid.'}
        $state=switch($mask){0{'Not Specified'}1{'Success'}2{'Failure'}3{'Success and Failure'}4{'No Auditing'}}
        $result.Add((Audit-Row ([string]$row.Subcategory) $guid.ToString('B') $state $mask))
      }else{$result.Add($Lines[$index])}
    }
    return $result.ToArray()
}
function Get-ItemCurrent([string]$Id,$Map,$Item){
    switch([string]$Map.handler){
      {$_ -in @('SecurityTemplate')} {
        $path=Security-Path $Id;if(!(Test-Path -LiteralPath $path)){return $null};$raw=Get-TemplateEntry ([IO.File]::ReadAllText($path)) ([string]$Item.section) ([string]$Item.key)
        if($null -eq $raw){return $null};if(([string]$Item.type -eq 'Principals')){return Normalize-Principals $raw};return $raw
      }
      {$_ -in @('Registry','RegistrySet')} {
        try{
          $entry=Get-GPRegistryValue -Guid ([guid]$Id) -Key ([string]$Item.key) -ValueName ([string]$Item.name) -Domain $cfg.domain -Server $cfg.domainController -ErrorAction Stop
          $v=$entry.Value;if([string]$entry.Type -ine (Registry-Type ([string]$Item.type))){return ('<type mismatch: '+[string]$entry.Type+'> '+[string]$v)}
          if(([string]$Item.type).ToUpperInvariant() -eq 'MULTISTRING'){return ((@($v)|ForEach-Object{[string]$_}|Sort-Object)-join '|')};return [string]$v
        }catch{
          # Missing policy data is a valid "not configured" state. Any other GroupPolicy/transport
          # failure must fail closed instead of being misreported as an absent setting.
          $fqid=[string]$_.FullyQualifiedErrorId
          if($fqid -eq 'UnableToRetrievePolicyRegistryItem' -or $fqid -like 'UnableToRetrievePolicyRegistryItem,*'){return $null}
          Fail 'GPO_REGISTRY_READ_FAILED' ('Unable to read the current registry policy value for control '+[string]$Map.id+'.')
        }
      }
      'AdvancedAudit' {
        $path=Audit-Path $Id;if(!(Test-Path -LiteralPath $path)){return $null}
        try{$rows=@(Get-Content -LiteralPath $path -Encoding UTF8|ConvertFrom-Csv)}catch{Fail 'AUDIT_POLICY_INVALID' 'Advanced-audit CSV could not be parsed.'}
        $matches=@($rows|Where-Object{[string]$_.'Subcategory GUID' -ieq [string]$Item.guid})
        if($matches.Count -gt 1){Fail 'AUDIT_POLICY_AMBIGUOUS' 'Duplicate advanced-audit subcategory rows exist in this GPO.'}
        if($matches.Count -eq 0){return $null}
        $mask=0;if(![int]::TryParse([string]$matches[0].'Setting Value',[ref]$mask) -or $mask -lt 0 -or $mask -gt 4){Fail 'AUDIT_POLICY_INVALID' 'Advanced-audit CSV contains an invalid system setting.'}
        if($mask -eq 0){return $null} # MS-GPAC: unchanged, not explicit No Auditing.
        if($mask -eq 4){return '0'} # Internal bitmask representation of explicit None.
        return [string]$mask
      }
      default {Fail 'GPO_HANDLER_UNSUPPORTED' ('Unsupported mapping handler: '+[string]$Map.handler)}
    }
}
function Desired-Normalized($Map,$Item,$S){
    # Numeric masks are authoritative and independent of the CSV display language.
    if([string]$Map.handler -eq 'AdvancedAudit'){return [string]$Item.mask}
    $desired=Desired-Item $Map $Item $S
    if([string]$Map.handler -eq 'SecurityTemplate' -and [string]$Item.type -eq 'Principals'){return Normalize-Principals (Principals-Desired @($Item.value))}
    if(([string]$Item.type).ToUpperInvariant() -eq 'MULTISTRING'){return ((@($desired)|ForEach-Object{[string]$_}|Sort-Object)-join '|')}
    if([string]$Item.type -eq 'QuotedString'){return '"'+([string]$desired)+'"'}
    return [string]$desired
}
function Numeric-Complies($Current,$Desired,[string]$Comparator){
    $c=0.0;$d=0.0;if(![double]::TryParse([string]$Current,[Globalization.NumberStyles]::Any,[Globalization.CultureInfo]::InvariantCulture,[ref]$c)){return $false};if(![double]::TryParse([string]$Desired,[Globalization.NumberStyles]::Any,[Globalization.CultureInfo]::InvariantCulture,[ref]$d)){return $false}
    switch($Comparator){'>=' {return $c -ge $d}'<=' {return $c -gt 0 -and $c -le $d}'atMost' {return $c -ge 0 -and $c -le $d}'==' {return $c -eq $d}default{return $c -eq $d}}
}
function Included-Value($Current,$Desired,[string]$Handler){
    if($null -eq $Current){return $false}
    if($Handler -eq 'AdvancedAudit'){$n=0;if(![int]::TryParse([string]$Current,[ref]$n) -or $n -lt 0 -or $n -gt 3){return $false};return ($n -band [int]$Desired) -eq [int]$Desired}
    $currentSet=@(([string]$Current -split ',')|Where-Object{$_})
    return @(([string]$Desired -split ',')|Where-Object{$_ -and $_ -notin $currentSet}).Count -eq 0
}
function Item-Matches($Current,$Desired,$Map,$Item){
    if($null -eq $Current){return $false}
    if([string]$Map.comparator -eq 'includes'){return Included-Value $Current $Desired ([string]$Map.handler)}
    $rule=[string](Read-Field $Item 'comparator' '')
    if(!$rule -and @(Mapping-Items $Map).Count -eq 1){$rule=[string]$Map.comparator}
    if($rule -in @('>=','<=','atMost','==')){return Numeric-Complies $Current $Desired $rule}
    return [string]$Current -ceq [string]$Desired
}
function Mapping-Matches([string]$Id,$Map,$S){
    if([string]$Map.handler -eq 'AdvancedAudit'){
      $extensions=[string](Gpo-Ad $Id).gPCMachineExtensionNames
      if((Add-AuditExtension $extensions) -ine $extensions){return $false}
      $path=Audit-Path $Id;if(!(Test-Path -LiteralPath $path)){return $false}
      $text=[IO.File]::ReadAllText($path)
      $canonical=(@(Audit-CanonicalLines ([string[]](Get-Content -LiteralPath $path -Encoding UTF8))) -join "`r`n")+"`r`n"
      if($text -cne $canonical){return $false}
    }
    foreach($item in Mapping-Items $Map){
      if(!(Item-Matches (Get-ItemCurrent $Id $Map $item) (Desired-Normalized $Map $item $S) $Map $item)){return $false}
    }
    return $true
}
function Mapping-Display([string]$Id,$Map,$S,[bool]$Desired=$false){
    $parts=@();foreach($item in Mapping-Items $Map){$label=[string]$(if($item.name){$item.name}elseif($item.key){$item.key}else{$item.guid});$v=if($Desired){Desired-Normalized $Map $item $S}else{Get-ItemCurrent $Id $Map $item};if(@(Mapping-Items $Map).Count -eq 1){return $(if($null -eq $v){$null}else{[string]$v})};$parts+=($label+'='+$(if($null -eq $v){'<not configured>'}else{[string]$v}))};return ($parts -join '; ')
}
function Fingerprint([string]$Id,[string]$ScopeDn){
    $ad=Gpo-Ad $Id;$folder=Gpo-Folder $Id
    $links=@();foreach($candidateScope in All-LinkScopes){$raw=$candidateScope.rawLinks;if(Link $raw $Id $candidateScope.dn){$links+=($candidateScope.dn+'='+$raw)}}
    $permissions=@(Get-GPPermission -Guid ([guid]$Id) -All -Domain $cfg.domain -Server $cfg.domainController|ForEach-Object{[string]$_.Trustee.Sid.Value+':'+[string]$_.Permission}|Sort-Object)
    return Hash (([string]$ad.versionNumber)+'|'+[string]$ad.whenChanged.ToUniversalTime().ToString('O')+'|'+[string]$ad.flags+'|'+[string]$ad.gPCMachineExtensionNames+'|'+[string]$ad.gPCWQLFilter+'|'+(Get-NormalizedGpoContentFingerprint $folder)+'|'+(Scope-Links $ScopeDn)+'|'+(($links|Sort-Object)-join '|')+'|'+($permissions-join '|'))
}
function Validate-Selection($S,$Map){
    if([string]$Map.automation -ne 'Automated' -or [string]$Map.handler -eq 'Manual'){Fail 'GPO_MANUAL_ONLY' 'This CIS control is read-only in the production mapping registry and cannot be remediated automatically.'}
    if($S.refresh -notin @('None','Pdc','Scope')){Fail 'GPO_OPTIONS_INVALID' 'Unknown refresh option.'}
    $scope=Scope $S.scopeDn;$gpo=Get-GPO -Guid ([guid]$S.gpoId) -Domain $cfg.domain -Server $cfg.domainController;$status=[string]$gpo.GpoStatus
    if($status -eq 'AllSettingsDisabled'){Fail 'GPO_SETTINGS_DISABLED' 'All settings are disabled in this GPO.'}
    if([string]$Map.scope -eq 'User' -and $status -eq 'UserSettingsDisabled'){Fail 'USER_POLICY_DISABLED' 'User settings are disabled in this GPO.'}
    if([string]$Map.scope -ne 'User' -and $status -eq 'ComputerSettingsDisabled'){Fail 'COMPUTER_POLICY_DISABLED' 'Computer settings are disabled in this GPO.'}
    if([string]$Map.scope -eq 'Computer' -and [string]$S.refresh -eq 'Pdc'){Fail 'PDC_REFRESH_SCOPE_INVALID' 'This computer policy targets the computer OU, not the PDC. Use scoped computer refresh.'}
    if([string]$Map.scope -eq 'User'){
      if($scope.kind -notin @('OU','Domain')){Fail 'USER_OU_REQUIRED' 'Choose a discovered user OU or domain.'}
      if([string]$S.refresh -eq 'Pdc'){Fail 'USER_REFRESH_TARGET_INVALID' 'User policy is processed in a user session, not on the PDC. Choose an endpoint OU or wait for the normal policy cycle.'}
      if([string]$S.refresh -eq 'Scope'){
        $endpointDn=[string](Read-Field $S 'endpointScopeDn' '')
        if([string]::IsNullOrWhiteSpace($endpointDn)){Fail 'ENDPOINT_SCOPE_REQUIRED' 'Choose the computer OU that contains the user session endpoints.'}
        $null=Scope $endpointDn
        $identity=[string](Read-Field $S 'verificationUser' '')
        if(![string]::IsNullOrWhiteSpace($identity)){
        $user=Verification-User $identity
        if(!$user.Enabled){Fail 'VERIFICATION_USER_DISABLED' 'The verification user is disabled.'}
        if(!([string]$user.DistinguishedName).EndsWith(','+[string]$scope.dn,[StringComparison]::OrdinalIgnoreCase) -and [string]$user.DistinguishedName -ine [string]$scope.dn){Fail 'VERIFICATION_USER_OUTSIDE_SCOPE' 'The verification user is outside the selected user policy scope.'}
        }
      }
    }elseif((Read-Field $S 'endpointScopeDn' $null) -or (Read-Field $S 'verificationUser' $null)){Fail 'USER_TARGET_NOT_ALLOWED' 'Endpoint OU and verification user are only valid for user-scoped policy.'}
    if([string]$Map.scope -eq 'Computer' -and $scope.kind -notin @('OU','Domain')){Fail 'COMPUTER_OU_REQUIRED' 'Choose a discovered computer OU or domain.'}
    if([string](Read-Field $S 'accountScope' '') -eq 'LocalComputers' -and [string]$Map.id -match '^1\.[12]\.' -and $scope.kind -ne 'OU'){Fail 'LOCAL_ACCOUNT_OU_REQUIRED' 'Local account policy must target a computer OU.'}
    if([bool]$Map.domainPolicySensitive){
      if($scope.kind -ne 'Domain'){Fail 'ACCOUNT_SCOPE_MISMATCH' 'Domain password and lockout policy requires the domain root.'}
      if(![bool](Read-Field $S 'firstLink' $false)){Fail 'DOMAIN_POLICY_PRIORITY_REQUIRED' 'Domain password/lockout policy must be enabled at link order 1 on the domain root.'}
      if([string]$S.refresh -eq 'Scope'){Fail 'DOMAIN_REFRESH_SCOPE_INVALID' 'Domain account policy has no computer OU refresh scope. Refresh the PDC or wait for the normal policy cycle.'}
    }
    if([bool]$Map.requiresInput){$v=[string]$S.customValue;if([string]::IsNullOrWhiteSpace($v)){Fail 'GPO_CUSTOM_VALUE_REQUIRED' 'This control requires an explicit organization value.'};if($v.IndexOf([char]0)-ge 0){Fail 'GPO_CUSTOM_VALUE_INVALID' 'Custom value contains an invalid character.'}}
    if([bool]$Map.allowValueOverride){if($null -ne $Map.minimum -and [int]$S.value -lt [int]$Map.minimum){Fail 'GPO_VALUE_INVALID' 'Value is below the approved range.'};if($null -ne $Map.maximum -and [int]$S.value -gt [int]$Map.maximum){Fail 'GPO_VALUE_INVALID' 'Value is above the approved range.'}}
    if([string]$Map.id -in @('1.1.3')){$max=Get-TemplateEntry $(if(Test-Path (Security-Path $S.gpoId)){[IO.File]::ReadAllText((Security-Path $S.gpoId))}else{''}) 'System Access' 'MaximumPasswordAge';if($max -and [int]$max -ne 0 -and [int](Desired-Item $Map @(Mapping-Items $Map)[0] $S) -ge [int]$max){Fail 'PASSWORD_AGE_CONFLICT' 'Minimum password age must be less than maximum password age.'}}
    if([string]$Map.id -in @('1.2.1','1.2.2','1.2.4')){
      $text=if(Test-Path (Security-Path $S.gpoId)){[IO.File]::ReadAllText((Security-Path $S.gpoId))}else{''};$duration=Get-TemplateEntry $text 'System Access' 'LockoutDuration';$threshold=Get-TemplateEntry $text 'System Access' 'LockoutBadCount';$reset=Get-TemplateEntry $text 'System Access' 'ResetLockoutCount'
      $requested=[string](Desired-Item $Map @(Mapping-Items $Map)[0] $S)
      if($Map.id -eq '1.2.1'){$duration=$requested}elseif($Map.id -eq '1.2.2'){$threshold=$requested}else{$reset=$requested}
      if($threshold -and [int]$threshold -eq 0){Fail 'LOCKOUT_DISABLED' 'Account lockout threshold 0 disables lockout.'}
      if($duration -and $reset -and [int]$reset -gt [int]$duration){Fail 'LOCKOUT_INTERVAL_CONFLICT' 'Reset lockout counter interval cannot exceed lockout duration.'}
    }
}
function Backup-AclIsUnsafe($Acl){
    # FullControl/Modify include READ bits and must not be used as an overlap
    # mask: broad read-only grants are valid, broad mutation grants are not.
    $mask=[int64]([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach($rule in @($Acl.Access)){
        if([string]$rule.AccessControlType -ne 'Allow'){continue}
        if(([int]$rule.PropagationFlags -band [int][Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0){continue}
        $sid='';try{$sid=[string]$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}catch{}
        $broad=$sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545') -or $sid -match '^S-1-5-21-\d+-\d+-\d+-513$'
        if($broad -and (([int64]$rule.FileSystemRights -band $mask) -ne 0)){return $true}
    }
    return $false
}
function Test-BackupRepository([string]$Root){
    $root=[IO.Path]::GetFullPath($Root)
    if($root -notmatch '^[A-Za-z]:\\'){Fail 'BACKUP_PATH_INVALID' 'Backup path must be a local drive path on the selected DC.'}
    $work=Join-Path $root 'GpoWorkflow'
    $null=[IO.Directory]::CreateDirectory($work)
    foreach($path in @($root,$work)){
        if(((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Fail 'BACKUP_PATH_INVALID' 'Backup repository cannot use junctions or symbolic links.'}
    }
    $probe=Join-Path $work ('.write-probe-'+[guid]::NewGuid().ToString('N'))
    try{
        $null=[IO.Directory]::CreateDirectory($probe)
        $file=Join-Path $probe 'probe.tmp'
        [IO.File]::WriteAllText($file,'probe')
        [IO.File]::Delete($file)
    }finally{if([IO.Directory]::Exists($probe)){[IO.Directory]::Delete($probe,$false)}}
    return $work
}
function Environment-Status {
    $checks=New-Object 'System.Collections.Generic.List[object]'
    function Add-Check([string]$Id,[string]$Label,[string]$State,[string]$Message,[bool]$Required=$true){$checks.Add([pscustomobject]@{id=$Id;label=$Label;state=$State;message=$Message;required=$Required})|Out-Null}
    Add-Check 'session' 'Kerberos / WinRM session' 'PASS' ('Authenticated remote session on '+$dc.HostName)
    Add-Check 'modules' 'Active Directory / GPMC PowerShell' 'PASS' 'Both ActiveDirectory and GroupPolicy modules loaded on the delegated writable DC.'
    try{$name='_ldap._tcp.dc._msdcs.'+$domain.DNSRoot;$srv=@(Resolve-DnsName -Name $name -Type SRV -ErrorAction Stop);if($srv.Count){Add-Check 'srv' 'AD DC SRV discovery' 'PASS' ('DC locator SRV records: '+$srv.Count)}else{Add-Check 'srv' 'AD DC SRV discovery' 'WARN' 'No AD DC SRV record was returned.' $false}}catch{Add-Check 'srv' 'AD DC SRV discovery' 'WARN' 'AD DC SRV discovery failed; verify domain DNS and firewall.' $false}
    try{$resolved=@(Resolve-DnsName -Name $cfg.domainController -Type A -ErrorAction Stop);Add-Check 'dns' 'DNS resolution' 'PASS' (($resolved|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress)-join ', ')}catch{Add-Check 'dns' 'DNS resolution' 'FAIL' 'Writable DC name could not be resolved.'}
    try{$null=Get-ADDomain -Identity $cfg.domain -Server $cfg.domainController -ErrorAction Stop;Add-Check 'ldap' 'Active Directory / LDAP' 'PASS' 'Domain query succeeded on the selected DC.'}catch{Add-Check 'ldap' 'Active Directory / LDAP' 'FAIL' 'Domain query failed on the selected DC.'}
    try{$policies=Sysvol-Policies;Add-Check 'sysvol' 'SYSVOL' 'PASS' ('Local SYSVOL Policies directory is accessible: '+$policies)}catch{Add-Check 'sysvol' 'SYSVOL' 'FAIL' ('Local SYSVOL check failed for '+[Security.Principal.WindowsIdentity]::GetCurrent().Name+': '+$_.Exception.Message)}
    try{$work=Test-BackupRepository ([string]$cfg.backupPath);Add-Check 'backup' 'Backup repository' 'PASS' ('Execution workspace is writable on '+$dc.HostName+': '+$work)}catch{Add-Check 'backup' 'Backup repository' 'FAIL' ('Cannot create/delete backup workspace files on '+$dc.HostName+' as '+[Security.Principal.WindowsIdentity]::GetCurrent().Name+'. Check Modify and inheritance on '+[string]$cfg.backupPath+' and its GpoWorkflow child. Upgrade the complete Control Panel/launcher folder to migrate old private backup ACLs, then reconnect.')}
    try{
      $root=[IO.Path]::GetFullPath([string]$cfg.backupPath)
      $acl=Get-Acl -LiteralPath $root -ErrorAction Stop
      if(Backup-AclIsUnsafe $acl){Add-Check 'backup-acl' 'Backup repository ACL' 'FAIL' 'Broad user groups have write/modify permissions on the GPO backup directory. Remove unsafe ACEs before Apply.'}
      else{Add-Check 'backup-acl' 'Backup repository ACL' 'PASS' 'No broad user group has write/modify permissions on the backup root.'}
    }catch{Add-Check 'backup-acl' 'Backup repository ACL' 'FAIL' ('Cannot read backup ACL on '+$dc.HostName+' as '+[Security.Principal.WindowsIdentity]::GetCurrent().Name+'. Check Read permissions and Modify delegation on '+[string]$cfg.backupPath+'.')}

    try{$backupRoot=[IO.Path]::GetFullPath([string]$cfg.backupPath);$drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($backupRoot));$free=[long]$drive.AvailableFreeSpace;if($free -le 0){Add-Check 'disk' 'Backup volume free space' 'WARN' 'Backup drive free space could not be established.' $false}elseif($free -lt 2GB){Add-Check 'disk' 'Backup volume free space' 'WARN' ('Only '+[math]::Round($free/1GB,2)+' GB free; review backup capacity.') $false}else{Add-Check 'disk' 'Backup volume free space' 'PASS' ([math]::Round($free/1GB,2).ToString()+' GB free on backup volume.') $false}}catch{Add-Check 'disk' 'Backup volume free space' 'WARN' 'Could not inspect the local backup disk.' $false}
    try{$bad=@(Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -ErrorAction Stop|Where-Object{$_.LastReplicationResult -ne 0});if($bad.Count){Add-Check 'replication' 'AD replication' 'WARN' ($bad.Count.ToString()+' replication partner(s) report a non-zero last result.') $false}else{Add-Check 'replication' 'AD replication' 'PASS' 'Local DC replication metadata reports no failed last result.' $false}}catch{Add-Check 'replication' 'AD replication' 'WARN' 'Replication metadata could not be read; Apply will still verify AD/SYSVOL versions for the selected GPO.' $false}
    $ready=@($checks|Where-Object{$_.required -and $_.state -eq 'FAIL'}).Count -eq 0
    return @{domain=$domain.DNSRoot;domainController=$dc.HostName;executionUser=[Security.Principal.WindowsIdentity]::GetCurrent().Name;ready=$ready;checks=$checks.ToArray();checkedAt=[DateTimeOffset]::UtcNow.ToString('O')}
}
function Test-FileSystemWrite([string]$Path){
    # Ask Windows AccessCheck with the real remoting token. Do not infer access
    # by adding allow ACEs: deny ACEs, inheritance and token group flags matter.
    if(!('GpoRemediator.EffectiveFileAccess' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace GpoRemediator {
 public static class EffectiveFileAccess {
  [StructLayout(LayoutKind.Sequential)] struct Mapping { public uint Read,Write,Execute,All; }
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateToken(IntPtr token,int level,out IntPtr copy);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AccessCheck(byte[] descriptor,IntPtr token,uint desired,ref Mapping mapping,IntPtr privileges,ref uint size,out uint granted,[MarshalAs(UnmanagedType.Bool)] out bool allowed);
  public static bool Write(byte[] descriptor) {
   using(var identity=WindowsIdentity.GetCurrent()) {
    IntPtr token;
    if(!DuplicateToken(identity.Token,2,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
    try {
     var mapping=new Mapping{Read=0x120089,Write=0x120116,Execute=0x1200A0,All=0x1F01FF};
     uint size=4096;
     for(int attempt=0;attempt<2;attempt++) {
      IntPtr buffer=Marshal.AllocHGlobal((int)size);
      try {
       uint granted;bool allowed;
       uint desired=(uint)(System.Security.AccessControl.FileSystemRights.ReadAndExecute|System.Security.AccessControl.FileSystemRights.Write);
       if(AccessCheck(descriptor,token,desired,ref mapping,buffer,ref size,out granted,out allowed))return allowed;
       int error=Marshal.GetLastWin32Error();if(error!=122)throw new Win32Exception(error);
      } finally { Marshal.FreeHGlobal(buffer); }
     }
     throw new InvalidOperationException("Effective access buffer unavailable.");
    } finally { CloseHandle(token); }
   }
  }
 }
}
'@
    }
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    return [GpoRemediator.EffectiveFileAccess]::Write($acl.GetSecurityDescriptorBinaryForm())
}
function Attribute-WriteState([string]$Dn,[string[]]$Required){
    try{
        # The DC computes this property for the actual caller, including AD
        # property-specific and inherited permissions. No directory write probe.
        $object=Get-ADObject -Identity $Dn -Server $cfg.domainController -Properties allowedAttributesEffective -ErrorAction Stop
        $property=$object.PSObject.Properties['allowedAttributesEffective']
        if(!$property -or $null -eq $property.Value){return 'UNKNOWN'}
        $attributes=@($property.Value|ForEach-Object{[string]$_})
        if(@($Required|Where-Object{$_ -notin $attributes}).Count){return 'DENIED'}
        return 'ALLOWED'
    }catch{return 'UNKNOWN'}
}
function Link-ChangeRequired($S,$Link){
    if($null -eq $Link){return $true}
    return (!$Link.enabled -or ([bool](Read-Field $S 'firstLink' $false) -and [int]$Link.order -ne 1))
}
function Policy-WritePaths($S,$Map){
    $folder=Gpo-Folder $S.gpoId
    $branch=if([string]$Map.scope -eq 'User'){'User'}else{'Machine'}
    $target=switch([string]$Map.handler){
        'SecurityTemplate' { Security-Path $S.gpoId }
        'AdvancedAudit' { Audit-Path $S.gpoId }
        {$_ -in @('Registry','RegistrySet')} { Join-Path $folder ($branch+'\Registry.pol') }
        default { Fail 'GPO_HANDLER_UNSUPPORTED' 'The selected remediation handler has no known SYSVOL write target.' }
    }
    $paths=@((Join-Path $folder 'GPT.INI'))
    if(!(Test-Path -LiteralPath $paths[0] -PathType Leaf)){Fail 'GPO_GPT_MISSING' 'The selected GPO has no GPT.INI on the writable DC.'}
    $parent=Split-Path -Path $target -Parent
    while(!(Test-Path -LiteralPath $parent -PathType Container)){
        if($parent -ieq $folder -or !$parent.StartsWith($folder+'\',[StringComparison]::OrdinalIgnoreCase)){Fail 'SYSVOL_TARGET_INVALID' 'The selected policy target is outside the GPO folder.'}
        $parent=Split-Path -Path $parent -Parent
    }
    if(Test-Path -LiteralPath $target){$paths+=@($target)}
    $paths+=@($parent)
    return @($paths|Select-Object -Unique)
}
function Selection-Access($S,$Map){
    $checks=@()
    $gpoDn='CN='+([guid]$S.gpoId).ToString('B').ToUpperInvariant()+',CN=Policies,CN=System,'+$domainDn
    $extension=if([string]$Map.scope -eq 'User'){'gPCUserExtensionNames'}else{'gPCMachineExtensionNames'}
    $checks+=@{id='gpo-edit';state=(Attribute-WriteState $gpoDn @('versionNumber',$extension));code='GPO_EDIT_ACCESS_DENIED';label='GPO edit authority'}
    $linkState='UNKNOWN'
    try{$link=Selected-Link ([string]$S.scopeDn) ([string]$S.gpoId);$linkState=if(Link-ChangeRequired $S $link){Attribute-WriteState ([string]$S.scopeDn) @('gPLink')}else{'ALLOWED'}}catch{}
    $checks+=@{id='link-write';state=$linkState;code='OU_LINK_ACCESS_DENIED';label='GPO link authority or unchanged link'}
    $fileState='UNKNOWN'
    try{
        $fileState='ALLOWED'
        foreach($path in @(Policy-WritePaths $S $Map)){if(!(Test-FileSystemWrite $path)){$fileState='DENIED';break}}
    }catch{$fileState='UNKNOWN'}
    $checks+=@{id='sysvol-write';state=$fileState;code='SYSVOL_WRITE_ACCESS_DENIED';label='SYSVOL GPO write authority'}
    return @{checks=@($checks);executionUser=[Security.Principal.WindowsIdentity]::GetCurrent().Name}
}
function Assert-SelectionAccess($S,$Map){
    $access=Selection-Access $S $Map
    $denied=@($access.checks|Where-Object{$_.state -eq 'DENIED'}|Select-Object -First 1)
    if($denied.Count){
        $code=[string]$denied[0].code
        $guidance=switch($code){
            'GPO_EDIT_ACCESS_DENIED' {'No GPO edit access. Ask an administrator: GPMC > Group Policy Objects > selected GPO > Delegation > Add the execution account/group with Edit settings. Read/Apply permission is not edit permission. Reconnect after changes. No remediation plan was created.'}
            'OU_LINK_ACCESS_DENIED' {'No permission to change the selected target link. Ask an administrator: GPMC > selected OU/domain > Delegation > Link GPOs > add the execution account/group for that target. GPO Edit settings is separate. Reconnect after changes. No remediation plan was created.'}
            'SYSVOL_WRITE_ACCESS_DENIED' {'No SYSVOL modification access for the selected GPO. Ask an administrator to review that GPO in GPMC > Delegation > Edit settings and its SYSVOL NTFS Effective Access. Repair delegation/ACL consistency for this GPO only, not broad SYSVOL access. Reconnect after changes. No remediation plan was created.'}
        }
        Fail $code $guidance
    }
    if(@($access.checks|Where-Object{$_.state -ne 'ALLOWED'}).Count){Fail 'GPO_ACCESS_UNVERIFIED' 'Effective write access could not be established for the selected GPO, SYSVOL or target link. No remediation plan was created. An administrator should inspect effective access and GPMC delegation, then reconnect and retry.'}
    return $access
}

function Token-Sids {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent();$s=@([string]$id.User.Value);$s+=@($id.Groups|ForEach-Object{[string]$_.Value});return @($s|Sort-Object -Unique)
}
function Selection-Preflight($S,$Map,$Access=$null){
    $base=Environment-Status;$checks=New-Object 'System.Collections.Generic.List[object]';foreach($c in @($base.checks)){$checks.Add($c)|Out-Null}
    if($null -eq $Access){$Access=Selection-Access $S $Map}
    foreach($check in @($Access.checks)){$checks.Add([pscustomobject]@{id=$check.id;label=$check.label;state=$(if($check.state -eq 'ALLOWED'){'PASS'}elseif($check.state -eq 'DENIED'){'FAIL'}else{'WARN'});message='Read-only effective access check for the domain execution account.';required=$true})|Out-Null}
    $checks.Add([pscustomobject]@{id='handler';label='Remediation handler';state='PASS';message=([string]$Map.handler+' · '+[string]$Map.source);required=$true})|Out-Null
    $ready=@($checks|Where-Object{$_.required -and $_.state -ne 'PASS'}).Count -eq 0
    return @{domain=$base.domain;domainController=$dc.HostName;executionUser=$base.executionUser;ready=$ready;checks=$checks.ToArray();checkedAt=[DateTimeOffset]::UtcNow.ToString('O')}
}
function Impact-Details($S,$Map,$Gpo,$Scope,[string[]]$LinkScopes){
    $inherit=Get-GPInheritance -Target $Scope.dn -Domain $cfg.domain -Server $cfg.domainController;$conflicts=@();$allLinks=@($inherit.GpoLinks)+@($inherit.InheritedGpoLinks);$desired=Mapping-Display $S.gpoId $Map $S $true
    foreach($link in $allLinks){try{$id=([guid]$link.GpoId).ToString();if($id -eq ([guid]$S.gpoId).ToString()){continue};$other=Mapping-Display $id $Map $S $false;if($null -ne $other -and [string]$other -cne [string]$desired){$conflicts+=@{severity=$(if($link.Enforced){'HIGH'}else{'MEDIUM'});code='SETTING_DEFINED_ELSEWHERE';message=('The same control is configured differently in another applicable GPO: '+$other);gpoId=$id;gpoName=[string]$link.DisplayName;scope=[string]$Scope.dn}};if($link.Enforced){$conflicts+=@{severity='HIGH';code='ENFORCED_LINK';message='An enforced GPO link is present in the inheritance path.';gpoId=$id;gpoName=[string]$link.DisplayName;scope=[string]$Scope.dn}}}catch{Fail 'ANALYSIS_INCOMPLETE' 'Conflict analysis could not read or interpret an applicable GPO. Apply is blocked until the analysis succeeds.'}}
    if([bool]$inherit.GpoInheritanceBlocked){$conflicts+=@{severity='HIGH';code='BLOCK_INHERITANCE';message='Block Inheritance is enabled on the selected scope.';gpoId=$null;gpoName=$null;scope=[string]$Scope.dn}}
    $permissions=@(Get-GPPermission -Guid ([guid]$S.gpoId) -All -Domain $cfg.domain -Server $cfg.domainController|Where-Object{$_.Permission -eq 'GpoApply'}|ForEach-Object{[string]$_.Trustee.Name}|Sort-Object -Unique);$ad=Gpo-Ad $S.gpoId
    if($ad.gPCWQLFilter){$conflicts+=@{severity='MEDIUM';code='WMI_FILTER';message='The selected GPO has a WMI filter. Effective application must be verified on an endpoint.';gpoId=([guid]$S.gpoId).ToString();gpoName=[string]$Gpo.DisplayName;scope=[string]$Scope.dn}}
    # Smart Target Discovery: keep domain account policy distinct from GPO client OU targeting.
    # This is a bounded pre-filter directory inventory, never a claim of RSoP compliance.
    $objects=@();$users=@();$domainAccount=[bool]$Map.domainPolicySensitive
    try{
      if($domainAccount){$null=Get-ADDomain -Identity $cfg.domain -Server $cfg.domainController -ErrorAction Stop}
      elseif([string]$Map.scope -eq 'User'){$users=@(Get-ADUser -SearchBase $Scope.dn -SearchScope Subtree -Filter * -Server $cfg.domainController -Properties Enabled -ResultSetSize 5001 -ErrorAction Stop)}
      else{$objects=@(Get-ADComputer -SearchBase $Scope.dn -SearchScope Subtree -Filter * -Server $cfg.domainController -Properties DNSHostName,OperatingSystem,Enabled -ResultSetSize 5001 -ErrorAction Stop)}
    }catch{Fail 'ANALYSIS_INCOMPLETE' 'Directory target inventory could not be read. Apply is blocked until target scope enumeration succeeds.'}
    $truncated=($objects.Count -gt 5000 -or $users.Count -gt 5000)
    if($truncated){Fail 'TARGET_SCOPE_INVENTORY_LIMIT' 'The selected OU contains more than 5,000 objects. Select a narrower OU; exact target impact cannot be guaranteed by the bounded preview.'}
    $enabled=@($objects|Where-Object Enabled);$enabledUsers=@($users|Where-Object Enabled)
    $servers=@($enabled|Where-Object{$_.OperatingSystem -match 'Server'});$workstations=@($enabled|Where-Object{$_.OperatingSystem -notmatch 'Server'})
    $sample=@($enabled|Where-Object DNSHostName|Select-Object -First 25 -ExpandProperty DNSHostName)
    $sampleUsers=@($enabledUsers|Select-Object -First 25 -ExpandProperty SamAccountName)
    $kind=if($domainAccount){'DomainAccount'}elseif([string]$Map.scope -eq 'User'){'User'}else{'Computer'}
    return @{inheritance=$(if([bool]$inherit.GpoInheritanceBlocked){'BLOCKED'}else{'NORMAL'});blockInheritance=[bool]$inherit.GpoInheritanceBlocked;conflicts=@($conflicts);affectedObjects=@{targetKind=$kind;scopeDn=[string]$Scope.dn;computers=$enabled.Count;servers=$servers.Count;workstations=$workstations.Count;disabled=@($objects|Where-Object{-not $_.Enabled}).Count;sampleHosts=$sample;truncated=$false;users=$enabledUsers.Count;disabledUsers=@($users|Where-Object{-not $_.Enabled}).Count;sampleUsers=$sampleUsers};existingLinkScopes=@($LinkScopes);securityFiltering=$permissions;wmiFilter=$(if($ad.gPCWQLFilter){[string]$ad.gPCWQLFilter}else{$null})}
}
function Preview($S,$Map,[bool]$RequireWriteAccess=$true){
    Validate-Selection $S $Map;$access=if($RequireWriteAccess){Assert-SelectionAccess $S $Map}else{@{checks=@()}};$gpo=Get-GPO -Guid ([guid]$S.gpoId) -Domain $cfg.domain -Server $cfg.domainController;$scope=Scope $S.scopeDn;$raw=Scope-Links $scope.dn;$existing=Selected-Link $scope.dn $S.gpoId;$computers=@()
    $endpointScope=[string](Read-Field $S 'endpointScopeDn' '')
    $computers=@(Refresh-Targets ([string]$S.refresh) ([string]$scope.dn) $endpointScope ([string]$Map.scope))
    $links=@();foreach($candidateScope in All-LinkScopes){if(Link $candidateScope.rawLinks $S.gpoId $candidateScope.dn){$links+=$candidateScope.dn}}
    $verificationComputers=@();if(![bool]$Map.domainPolicySensitive -and ([string]$Map.scope -ne 'User' -or $endpointScope)){$verificationComputers=@(Refresh-Targets 'Scope' ([string]$scope.dn) $endpointScope ([string]$Map.scope))}
    $preflight=Selection-Preflight $S $Map $access;$impact=Impact-Details $S $Map $gpo $scope $links;$warnings=@('Changing this GPO affects all of its existing links, not only the selected link.',('Existing links: '+$(if($links.Count){$links -join '; '}else{'none'})),'Security filtering, WMI filtering, inheritance and precedence are analyzed but are never silently changed.','gpupdate scheduling does not by itself prove effective endpoint compliance.','A full GPO backup is created before any policy write; rollback is blocked after external changes.','Rollback imports the saved policy settings into the same GPO and restores the selected link. Security filtering, GPO ACLs and WMI filter ownership are preserved; Edit settings and any required link delegation are checked again.')+@($Map.warnings)
    if([string]$Map.handler -eq 'AdvancedAudit'){$warnings+='AUDIT_DEPENDENCY: Review control 2.3.2.1: SCENoApplyLegacyAuditPolicy=1 on the endpoint prevents legacy category policy overriding audit subcategories. This separate control is not silently changed.';$warnings+='AUDIT_FORMAT: Applying an audit control also normalizes legacy system audit CSV rows without changing their other numeric settings. The full GPO backup preserves the original file.'}
    foreach($c in @($impact.conflicts|Where-Object{$_.severity -eq 'HIGH'})){$warnings+=('High-impact conflict: '+$c.message)}
    if([string]$Map.scope -eq 'User' -and [int]$impact.affectedObjects.users -eq 0){$warnings+='TARGET_EMPTY: No enabled users were discovered under the selected user OU. Writing the GPO is not proof it will affect any user.'}
    if([string]$Map.scope -eq 'Computer' -and [int]$impact.affectedObjects.computers -eq 0){$warnings+='TARGET_EMPTY: No enabled computers were discovered under the selected computer OU. Select an OU containing the intended endpoints.'}
    if(@($impact.securityFiltering).Count -eq 0){$warnings+='GPO_APPLY_PERMISSION_MISSING: No GPO Apply trustees were discovered. Verify Security Filtering and Read/Apply permissions before deployment.'}
    if([string]$Map.scope -eq 'Computer' -and [int]$impact.affectedObjects.servers -gt 0){$warnings+='ROLE_BASELINE_REVIEW: This computer scope contains servers. Verify that each role (DC, IIS, SQL, Exchange, RDS) supports the requested policy and values.'}
    if([string]$Map.scope -eq 'User'){$warnings+='USER_POLICY_APPLICATION: Linked OU and GPO registry values are not proof of user-session convergence. Check Security Filtering, user GPO status, loopback processing, gpresult /scope user /r and HKCU evidence.'}

    # Apply regenerates the preview on the DC. Use the same host boundary here
    # so filtering cannot make a fresh plan reject its own refresh target list.
    $computers=@(Filter-EndpointHosts $computers)
    $impact.affectedObjects.sampleHosts=@(Filter-EndpointHosts @($impact.affectedObjects.sampleHosts))
    if([string]$S.refresh -eq 'Scope' -and @($computers).Count -eq 0){$warnings+='NO_REFRESH_HOSTS: No enabled endpoint matched the selected OU and endpoint targeting mode.'}
    $contentMatches=Mapping-Matches $S.gpoId $Map $S;$linkMatches=$null -ne $existing -and $existing.enabled -and (!$S.firstLink -or $existing.order -eq 1);$desired=Mapping-Display $S.gpoId $Map $S $true
    return @{gpo=(Gpo-Choice $gpo);scope=$scope;previousValue=(Mapping-Display $S.gpoId $Map $S $false);desiredValue=$desired;noChange=($contentMatches -and $linkMatches);fingerprint=(Fingerprint $S.gpoId $scope.dn);scopeLinks=$raw;existingLink=$existing;refreshComputers=$computers;verificationComputers=$verificationComputers;warnings=$warnings;impact=$impact;preflight=$preflight}
}
function Atomic-Text([string]$Path,[string]$Text,[Text.Encoding]$Encoding){
    $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path));$temp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try{
        [IO.File]::WriteAllText($temp,$Text,$Encoding)
        try{if([IO.File]::Exists($Path)){[IO.File]::Replace($temp,$Path,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temp,$Path)}}
        catch [UnauthorizedAccessException]{
            # Standard GPMC "Edit settings" SYSVOL ACLs grant RX, W and DC,
            # but not DELETE on each existing file. ReplaceFile requires that
            # extra right, so use a durable in-place write after the backup and
            # manifest have already been committed.
            $bytes=$Encoding.GetBytes($Text);$stream=[IO.File]::Open($Path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        }
    }finally{if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
}
function Assert-VersionSync([string]$Id){$ad=Gpo-Ad $Id;$gptPath=Join-Path (Gpo-Folder $Id) 'GPT.INI';$gpt=[IO.File]::ReadAllText($gptPath);$adVersion=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ad.versionNumber),0);$gptVersion=[uint32](Get-TemplateEntry $gpt 'General' 'Version');if($gptVersion -ne $adVersion){Fail 'REPLICATION_PENDING' 'AD and SYSVOL GPO versions differ. Wait for replication before applying.'};return @{ad=$ad;gptPath=$gptPath;gpt=$gpt;version=$adVersion}}
function Bump-ComputerVersion([string]$Id,[ValidateSet('Security','Audit')][string]$Extension){
    $v=Assert-VersionSync $Id;$next=Get-NextComputerVersion ([uint32]$v.version)
    $extensions=if($Extension -eq 'Audit'){Add-AuditExtension ([string]$v.ad.gPCMachineExtensionNames)}else{Add-SecurityExtension ([string]$v.ad.gPCMachineExtensionNames)}
    Atomic-Text $v.gptPath (Set-TemplateEntry $v.gpt 'General' 'Version' ([string]$next)) ([Text.Encoding]::ASCII)
    $signed=[BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$next),0)
    Set-ADObject -Identity $v.ad.DistinguishedName -Server $cfg.domainController -Replace @{versionNumber=$signed;gPCMachineExtensionNames=$extensions}
}
function Write-Mapping($Plan,$Map){
    $s=$Plan.selection;if(Mapping-Matches $s.gpoId $Map $s){return $false}
    switch([string]$Map.handler){
      'SecurityTemplate' {$null=Assert-VersionSync $s.gpoId;$path=Security-Path $s.gpoId;$text=if(Test-Path -LiteralPath $path){[IO.File]::ReadAllText($path)}else{''};foreach($item in Mapping-Items $Map){$desired=Desired-Item $Map $item $s;if([string]$item.type -eq 'Principals'){$values=@($item.value);if([string]$Map.comparator -eq 'includes'){$existing=Get-ItemCurrent $s.gpoId $Map $item;if($existing){$values+=@($existing -split ',')}};$desired=Principals-Desired @($values|Sort-Object -Unique)}elseif([string]$item.type -eq 'QuotedString'){$desired='"'+([string]$desired)+'"'};$text=Set-SecurityTemplateValue $text ([string]$item.section) ([string]$item.key) ([string]$desired)};Atomic-Text $path $text ([Text.Encoding]::Unicode);Bump-ComputerVersion $s.gpoId 'Security';return $true}
      {$_ -in @('Registry','RegistrySet')} {foreach($item in Mapping-Items $Map){$current=Get-ItemCurrent $s.gpoId $Map $item;$desired=Desired-Normalized $Map $item $s;if(Item-Matches $current $desired $Map $item){continue};$value=Desired-Item $Map $item $s;$type=Registry-Type ([string]$item.type);if($type -eq 'DWord'){$value=[int64]$value}elseif($type -eq 'QWord'){$value=[int64]$value}elseif($type -eq 'MultiString'){$value=[string[]]@($value)}else{$value=[string]$value};Set-GPRegistryValue -Guid ([guid]$s.gpoId) -Key ([string]$item.key) -ValueName ([string]$item.name) -Type $type -Value $value -Domain $cfg.domain -Server $cfg.domainController|Out-Null};return $true}
      'AdvancedAudit' {$null=Assert-VersionSync $s.gpoId;$path=Audit-Path $s.gpoId;$lines=New-Object 'System.Collections.Generic.List[string]';if(Test-Path -LiteralPath $path){$lines.AddRange([string[]](Audit-CanonicalLines ([string[]](Get-Content -LiteralPath $path -Encoding UTF8))))}else{$lines.Add('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')};foreach($item in Mapping-Items $Map){$guid=[string]$item.guid;$indices=@();for($i=1;$i -lt $lines.Count;$i++){if($lines[$i] -match [regex]::Escape($guid)){$indices+=$i}};if($indices.Count -gt 1){Fail 'AUDIT_POLICY_AMBIGUOUS' 'Duplicate advanced-audit subcategory rows exist in this GPO.'};$mask=[int]$item.mask;if([string]$Map.comparator -eq 'includes'){$existing=Get-ItemCurrent $s.gpoId $Map $item;if($null -ne $existing){$n=0;if(![int]::TryParse([string]$existing,[ref]$n) -or $n -lt 0 -or $n -gt 3){Fail 'AUDIT_POLICY_INVALID' 'Existing audit mask is invalid.'};$mask=$mask -bor $n}};$auditState=switch($mask){0{'No Auditing'}1{'Success'}2{'Failure'}3{'Success and Failure'}};$row=Audit-Row ([string]$item.name) $guid $auditState $(if($mask -eq 0){4}else{$mask});if($indices.Count -eq 1){$lines[$indices[0]]=$row}else{$lines.Add($row)}};Atomic-Text $path (($lines -join "`r`n")+"`r`n") ([Text.UTF8Encoding]::new($false));Bump-ComputerVersion $s.gpoId 'Audit';return $true}
      default {Fail 'GPO_HANDLER_UNSUPPORTED' ('Unsupported mapping handler: '+[string]$Map.handler)}
    }
}
function Rollback-ExpectedFingerprint($Plan,$Manifest,[string]$Current){
    if([string]$Manifest.phase -ne 'ROLLED_BACK'){return [string]$Manifest.postFingerprint}
    $saved=Read-Field $Manifest 'rollbackFingerprint' $null
    if($saved){return [string]$saved}
    # Old releases did not save a post-restore fingerprint. Accept that baseline
    # only after comparing the full recorded snapshot, CSE and original links.
    $s=$Plan.selection
    if((Get-NormalizedGpoContentFingerprint (Gpo-Folder $s.gpoId)) -ceq [string]$Manifest.beforeContent -and (Snapshot-ExtensionsMatch $Manifest $s.gpoId $s) -and (Scope-Links $s.scopeDn) -ceq [string]$Plan.preview.scopeLinks){return $Current}
    return $null
}
function Snapshot-ExtensionsMatch($Manifest,[string]$Id,$Selection){
    $ad=Gpo-Ad $Id
    if([string]$ad.gPCMachineExtensionNames -cne [string]$Manifest.beforeExtensions){return $false}
    $userBefore=Read-Field $Manifest 'beforeUserExtensions' $null
    if($null -eq $userBefore){return [string](Read-Field $Selection 'accountScope' '') -ne 'Users'}
    return [string]$ad.gPCUserExtensionNames -ceq [string]$userBefore
}
function Remote-GpoFolder([string]$Server,[string]$Id){return ('\\'+$Server+'\SYSVOL\'+$domain.DNSRoot+'\Policies\'+([guid]$Id).ToString('B').ToUpperInvariant())}
function Verification-Metadata($S){
    $ad=Gpo-Ad $S.gpoId;$folder=Gpo-Folder $S.gpoId;$gpt=[string](Get-TemplateEntry ([IO.File]::ReadAllText((Join-Path $folder 'GPT.INI'))) 'General' 'Version');$adv=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ad.versionNumber),0);$warnings=@();$dcStatus=@();$localContent=Get-NormalizedGpoContentFingerprint $folder
    try{$bad=@(Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -ErrorAction Stop|Where-Object{$_.LastReplicationResult -ne 0});if($bad.Count){$warnings+=($bad.Count.ToString()+' replication partner(s) report a non-zero last result.')}}catch{$warnings+='AD replication partner metadata probe unavailable.'}
    $dcs=@(Get-ADDomainController -Filter * -Server $cfg.domainController|ForEach-Object{[string]$_.HostName}|Sort-Object)
    $truncated=$dcs.Count -gt 50
    if($truncated){$warnings+='More than 50 domain controllers were discovered; convergence verification is limited to the first 50.';$dcs=@($dcs|Select-Object -First 50)}
    $gpoDn='CN='+([guid]$S.gpoId).ToString('B').ToUpperInvariant()+',CN=Policies,CN=System,'+$domainDn;$guidFolder=([guid]$S.gpoId).ToString('B').ToUpperInvariant()
    foreach($server in $dcs){
      try{
        $remote=Get-ADObject -Identity $gpoDn -Server $server -Properties versionNumber,gPCMachineExtensionNames,gPCUserExtensionNames -ErrorAction Stop;$remoteAd=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$remote.versionNumber),0)
        $unc=Join-Path (Remote-GpoFolder $server $S.gpoId) 'GPT.INI'
        if(!(Test-Path -LiteralPath $unc)){throw 'SYSVOL GPT.INI unavailable'}
        $remoteGpt=[string](Get-TemplateEntry ([IO.File]::ReadAllText($unc)) 'General' 'Version');$remoteContent=Get-NormalizedGpoContentFingerprint (Split-Path $unc -Parent);$contentMatches=$remoteContent -ceq $localContent;$extensionMatches=([string]$remote.gPCMachineExtensionNames -ceq [string]$ad.gPCMachineExtensionNames) -and ([string]$remote.gPCUserExtensionNames -ceq [string]$ad.gPCUserExtensionNames);$same=([string]$remoteAd -ceq $remoteGpt) -and ([string]$remoteAd -ceq [string]$adv) -and $contentMatches -and $extensionMatches
        $dcStatus+=@{domainController=$server;adVersion=[string]$remoteAd;gptVersion=$remoteGpt;reachable=$true;versionsMatch=[bool]$same;message=$(if($same){'AD/SYSVOL versions, policy content and computer/user extensions match the selected DC.'}else{'AD/SYSVOL version, policy content or computer/user extensions have not converged.'})}
      }catch{$dcStatus+=@{domainController=$server;adVersion=$null;gptVersion=$null;reachable=$false;versionsMatch=$false;message='Could not read AD and SYSVOL GPO versions from this DC.'};$warnings+=('Replication verification unavailable on '+$server+'.')}
    }
    $converged=$dcStatus.Count -gt 0 -and !$truncated -and @($dcStatus|Where-Object{-not $_.versionsMatch}).Count -eq 0
    if(!$converged){$warnings+='Not every checked DC has converged to the selected GPO version yet.'}
    return @{adVersion=[string]$adv;gptVersion=$gpt;versionsMatch=([string]$adv -ceq $gpt);domainControllers=$dcs;replicationWarnings=$warnings;checkedAt=[DateTimeOffset]::UtcNow.ToString('O');replicationConverged=[bool]$converged;dcVersions=@($dcStatus);evidenceVersion='2.0-content'}
}
function Endpoint-Expected($Map,$S){
    $items=@();foreach($item in Mapping-Items $Map){
      $expected=if([string]$Map.handler -eq 'AdvancedAudit'){[string]$item.mask}elseif([string]$Map.handler -eq 'SecurityTemplate' -and [string]$item.type -eq 'QuotedString'){[string](Desired-Item $Map $item $S)}else{[string](Desired-Normalized $Map $item $S)}
      $items+=@{section=[string]$item.section;key=[string]$item.key;name=[string]$item.name;type=[string]$item.type;guid=[string]$item.guid;expected=$expected;comparator=[string](Read-Field $item 'comparator' $Map.comparator)}
    };return @($items)
}
function Endpoint-CredentialOptions {
    $credential=Get-Variable -Name EndpointCredential -ValueOnly -ErrorAction SilentlyContinue
    if($credential){return @{Credential=$credential}}
    return @{}
}
function Endpoint-FailureMessage($Record){
    # Classify the native error without returning raw exception text, command
    # arguments or credentials in an evidence bundle.
    $category=[string]$Record.CategoryInfo.Category
    $id=([string]$Record.FullyQualifiedErrorId -replace '[^A-Za-z0-9_.,-]','')
    if($id.Length -gt 160){$id=$id.Substring(0,160)}
    $native=[string]$Record.Exception.Message
    if($id -match '^(?:112|39)(?:,|$)|ERROR_DISK_FULL|ERROR_HANDLE_DISK_FULL' -or $native -match '(?i)0x80070070|not enough space on the disk'){
        $reason='ENDPOINT_DISK_FULL. Windows reported insufficient disk space. Check free space and quotas on the endpoint system, profile and temporary-file volumes, then retry the remote session. A listening WinRM port does not establish that a host process can start.'
    }elseif($category -eq 'PermissionDenied' -or $native -match '(?i)access.*denied|unauthorized|0x80070005' -or $id -match 'AccessDenied'){
        $reason='ENDPOINT_ACCESS_DENIED. Check this account''s Execute access to the endpoint Microsoft.PowerShell session and the privileges required by the native probe. GPO Edit settings and Link GPOs do not grant endpoint access.'
    }elseif($id -match 'Kerberos|Authentication|Logon' -or $native -match '(?i)Kerberos|logon failure|unknown user name|user name or password|0x8009030e|0x80090322'){
        $reason='ENDPOINT_AUTHENTICATION_FAILED. Check the endpoint FQDN, domain DNS, Kerberos/SPN, clock and current delegated credentials.'
    }elseif($category -in @('OpenError','ResourceUnavailable','ConnectionError') -or $id -match 'PSSessionOpenFailed|CannotConnect|NetworkPathNotFound'){
        $reason='ENDPOINT_CONNECTION_FAILED. Check host availability, WinRM listener/service, firewall and the connection path from the selected DC to this endpoint.'
    }else{
        $reason='ENDPOINT_PROBE_FAILED. The remote command failed. Check endpoint permissions and the native security-policy tools; no effective value was established.'
    }
    return ($reason+' Error ID: '+$(if($id){$id}else{'unavailable'})+'.')
}
function Refresh-ComputerPolicy([string[]]$Computer){
    $credential=Endpoint-CredentialOptions
    # Run on the endpoint with an explicit delegated credential: no Kerberos
    # second-hop dependency. /wait:-1 plus the process deadline distinguish
    # actual process completion from mere RPC task scheduling.
    $remoteErrors=@()
    $results=@(Invoke-Command -ComputerName $Computer -Authentication Kerberos @credential -ThrottleLimit 16 -ScriptBlock {
        $process=[Diagnostics.Process]::new()
        $process.StartInfo=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\gpupdate.exe'),'/target:computer /force /wait:-1')
        $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
        $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
        try{
            $null=$process.Start()
            $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            if(!$process.WaitForExit(120000)){try{$process.Kill()}catch{};return @{state='FAILED';message='gpupdate did not complete before the 120-second deadline; client processing may still be running.'}}
            if($process.ExitCode -ne 0){return @{state='FAILED';message=('gpupdate exited with code '+$process.ExitCode+'. Review GroupPolicy Operational events.')}}
            return @{state='COMPLETED';message='gpupdate /target:computer /force /wait:-1 exited successfully. Verify values and winning GPO separately.'}
        }finally{$process.Dispose()}
    } -ErrorAction SilentlyContinue -ErrorVariable remoteErrors)
    foreach($computerName in $Computer){
        $result=@($results|Where-Object{[string]$_.PSComputerName -ieq $computerName}|Select-Object -Last 1)
        if($result.Count){$result[0];continue}
        $failure=@($remoteErrors|Where-Object{
            $origin=Read-Field $_ 'OriginInfo' $null
            $target=Read-Field $_ 'TargetObject' $null
            [string](Read-Field $origin 'PSComputerName' '') -ieq $computerName -or
            [string](Read-Field $target 'ComputerName' '') -ieq $computerName -or [string]$target -ieq $computerName
        }|Select-Object -First 1)
        if(!$failure.Count -and $Computer.Count -eq 1){$failure=@($remoteErrors|Select-Object -First 1)}
        $message=if($failure.Count){Endpoint-FailureMessage $failure[0]}else{'ENDPOINT_NO_COMPLETION. No per-host completion result was received. Check endpoint WinRM/Kerberos and execution permissions.'}
        [pscustomobject]@{PSComputerName=$computerName;state='FAILED';message=$message}
    }
}
function Verification-Page($Plan,$Fallback){
    $all=Read-Field $Plan.preview 'verificationComputers' $null
    if($null -eq $all){return @($Fallback|Sort-Object -Unique|Select-Object -First 5)}
    $requestData=Get-Variable -Name Data -ValueOnly -ErrorAction SilentlyContinue
    $offset=[int](Read-Field $requestData 'verificationOffset' 0)
    if($offset -lt 0){Fail 'INVALID_REQUEST' 'Invalid verification offset.'}
    return @($all|Select-Object -Skip $offset -First 25)
}
function Verify-EffectiveSamples($Plan,$Map){
    $s=$Plan.selection;$checks=@();$remoteCredential=Endpoint-CredentialOptions
    if([bool]$Map.domainPolicySensitive){return @()}
    if([string]$Map.scope -eq 'User'){
      $identity=[string](Read-Field $s 'verificationUser' '')
      $hosts=@(Verification-Page $Plan @($Plan.preview.refreshComputers))
      if([string]::IsNullOrWhiteSpace($identity) -or !$hosts.Count){return @(@{hostname='<user-session>';state='PENDING';message='The GPO targets the entire selected user OU. A verification user is optional and only enables a sampled HKCU check on authorized session endpoints; no per-user Apply is required.';actualValue=$null})}
      try{$user=Verification-User $identity;if(!$user.Enabled -or !([string]$user.DistinguishedName).EndsWith(','+[string]$s.scopeDn,[StringComparison]::OrdinalIgnoreCase)){throw 'User is outside the current enabled target scope'};$sid=[string]$user.SID.Value}catch{return @(@{hostname='<user-session>';state='UNAVAILABLE';message='The verification user could not be resolved.';actualValue=$null})}
      $currentHosts=@(Refresh-Targets 'Scope' $s.scopeDn ([string](Read-Field $s 'endpointScopeDn' '')) 'User');foreach($removed in @($hosts|Where-Object{$_ -notin $currentHosts})){$checks+=@{hostname=$removed;state='OUTSIDE_SCOPE';message='The pinned endpoint is no longer in the enabled authorized scope.';actualValue=$null}};$hosts=@($hosts|Where-Object{$_ -in $currentHosts})
      if(!$hosts.Count){return @(@{hostname='<user-session>';state='PENDING';message='No preview endpoint remains in the current authorized endpoint scope.';actualValue=$null})}
      $expected=@(Endpoint-Expected $Map $s)
      foreach($hostName in $hosts){
        try{
          $probe=Invoke-Command -ComputerName $hostName -Authentication Kerberos @remoteCredential -ErrorAction Stop -ArgumentList $sid,$expected -ScriptBlock {
            param($UserSid,$ExpectedItems)
            $ErrorActionPreference='Stop';$actual=@();$ok=$true
            if(!(Test-Path -LiteralPath ('Registry::HKEY_USERS\'+$UserSid))){return @{supported=$false;match=$false;actual='';message='The selected user profile hive is not loaded on this endpoint. The user must have an active or loaded profile before HKCU policy can be verified.'}}
            foreach($item in @($ExpectedItems)){
              $key=[string]$item.key;if($key -notmatch '^HKCU\\'){return @{supported=$false;match=$false;actual='';message='The user-policy verifier only accepts HKCU registry mappings.'}}
              $path='Registry::HKEY_USERS\'+$UserSid+'\'+$key.Substring(5)
              try{$value=Get-ItemPropertyValue -LiteralPath $path -Name ([string]$item.name) -ErrorAction Stop;$kind=(Get-Item -LiteralPath $path -ErrorAction Stop).GetValueKind([string]$item.name)}catch{if($_.FullyQualifiedErrorId -match 'ItemNotFound|PathNotFound|PropertyNotFound'){$value=$null;$kind=$null}else{return @{supported=$false;match=$false;actual='';message='The user registry policy could not be read because access or transport failed.'}}}
              if(([string]$item.type).ToUpperInvariant() -eq 'MULTISTRING'){$current=if($null -eq $value){$null}else{((@($value)|ForEach-Object{[string]$_}|Sort-Object)-join '|')}}else{$current=if($null -eq $value){$null}else{[string]$value}}
              $actual+=([string]$item.name+'='+$(if($null -eq $current){'<not configured>'}else{$current}));if($null -eq $current -or [string]$current -cne [string]$item.expected -or ($kind -and [string]$kind -ine [string]$item.type)){$ok=$false}
            }
            return @{supported=$true;match=$ok;actual=($actual -join '; ');message='The effective HKCU policy values were read from the selected user profile hive.'}
          }
          if([bool]$probe.supported){$checks+=@{hostname=$hostName;state=$(if([bool]$probe.match){'VERIFIED'}else{'MISMATCH'});message=([string]$probe.message+' User: '+$identity);actualValue=[string]$probe.actual}}else{$checks+=@{hostname=$hostName;state='PENDING';message=([string]$probe.message+' User: '+$identity);actualValue=[string]$probe.actual}}
        }catch{$checks+=@{hostname=$hostName;state='UNAVAILABLE';message=((Endpoint-FailureMessage $_)+' User: '+$identity);actualValue=$null}}
      }
      return @($checks)
    }
    $hosts=@();if($Plan.preview.impact -and $Plan.preview.impact.affectedObjects){$hosts+=@($Plan.preview.impact.affectedObjects.sampleHosts)};$hosts=@(Filter-EndpointHosts @(Verification-Page $Plan $hosts)|Sort-Object -Unique)
    if(!$hosts.Count){return @(@{hostname='<scope>';state='PENDING';message='No concrete endpoint is available for effective-policy verification in the selected scope.';actualValue=$null})}
    try{$liveHosts=@(Get-ADComputer -SearchBase $s.scopeDn -SearchScope Subtree -Filter {Enabled -eq $true} -Server $cfg.domainController -Properties DNSHostName -ResultSetSize 5001 -ErrorAction Stop|ForEach-Object{[string]$_.DNSHostName});foreach($removed in @($hosts|Where-Object{$_ -notin $liveHosts})){$checks+=@{hostname=$removed;state='OUTSIDE_SCOPE';message='The pinned endpoint is no longer in the enabled target scope.';actualValue=$null}};$hosts=@($hosts|Where-Object{$_ -in $liveHosts})}catch{return @(@{hostname='<scope>';state='UNAVAILABLE';message='Current endpoint scope membership could not be established.';actualValue=$null})}
    if(!$hosts.Count){return @(@{hostname='<scope>';state='PENDING';message='Preview sample endpoints no longer belong to the enabled target scope.';actualValue=$null})}
    $expected=@(Endpoint-Expected $Map $s);$handler=[string]$Map.handler
    foreach($hostName in $hosts){
      try{
        $probe=Invoke-Command -ComputerName $hostName -Authentication Kerberos @remoteCredential -ErrorAction Stop -ArgumentList $handler,$expected,([string]$Map.comparator) -ScriptBlock {
          param($Handler,$ExpectedItems,$Comparator)
          $ErrorActionPreference='Stop'
          function Read-IniValue([string]$Text,[string]$Section,[string]$Key){$inside=$false;foreach($line in ($Text -split "`r?`n")){$t=$line.Trim();if($t -match '^\[(.+)\]$'){$inside=($Matches[1] -ieq $Section);continue};if($inside -and $t -match '^([^=]+)=(.*)$' -and $Matches[1].Trim() -ieq $Key){return $Matches[2].Trim()}};return $null}
          function Normalize-Sids([string]$Raw){if($null -eq $Raw){return $null};$v=@();foreach($part in ($Raw -split ',')){if($part.Trim()){$name=$part.Trim().TrimStart('*');if($name -notmatch '^S-\d-(?:\d+-){1,14}\d+$'){$name=([Security.Principal.NTAccount]$name).Translate([Security.Principal.SecurityIdentifier]).Value};$v+=$name}};return (($v|Sort-Object -Unique)-join ',')}
          function Value-Matches($Current,$Expected,[string]$Rule){
            if($null -eq $Current){return $false}
            if($Rule -in @('>=','<=','atMost','==')){
              $a=0.0;$b=0.0
              if(![double]::TryParse([string]$Current,[Globalization.NumberStyles]::Any,[Globalization.CultureInfo]::InvariantCulture,[ref]$a) -or ![double]::TryParse([string]$Expected,[Globalization.NumberStyles]::Any,[Globalization.CultureInfo]::InvariantCulture,[ref]$b)){return $false}
              switch($Rule){'>=' {return $a -ge $b} '<=' {return $a -gt 0 -and $a -le $b} 'atMost' {return $a -ge 0 -and $a -le $b} '==' {return $a -eq $b}}
            }
            return [string]$Current -ceq [string]$Expected
          }
          $actual=@();$ok=$true
          # The policy registry is configuration input. Firewall evidence must
          # additionally query the resultant active store (GPO + local merges).
          if($Handler -in @('Registry','RegistrySet') -and @($ExpectedItems).Count -gt 0 -and @($ExpectedItems|Where-Object{[string]$_.key -notmatch '^HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\(Domain|Private|Public)Profile(?:\\Logging)?$'}).Count -eq 0){
            $properties=@{EnableFirewall='Enabled';DefaultInboundAction='DefaultInboundAction';DisableNotifications='NotifyOnListen';LogFilePath='LogFileName';LogFileSize='LogMaxSizeKilobytes';LogDroppedPackets='LogBlocked';LogSuccessfulConnections='LogAllowed';AllowLocalPolicyMerge='AllowLocalFirewallRules';AllowLocalIPsecPolicyMerge='AllowLocalIPsecRules'}
            foreach($item in @($ExpectedItems)){
              $null=[string]$item.key -match '\\(Domain|Private|Public)Profile';$profileName=$Matches[1];$property=$properties[[string]$item.name]
              if(!$property){return @{supported=$false;match=$false;actual='';message='No active firewall property mapping exists for this registry field.'}}
              try{$profiles=@(Get-NetFirewallProfile -Name $profileName -PolicyStore ActiveStore -ErrorAction Stop);if($profiles.Count -ne 1){throw 'Ambiguous active profile'};$value=$profiles[0].PSObject.Properties[$property].Value;if($null -eq $value -or [string]$value -eq 'NotConfigured'){throw 'No effective value'}}catch{return @{supported=$false;match=$false;actual='';message='Active firewall profile evidence is unavailable. A registry value alone is insufficient.'}}
              $expected=[string]$item.expected
              switch([string]$item.name){
                'DefaultInboundAction' {$current=switch([string]$value){'Block'{'1'}'Allow'{'0'}default{'<unknown>'}}}
                'DisableNotifications' {$current=switch([string]$value){'True'{'0'}'False'{'1'}default{'<unknown>'}}}
                {$_ -in @('EnableFirewall','LogDroppedPackets','LogSuccessfulConnections','AllowLocalPolicyMerge','AllowLocalIPsecPolicyMerge')} {$current=switch([string]$value){'True'{'1'}'False'{'0'}default{'<unknown>'}}}
                'LogFilePath' {$current=[Environment]::ExpandEnvironmentVariables([string]$value);$expected=[Environment]::ExpandEnvironmentVariables($expected)}
                default {$current=[string]$value}
              }
              $actual+=($profileName+'.'+$property+'='+[string]$value)
              if([string]$item.name -eq 'LogFilePath'){if($current -ine $expected){$ok=$false}}elseif(!(Value-Matches $current $expected $(if($item.comparator){$item.comparator}else{$Comparator}))){$ok=$false}
            }
            return @{supported=$true;match=$ok;actual=($actual -join '; ');message='Resultant firewall profile configuration was read from Get-NetFirewallProfile -PolicyStore ActiveStore. This does not prove packet-level enforcement or service health.'}
          }
          if($Handler -in @('Registry','RegistrySet')){
            foreach($item in @($ExpectedItems)){$key=[string]$item.key;if($key -notmatch '^HKLM\\'){return @{supported=$false;match=$false;actual='';message='Only computer-scope HKLM registry policies can be verified without a user session.'}};$path='Registry::HKEY_LOCAL_MACHINE\'+$key.Substring(5);try{$v=Get-ItemPropertyValue -LiteralPath $path -Name ([string]$item.name) -ErrorAction Stop;$kind=(Get-Item -LiteralPath $path -ErrorAction Stop).GetValueKind([string]$item.name);if([string]$kind -ine [string]$item.type){$ok=$false;$actual+=([string]$item.name+' type='+[string]$kind+' (expected '+[string]$item.type+')')}}catch{if($_.FullyQualifiedErrorId -match 'ItemNotFound|PathNotFound|PropertyNotFound'){$v=$null}else{return @{supported=$false;match=$false;actual='';message='Registry policy could not be read because access or transport failed.'}}};if(([string]$item.type).ToUpperInvariant() -eq 'MULTISTRING'){$cur=if($null -eq $v){$null}else{((@($v)|ForEach-Object{[string]$_}|Sort-Object)-join '|')}}else{$cur=if($null -eq $v){$null}else{[string]$v}};$actual+=([string]$item.name+'='+$(if($null -eq $cur){'<not configured>'}else{$cur}));if(!(Value-Matches $cur $item.expected $(if($item.comparator){$item.comparator}else{$Comparator}))){$ok=$false}}
            return @{supported=$true;match=$ok;actual=($actual -join '; ');message='Endpoint policy registry values were read directly. This evidence does not prove runtime enforcement; restart, logon, service and tamper-protection requirements still apply.'}
          }
          if($Handler -eq 'SecurityTemplate'){
            $samKeys=@('EnableGuestAccount','EnableAdminAccount','NewGuestName','NewAdministratorName')
            if(@($ExpectedItems).Count -gt 0 -and @($ExpectedItems|Where-Object{[string]$_.section -ne 'System Access' -or [string]$_.key -notin $samKeys}).Count -eq 0){
              # These settings describe built-in SAM accounts. An exported INF
              # may omit them; identify the live account by RID, never its name.
              $accounts=@()
              try{
                if(Get-Command Get-LocalUser -ErrorAction SilentlyContinue){
                  $accounts=@(Get-LocalUser -ErrorAction Stop|Where-Object{[string]$_.PrincipalSource -eq 'Local'}|ForEach-Object{
                    if($_.Enabled -isnot [bool]){throw 'Account enabled flag unavailable'}
                    [pscustomobject]@{name=[string]$_.Name;sid=[string]$_.SID;enabled=[bool]$_.Enabled}
                  })
                }else{
                  $role=Get-CimInstance Win32_ComputerSystem -Property DomainRole -ErrorAction Stop
                  if($null -eq $role.DomainRole -or [int]$role.DomainRole -notin @(0,1,2,3)){throw 'A local SAM endpoint role was not established'}
                  $accounts=@(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND (SID LIKE '%-500' OR SID LIKE '%-501')" -ErrorAction Stop|Where-Object{$_.LocalAccount -eq $true}|ForEach-Object{
                    if($_.Disabled -isnot [bool]){throw 'Account disabled flag unavailable'}
                    [pscustomobject]@{name=[string]$_.Name;sid=[string]$_.SID;enabled=(-not [bool]$_.Disabled)}
                  })
                }
              }catch{return @{supported=$false;match=$false;actual='';message='Local built-in account state could not be read. Check local SAM read permissions and endpoint role. No account state was established.'}}
              foreach($item in @($ExpectedItems)){
                $key=[string]$item.key;$rid=if($key -in @('EnableGuestAccount','NewGuestName')){501}else{500}
                $account=@($accounts|Where-Object{$_.sid -match ('^S-1-5-21-(?:\d+-){2}\d+-'+$rid+'$')})
                if($account.Count -ne 1 -or [string]::IsNullOrWhiteSpace($account[0].name)){return @{supported=$false;match=$false;actual='';message=('Exactly one local built-in RID '+$rid+' account could not be established. Domain accounts are not substituted for local SAM evidence.')}}
                $current=if($key -like 'Enable*'){[string][int][bool]$account[0].enabled}else{[string]$account[0].name}
                $actual+=($key+'='+$current+' (account='+$account[0].name+'; SID='+$account[0].sid+')')
                if(!(Value-Matches $current $item.expected $(if($item.comparator){$item.comparator}else{$Comparator}))){$ok=$false}
              }
              return @{supported=$true;match=$ok;actual=($actual -join '; ');message='Live local built-in account state was read by SID/RID. This establishes the observed account state, not which GPO caused it or whether the application refresh completed.'}
            }
            $tmp=Join-Path $env:TEMP ('gpo-remediator-'+[guid]::NewGuid().ToString('N')+'.inf');try{& secedit.exe /export /mergedpolicy /cfg $tmp /quiet | Out-Null;if($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $tmp)){return @{supported=$false;match=$false;actual='';message='secedit could not export merged security policy.'}};$text=[IO.File]::ReadAllText($tmp);foreach($item in @($ExpectedItems)){$cur=Read-IniValue $text ([string]$item.section) ([string]$item.key);if([string]$item.type -eq 'Principals' -and $null -ne $cur){$cur=Normalize-Sids $cur}elseif([string]$item.type -eq 'QuotedString' -and $null -ne $cur){$cur=$cur.Trim().Trim('"')};$actual+=([string]$item.key+'='+$(if($null -eq $cur){'<not configured>'}else{$cur}));if($null -eq $cur){$ok=$false}elseif($Comparator -eq 'includes' -and [string]$item.type -eq 'Principals'){if(@(([string]$item.expected -split ',')|Where-Object{$_ -and $_ -notin @($cur -split ',')}).Count){$ok=$false}}elseif(!(Value-Matches $cur $item.expected $(if($item.comparator){$item.comparator}else{$Comparator}))){$ok=$false}};return @{supported=$true;match=$ok;actual=($actual -join '; ');message='Effective security policy was exported with secedit.'}}finally{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}
          }
          if($Handler -eq 'AdvancedAudit'){
            # /get /r may contain only five columns and localized Setting text.
            # /backup uses the restorable seven-column numeric policy format.
            $auditFile=Join-Path $env:TEMP ('gpo-remediator-audit-'+[guid]::NewGuid().ToString('N')+'.csv')
            try{
              & auditpol.exe /backup ('/file:'+$auditFile) 2>$null | Out-Null
              if($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $auditFile)){return @{supported=$false;match=$false;actual='';message='auditpol could not export effective policy. Check audit-policy read/export privileges on this endpoint.'}}
              $auditRows=@(Get-Content -LiteralPath $auditFile -Encoding UTF8 | ConvertFrom-Csv)
              try{$override=Get-ItemPropertyValue -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -ErrorAction Stop;$actual+=('SCENoApplyLegacyAuditPolicy='+[string]$override)}catch{$actual+='SCENoApplyLegacyAuditPolicy=<not available>'}
            foreach($item in @($ExpectedItems)){
              try{
                $rows=@($auditRows|Where-Object{
                  $columns=@($_.PSObject.Properties.Value)
                  $columns.Count -eq 7 -and [string]$columns[3] -ieq [string]$item.guid -and [string]$columns[1] -eq 'System' -and [string]$columns[5] -eq ''
                })
                if($rows.Count -ne 1){return @{supported=$false;match=$false;actual='';message='auditpol did not return exactly one row for the requested subcategory GUID.'}}
                $row=$rows[0];$value=[string]($row.PSObject.Properties.Value|Select-Object -Last 1);$numeric=0
                if(![int]::TryParse($value,[ref]$numeric) -or $numeric -lt 1 -or $numeric -gt 4){return @{supported=$false;match=$false;actual=$value;message='auditpol export did not expose a valid explicit numeric setting (1-4).'}}
                if($numeric -eq 4){$numeric=0}
                $label=switch($numeric){0{'No Auditing'}1{'Success'}2{'Failure'}3{'Success and Failure'}}
                $expectedMask=[int]$item.expected;$actual+=([string]$item.guid+'='+$numeric+' ('+$label+')');if($Comparator -eq 'includes'){if(($numeric -band $expectedMask) -ne $expectedMask){$ok=$false}}elseif($numeric -ne $expectedMask){$ok=$false}
              }catch{return @{supported=$false;match=$false;actual='';message='Effective advanced-audit probe is unavailable on this endpoint.'}}
            }
            return @{supported=$true;match=$ok;actual=($actual -join '; ');message=$(if($ok){'Effective advanced-audit settings match the requested values on this sampled endpoint. This does not identify the winning GPO or prove refresh completion.'}else{'Effective advanced-audit settings differ from the requested values. Check policy processing, winning GPO and control 2.3.2.1 (subcategory override).'})}
            }finally{Remove-Item -LiteralPath $auditFile -Force -ErrorAction SilentlyContinue}
          }
          return @{supported=$false;match=$false;actual='';message='No endpoint verifier exists for this handler.'}
        }
        if([bool]$probe.supported){$checks+=@{hostname=$hostName;state=$(if([bool]$probe.match){'VERIFIED'}else{'MISMATCH'});message=[string]$probe.message;actualValue=[string]$probe.actual}}else{$checks+=@{hostname=$hostName;state='PENDING';message=[string]$probe.message;actualValue=[string]$probe.actual}}
      }catch{$checks+=@{hostname=$hostName;state='UNAVAILABLE';message=(Endpoint-FailureMessage $_);actualValue=$null}}
    }
    return @($checks)
}
function Verify-Published($Plan,$Map,[bool]$CheckEndpoints=$false){
    $s=$Plan.selection;$metadata=Verification-Metadata $s;$published=(Mapping-Matches $s.gpoId $Map $s) -and [bool]$metadata.versionsMatch;$link=Selected-Link $s.scopeDn $s.gpoId;$linked=$null -ne $link -and $link.enabled -and (!$s.firstLink -or $link.order -eq 1);$effective='GPO_VALUE_VERIFIED_ENDPOINT_PENDING';$endpointChecks=@()
    if([bool]$Map.domainPolicySensitive){$policy=Get-ADDefaultDomainPasswordPolicy -Identity $domainDn -Server $cfg.domainController;$actual=$null;switch([string]$Map.id){'1.1.1'{$actual=$policy.PasswordHistoryCount}'1.1.3'{$actual=$policy.MinPasswordAge.TotalDays}'1.1.4'{$actual=$policy.MinPasswordLength}'1.1.5'{$actual=[int][bool]$policy.ComplexityEnabled}'1.1.6'{$actual=[int][bool]$policy.ReversibleEncryptionEnabled}'1.2.1'{$actual=$policy.LockoutDuration.TotalMinutes}'1.2.2'{$actual=$policy.LockoutThreshold}'1.2.4'{$actual=$policy.LockoutObservationWindow.TotalMinutes}};if($null -eq $actual){$effective='DOMAIN_VALUE_NOT_EXPOSED_BY_AD_CMDLET'}elseif(Numeric-Complies $actual (Desired-Normalized $Map @($Map.items)[0] $s) ([string]$Map.comparator)){$effective='DOMAIN_VALUE_MATCHES_ON_SELECTED_DC'}else{$effective='DOMAIN_VALUE_PENDING_OR_OVERRIDDEN'}}elseif($CheckEndpoints){$endpointChecks=@(Verify-EffectiveSamples $Plan $Map);if(@($endpointChecks|Where-Object{$_.state -eq 'MISMATCH'}).Count){$effective='ENDPOINT_MISMATCH'}elseif(@($endpointChecks|Where-Object{$_.state -eq 'VERIFIED'}).Count -gt 0 -and @($endpointChecks|Where-Object{$_.state -ne 'VERIFIED'}).Count -eq 0){$effective='VERIFIED_ON_SAMPLE'}else{$effective='ENDPOINT_VERIFICATION_PENDING'}}
    $coverage=$null;$all=Read-Field $Plan.preview 'verificationComputers' $null
    if($CheckEndpoints -and $null -ne $all -and ![bool]$Map.domainPolicySensitive){$offset=[int](Read-Field (Get-Variable Data -ValueOnly -ErrorAction SilentlyContinue) 'verificationOffset' 0);$count=@($all).Count;$coverage=@{total=$count;checked=[math]::Min($offset+25,$count);complete=($offset+25 -ge $count)};if(!$coverage.complete -and $effective -eq 'VERIFIED_ON_SAMPLE'){$effective='ENDPOINT_VERIFICATION_PENDING'}}
    # Never display endpoint effectiveness as verified when the source GPO or target link is wrong.
    # A matching sample is evidence only for inspected hosts; a scheduled gpupdate is not evidence.
    if(!$published){$effective='GPO_PUBLICATION_MISMATCH'}
    elseif(!$linked){$effective='GPO_LINK_MISMATCH'}
    elseif(!$metadata.replicationConverged -and $effective -ne 'ENDPOINT_MISMATCH'){$effective='REPLICATION_PENDING'}
    return @{published=[bool]$published;linked=[bool]$linked;effective=$effective;verification=$metadata;endpointChecks=@($endpointChecks);endpointCoverage=$coverage;currentValue=(Mapping-Display $s.gpoId $Map $s $false)}
}
function Verify-Rollback($Plan,$Map,$Manifest){
    $s=$Plan.selection
    $matches=(Get-NormalizedGpoContentFingerprint (Gpo-Folder $s.gpoId)) -ceq [string]$Manifest.beforeContent
    $matches=$matches -and (Snapshot-ExtensionsMatch $Manifest $s.gpoId $s) -and ((Scope-Links $s.scopeDn) -ceq [string]$Plan.preview.scopeLinks)
    return @{restored=[bool]$matches;published=$false;linked=$false;effective='ROLLBACK_ENDPOINT_PENDING';verification=(Verification-Metadata $s);endpointChecks=@();currentValue=(Mapping-Display $s.gpoId $Map $s $false)}
}
function Filter-EndpointHosts([string[]]$Hosts){
    $allowed=@(Read-Field $cfg 'allowedHosts' @())
    $mode=[string](Read-Field $cfg 'endpointTargeting' '')
    if(!$mode){$mode=if($allowed.Count){'ExplicitHosts'}else{'SelectedOu'}}
    if($mode -notin @('SelectedOu','ExplicitHosts')){Fail 'INVALID_ENDPOINT_TARGETING' 'Choose selected OU or explicit endpoint hosts.'}
    if($mode -eq 'ExplicitHosts'){return @($Hosts|Where-Object{$_ -and $_ -in $allowed})}
    # Only accept concrete DNS names in the configured domain from the scoped AD query.
    $suffix='.'+[string]$cfg.domain
    return @($Hosts|Where-Object{$_ -and $_.Length -le 253 -and $_ -match '^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$' -and $_.EndsWith($suffix,[StringComparison]::OrdinalIgnoreCase)})
}
function Refresh-Targets([string]$Strategy,[string]$ScopeDn,[string]$EndpointScopeDn='', [string]$PolicyScope='Computer'){
    $targets=@()
    switch($Strategy){
        'None' {return @()}
        'Pdc' {if($PolicyScope -eq 'User'){Fail 'USER_REFRESH_TARGET_INVALID' 'User policy cannot be refreshed on the PDC without a user session.'};if($PolicyScope -ne 'Domain'){Fail 'PDC_REFRESH_SCOPE_INVALID' 'PDC refresh is only valid for domain-account-policy controls.'};$targets=@([string]$domain.PDCEmulator)}
        'Scope' {$searchDn=if($PolicyScope -eq 'User'){$EndpointScopeDn}else{$ScopeDn};if([string]::IsNullOrWhiteSpace($searchDn)){Fail 'ENDPOINT_SCOPE_REQUIRED' 'Choose a computer OU for policy refresh.'};$null=Scope $searchDn;$objects=@(Get-ADComputer -SearchBase $searchDn -SearchScope Subtree -Filter {Enabled -eq $true} -Server $cfg.domainController -Properties DNSHostName -ResultSetSize 5001);if($objects.Count -gt 5000){Fail 'REFRESH_SCOPE_TOO_LARGE' 'More than 5,000 computers are in the refresh scope. Choose a smaller endpoint OU.'};$targets=@($objects|Where-Object{$_.DNSHostName}|ForEach-Object{[string]$_.DNSHostName})}
        default {Fail 'GPO_OPTIONS_INVALID' 'Choose PDC or scope computers.'}
    }
    return @(Filter-EndpointHosts $targets|Sort-Object -Unique)
}
function Run-Directory($Plan){if($Plan.id -notmatch '^[a-f0-9]{32}$' -or $Plan.domain -ine $cfg.domain -or $Plan.domainController -ine $cfg.domainController){Fail 'PLAN_CONTEXT_CHANGED' 'Plan context does not match the selected DC/domain.'};$root=[IO.Path]::GetFullPath([string]$cfg.backupPath);if($root -notmatch '^[A-Za-z]:\\'){Fail 'BACKUP_PATH_INVALID' 'A local backup path on the selected DC is required.'};return Join-Path $root ('GpoWorkflow\'+$Plan.id)}
function Save-Manifest($Manifest,[string]$Directory){Atomic-Text (Join-Path $Directory 'manifest.json') ($Manifest|ConvertTo-Json -Depth 50) ([Text.UTF8Encoding]::new($false))}
function Read-Field($Object,[string]$Name,$Default=$null){
    if($null -eq $Object){return $Default}
    if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default}
    $property=$Object.PSObject.Properties[$Name];if($property){return $property.Value};return $Default
}
function Result([string]$State,[string]$Message,$Manifest,$V,$Refresh){
    $verification=Read-Field $V 'verification' $null
    $endpointChecks=@(Read-Field $V 'endpointChecks' @())
    $backupId=Read-Field $Manifest 'backupId' $null
    $backupDirectory=Read-Field $Manifest 'directory' $null
    $postFingerprint=Read-Field $Manifest 'postFingerprint' $null
    return @{state=$State;message=$Message;backupId=$backupId;backupDirectory=$backupDirectory;postFingerprint=$postFingerprint;gpoPublished=[bool](Read-Field $V 'published' $false);linkVerified=[bool](Read-Field $V 'linked' $false);refreshResults=@($Refresh);effectiveStatus=[string](Read-Field $V 'effective' 'UNKNOWN');verification=$verification;endpointChecks=$endpointChecks;currentValue=Read-Field $V 'currentValue' $null;endpointCoverage=Read-Field $V 'endpointCoverage' $null}
}

function Operation-Failure($Record,[string]$Stage){
    $message=[string]$Record.Exception.Message
    if($message -match '^([A-Z][A-Z0-9_]+)\|(.+)$'){return @{code=$Matches[1];message=$Matches[2];stage=$Stage}}
    $denied=$Record.CategoryInfo.Category -eq 'PermissionDenied' -or $message -match '(?i)access.*denied|unauthorized|0x80070005'
    $code=if($denied){'GPO_NATIVE_ACCESS_DENIED'}else{'GPO_NATIVE_FAILURE'}
    $guidance=switch -Regex ($Stage){
        '^BACKUP' {'Check Modify access on the backup repository on the selected DC for the execution account, including GpoWorkflow and existing child files.';break}
        '^WRITING' {'Check Edit settings on the selected GPO, SYSVOL policy file write access, and AD version/CSE attribute write access.';break}
        '^LINK' {'Check Link GPOs delegation on the selected OU/domain.';break}
        '^RESTOR' {'Check GPO Edit settings, link delegation and the retained backup. Verify live state before retrying recovery.';break}
        default {'Inspect the selected GPO, target link and DC connectivity. Use Verify before retrying a write.'}
    }
    # Product-owned context only: no raw exception text, data values or credentials.
    $reason=([string]$Record.CategoryInfo.Reason) -replace '[^A-Za-z0-9_.]',''
    $command=([string](Read-Field $Record.InvocationInfo.MyCommand 'Name' 'native operation')) -replace '[^A-Za-z0-9_.-]',''
    $line=[int]$Record.InvocationInfo.ScriptLineNumber
    return @{code=$code;stage=$Stage;message=('Stage '+$Stage+' failed ('+$reason+', '+$command+', worker line '+$line+'). '+$guidance)}
}
function Emit-Stage([string]$Name){$script:workerStage=$Name;if([bool](Read-Field $cfg 'emitProgress' $false)){Write-Output ([pscustomobject]@{gpoStage=$Name})}}
# FGPP_FUNCTIONS
# DIAGNOSTIC_FUNCTIONS
$script:workerStage='VALIDATING'
try {
switch($Operation){
    'fgppPreview'{return Fgpp-Preview $Data.request @(Read-Field $Data 'previousUsers' @())}
    'fgppApply'{return Fgpp-Execute 'apply' $Data.plan}
    'fgppVerify'{return Fgpp-Execute 'verify' $Data.plan}
    'fgppRollback'{return Fgpp-Execute 'rollback' $Data.plan}
    'gpoReadiness'{return Environment-Status}
    'gpoInventory'{$gpos=@(Get-GPO -All -Domain $cfg.domain -Server $cfg.domainController|Sort-Object DisplayName|ForEach-Object{Gpo-Choice $_});if($gpos.Count -gt 5000){Fail 'DIRECTORY_TOO_LARGE' 'More than 5000 GPOs exist. Narrow the configured domain.'};return @{domain=$domain.DNSRoot;domainController=$dc.HostName;executionUser=[Security.Principal.WindowsIdentity]::GetCurrent().Name;gpos=$gpos;scopes=@(Scopes)}}
    'gpoExplain'{return Explain-Policy $Data.plan $Data.mapping ([string]$Data.hostname)}
    'gpoPreview'{if([bool](Read-Field $Data 'accessReport' $false)){return Access-Report $Data.selection $Data.mapping};if([bool](Read-Field $Data 'accessOnly' $false)){$access=Assert-SelectionAccess $Data.selection $Data.mapping;return @{authorized=$true;executionUser=$access.executionUser}};return Preview $Data.selection $Data.mapping ([bool](Read-Field $Data 'requireWriteAccess' $true))}
    'gpoApply'{
        Emit-Stage 'PREFLIGHT'
        $plan=$Data.plan;$map=$Data.mapping;$s=$plan.selection;Validate-Selection $s $map;$null=Assert-SelectionAccess $s $map;Emit-Stage 'BACKUP_DIRECTORY';$directory=Run-Directory $plan;$null=New-Item -ItemType Directory -Path $directory -Force;$lockRoot=Split-Path $directory -Parent;$lock=$null
        try{$lock=[IO.File]::Open((Join-Path $lockRoot (([guid]$s.gpoId).ToString()+'.lock')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{Fail 'GPO_BUSY' 'Another operation is writing this GPO.'}
        $manifest=$null
        try{
            if(Test-Path -LiteralPath (Join-Path $directory 'manifest.json')){Fail 'GPO_ALREADY_STARTED' 'A durable execution manifest already exists. Verify or recover; do not replay Apply.'}
            Emit-Stage 'PREFLIGHT'
            $fresh=Preview $s $map;if(!$fresh.preflight.ready){Fail 'ENVIRONMENT_NOT_READY' 'Required environment preflight checks must pass before Apply.'}
            if($fresh.fingerprint -cne $plan.preview.fingerprint -or (@($fresh.refreshComputers)-join '|') -cne (@($plan.preview.refreshComputers)-join '|')){Fail 'GPO_CHANGED' 'GPO, links or refresh targets changed after preview. Prepare a new plan.'}
            if([bool]$fresh.noChange){$v=Verify-Published $plan $map $true;$state=if($v.published -and $v.linked){'NO_CHANGE'}else{'VERIFY_MISMATCH'};return Result $state 'No policy write was required. Live content, link and AD/SYSVOL versions were checked; inspect the verification result before claiming publication.' $null $v @()}
            $beforeAd=Gpo-Ad $s.gpoId
            $manifest=[ordered]@{plan=$plan;mappingId=[string]$map.id;mappingSource=[string]$map.source;approval=$Data.consent;backupId=$null;directory=$directory;preFingerprint=$fresh.fingerprint;postFingerprint=$null;phase='BACKUP_STARTED';beforeContent=(Get-NormalizedGpoContentFingerprint (Gpo-Folder $s.gpoId));beforeExtensions=[string]$beforeAd.gPCMachineExtensionNames;beforeUserExtensions=[string]$beforeAd.gPCUserExtensionNames};Save-Manifest $manifest $directory
            Emit-Stage 'BACKUP'
            $backup=Backup-GPO -Guid ([guid]$s.gpoId) -Path $directory -Domain $cfg.domain -Server $cfg.domainController -Comment ('GpoRemediator '+$plan.id)
            $manifest.backupId=$backup.Id.ToString();$manifest.phase='BACKED_UP';Save-Manifest $manifest $directory
            if((Fingerprint $s.gpoId $s.scopeDn) -cne $plan.preview.fingerprint){Fail 'GPO_CHANGED' 'GPO changed during backup; no policy write started.'}
            Emit-Stage 'WRITING'
            $manifest.phase='WRITING';Save-Manifest $manifest $directory;$null=Write-Mapping $plan $map
            Emit-Stage 'LINKING'
            if(Link-ChangeRequired $s $fresh.existingLink){
            if($null -eq $fresh.existingLink){$p=@{Guid=[guid]$s.gpoId;Target=$s.scopeDn;Domain=$cfg.domain;Server=$cfg.domainController;LinkEnabled='Yes'};if($s.firstLink){$p.Order=1};New-GPLink @p|Out-Null}else{$p=@{Guid=[guid]$s.gpoId;Target=$s.scopeDn;Domain=$cfg.domain;Server=$cfg.domainController;LinkEnabled='Yes'};if($s.firstLink){$p.Order=1};Set-GPLink @p|Out-Null}
            }
            Emit-Stage 'PUBLICATION_CHECK'
            $v=Verify-Published $plan $map $false;$manifest.postFingerprint=Fingerprint $s.gpoId $s.scopeDn;$manifest.phase=if(!$v.published -or !$v.linked){'VERIFY_MISMATCH'}else{'PUBLISHED'};Save-Manifest $manifest $directory
            # Do not force endpoint refresh as a side effect of Apply. Publication and refresh are
            # intentionally separate operator decisions so the change result is visible first.
            $state=if(!$v.published -or !$v.linked){'VERIFY_MISMATCH'}else{'PUBLISHED'};return Result $state 'GPO content and selected link were read back after the write. gpupdate /force was not run automatically; use the explicit Refresh action after reviewing this result.' $manifest $v @()
        }catch{
            $failure=Operation-Failure $_ $script:workerStage
            if($manifest){
                $manifest['failure']=$failure
                $preWrite=([string]$manifest.phase -in @('BACKUP_STARTED','BACKED_UP'))
                $manifest.phase=if($preWrite){'FAILED_SAFE'}else{'REVIEW_REQUIRED'};Save-Manifest $manifest $directory
                $message=if($preWrite){'Apply stopped before the policy write began. The backup/manifest were retained and no policy change should be assumed.'}else{'Operation did not finish after the write phase began. The full Backup-GPO snapshot and manifest are on the selected DC. Use Verify; partial writes require administrator review.'}
                return Result $manifest.phase ($message+' '+$failure.message) $manifest @{published=$false;linked=$false;effective='UNKNOWN';currentValue=$null} @()
            }
            throw
        }finally{if($lock){$lock.Dispose()}}
    }
    'gpoVerify'{
        Emit-Stage 'REPLICATION_ENDPOINT_CHECK'
        $plan=$Data.plan;$map=$Data.mapping;$directory=Run-Directory $plan
        if(!(Test-Path -LiteralPath (Join-Path $directory 'manifest.json'))){
            $v=Verify-Published $plan $map $true
            $state=if($v.published -and $v.linked){'NO_CHANGE'}else{'DRIFT_DETECTED'}
            $message=if($state -eq 'DRIFT_DETECTED'){'Current GPO content or link no longer matches the requested state. The previous success state has been invalidated; generate a fresh plan before remediation.'}else{'Read-only verification completed; the current GPO/link still matches the requested state.'}
            return Result $state $message $null $v @()
        }
        $manifest=Get-Content -LiteralPath (Join-Path $directory 'manifest.json') -Raw|ConvertFrom-Json
        if([string]$manifest.phase -in @('ROLLING_BACK','ROLLED_BACK','ROLLBACK_REVIEW_REQUIRED','ROLLBACK_DRIFT_DETECTED')){
            $contentMatches=(Get-NormalizedGpoContentFingerprint (Gpo-Folder $plan.selection.gpoId)) -ceq [string]$manifest.beforeContent
            $extensionMatches=Snapshot-ExtensionsMatch $manifest $plan.selection.gpoId $plan.selection
            $linkMatches=((Scope-Links $plan.selection.scopeDn) -ceq [string]$plan.preview.scopeLinks)
            $rolledBack=$contentMatches -and $extensionMatches -and $linkMatches
            $v=@{published=$false;linked=$false;effective='ROLLBACK_ENDPOINT_PENDING';verification=(Verification-Metadata $plan.selection);endpointChecks=@();currentValue=(Mapping-Display $plan.selection.gpoId $map $plan.selection $false)}
            if($rolledBack){
                $manifest.phase='ROLLED_BACK';Save-Manifest $manifest $directory
                return Result 'ROLLED_BACK' 'Rollback was re-verified against the pre-change GPO content, extensions and link state. Endpoint policy convergence may still be pending.' $manifest $v @()
            }
            $manifest.phase='ROLLBACK_DRIFT_DETECTED';Save-Manifest $manifest $directory
            return Result 'ROLLBACK_DRIFT_DETECTED' 'The GPO or selected link changed after rollback. The rollback record is preserved, but the current state no longer matches the pre-change snapshot.' $manifest $v @()
        }
        if([string]$manifest.phase -in @('BACKUP_STARTED','BACKED_UP','FAILED_SAFE','WRITING','REVIEW_REQUIRED')){
            $v=Verify-Published $plan $map $true
            return Result 'REVIEW_REQUIRED' 'This execution did not record a completed publication. Live values were inspected, but partial writes and the retained backup/manifest require administrator review.' $manifest $v @()
        }
        $v=Verify-Published $plan $map $true
        $state=if($v.published -and $v.linked){'PUBLISHED'}else{'DRIFT_DETECTED'}
        $message=if($state -eq 'DRIFT_DETECTED'){'Drift detected: the live GPO content or selected link changed after Apply. This operation is no longer compliant until it is remediated again.'}else{'Read-only verification completed against the live GPO, link, replication metadata and available endpoint evidence.'}
        return Result $state $message $manifest $v @()
    }
    'gpoRefresh'{
        Emit-Stage 'REFRESH_PREFLIGHT'
        $plan=$Data.plan;$map=$Data.mapping;$directory=Run-Directory $plan;$manifest=$null;if(Test-Path -LiteralPath (Join-Path $directory 'manifest.json')){$manifest=Get-Content -LiteralPath (Join-Path $directory 'manifest.json') -Raw|ConvertFrom-Json}
        $rollback=$manifest -and [string]$manifest.phase -eq 'ROLLED_BACK'
        if($manifest -and [string]$manifest.phase -notin @('PUBLISHED','VERIFY_MISMATCH','ROLLED_BACK')){Fail 'REFRESH_REVIEW_REQUIRED' 'Verify the interrupted execution before refresh.'}
        if(!$manifest -and [string](Read-Field $Data.previous 'state' '') -ne 'NO_CHANGE'){Fail 'REFRESH_REVIEW_REQUIRED' 'No completed execution is available for refresh.'}
        $before=if($rollback){Verify-Rollback $plan $map $manifest}else{Verify-Published $plan $map $false}
        if($rollback){if(!$before.restored){Fail 'ROLLBACK_DRIFT_DETECTED' 'Restored GPO content or links changed. Refresh is blocked.'}}
        elseif(!$before.published -or !$before.linked){Fail 'DRIFT_DETECTED' 'Live GPO content or link changed. Refresh is blocked.'}
        $strategy=[string](Read-Field $Data 'refresh' '')
        if(!$strategy){$strategy=[string]$plan.selection.refresh}
        $domainPolicy=[bool](Read-Field $map 'domainPolicySensitive' ([string]$map.scope -eq 'Domain'))
        if($strategy -eq 'Pdc' -and !$domainPolicy){Fail 'PDC_REFRESH_SCOPE_INVALID' 'PDC refresh is only valid for domain account policy. Use the recorded endpoint scope.'}
        if($strategy -eq 'Scope' -and $domainPolicy){Fail 'DOMAIN_REFRESH_SCOPE_INVALID' 'Domain account policy requires PDC refresh or the normal cycle.'}
         $endpointScope=[string](Read-Field $plan.selection 'endpointScopeDn' '')
         $computers=@(Refresh-Targets $strategy $plan.selection.scopeDn $endpointScope ([string]$map.scope))
        $liveComputers=@($computers);$pinned=Read-Field $plan.preview 'verificationComputers' $null
        if($strategy -eq 'Scope' -and $null -ne $pinned){$computers=@($pinned)}
        if(!$computers.Count){return Result $(if($rollback){'ROLLED_BACK'}else{'REFRESH_NOT_CONFIGURED'}) 'No authorized refresh hosts are available. Choose the endpoint OU and automatic OU targeting, or configure explicit hosts in Settings.' $manifest $before @()}
        Emit-Stage 'GPUPDATE'
        $refresh=@();$target=if($rollback){'Both'}elseif([string]$map.scope -eq 'User'){'User'}else{'Computer'}
        $refreshCoverage=$null
        if(((!$rollback -and $target -eq 'Computer') -or ($rollback -and [string]$map.scope -eq 'Computer')) -and (Endpoint-CredentialOptions).Count){
            $offset=[int](Read-Field $Data 'refreshOffset' 0);if($offset -lt 0){Fail 'INVALID_REQUEST' 'Invalid refresh offset.'}
            $total=$computers.Count;$computers=@($computers|Select-Object -Skip $offset -First 64)
            $runTargets=@($computers|Where-Object{$_ -in $liveComputers})
            $done=@();if($runTargets.Count){$done=@(Refresh-ComputerPolicy $runTargets)}
            foreach($computer in $computers){$entry=@($done|Where-Object{[string]$_.PSComputerName -ieq $computer}|Select-Object -Last 1);if($entry.Count){$refresh+=@{computer=$computer;state=[string]$entry[0].state;message=[string]$entry[0].message}}else{$refresh+=@{computer=$computer;state='FAILED';message='No completion result. Check endpoint WinRM/Kerberos and execution permissions.'}}}
            $refreshCoverage=@{total=$total;checked=[math]::Min($offset+64,$total);complete=($offset+64 -ge $total)}
        }else{
            foreach($computer in $computers){try{$options=@{Computer=$computer;Force=$true;RandomDelayInMinutes=0;ErrorAction='Stop'};if(!$rollback){$options.Target=$target};Invoke-GPUpdate @options|Out-Null;$refresh+=@{computer=$computer;state='SCHEDULED';message=('gpupdate /target:'+$target.ToLowerInvariant()+' /force scheduled.')}}catch{$refresh+=@{computer=$computer;state='FAILED';message='Remote gpupdate could not be scheduled. Check RPC/task-scheduler firewall and permissions.'}}}
        }
        # Invoke-GPUpdate schedules a task; it does not wait for policy processing.
        $v=if($rollback){Verify-Rollback $plan $map $manifest}else{Verify-Published $plan $map $false};$failed=@($refresh|Where-Object{$_.state -eq 'FAILED'}).Count
        $completed=$refresh.Count -gt 0 -and @($refresh|Where-Object state -ne 'COMPLETED').Count -eq 0
        $state=if($rollback){if($v.restored){'ROLLED_BACK'}else{'ROLLBACK_DRIFT_DETECTED'}}elseif(!$v.published -or !$v.linked){'DRIFT_DETECTED'}elseif($failed){'REFRESH_PARTIAL'}elseif($completed){'REFRESH_COMPLETED'}else{'REFRESH_SCHEDULED'}
        $output=Result $state $(if($failed){'One or more gpupdate /force targets failed. Review the per-host results.'}elseif($completed){'Computer policy processing completed on every refresh target. Verify resultant values and winning GPO separately.'}else{'gpupdate /force was scheduled. Endpoint convergence still requires verification.'}) $manifest $v $refresh
        if($refreshCoverage){$output.refreshCoverage=$refreshCoverage}
        return $output
    }
    'gpoRollbackInspect'{
        # Read-only assessment; actual rollback will independently lock and verify the fingerprint.
        $plan=$Data.plan;$s=$plan.selection;$directory=Run-Directory $plan
        $manifestPath=Join-Path $directory 'manifest.json'
        if(!(Test-Path -LiteralPath $manifestPath)){return @{canRestore=$false;driftDetected=$false;reason='NO_BACKUP';message='No completed backup manifest exists for this operation.'}}
        $m=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if(!$m.backupId -or !$m.postFingerprint){return @{canRestore=$false;driftDetected=$false;reason='INCOMPLETE_BACKUP';message='A completed backup and post-write fingerprint are required.'}}
        $phase=[string]$m.phase
        if($phase -notin @('PUBLISHED','VERIFY_MISMATCH','ROLLED_BACK')){return @{canRestore=$false;driftDetected=$false;reason='MANUAL_REVIEW_REQUIRED';message=('Manifest phase '+$phase+' requires independent recovery review.')}}
        $current=Fingerprint $s.gpoId $s.scopeDn
        $expected=Rollback-ExpectedFingerprint $plan $m $current
        $drift=(!$expected -or $current -cne [string]$expected)
        $gpo=Get-GPO -Guid ([guid]$s.gpoId) -Domain $cfg.domain -Server $cfg.domainController
        $direct=Selected-Link $s.scopeDn $s.gpoId
        return @{canRestore=(-not $drift);driftDetected=[bool]$drift;restoreMethod='Import-GPO';restorePermissionVerified=$false;reason=$(if($drift){'ROLLBACK_CONFLICT'}else{'READY'});message=$(if($drift){'The live GPO or its link changed since Apply; automatic rollback must not overwrite the external change.'}else{'Live fingerprint matches the saved post-apply state. Recovery imports the saved settings into the same GPO and preserves its ACL. Edit settings, backup read access and required link authority are checked again before import.'});gpoName=[string]$gpo.DisplayName;gpoId=[string]$s.gpoId;scopeDn=[string]$s.scopeDn;backupId=[string]$m.backupId;controlId=[string]$m.mappingId;beforeValue=[string]$plan.preview.previousValue;afterValue=[string]$plan.preview.desiredValue;beforeLink=$plan.preview.existingLink;currentLink=$direct;otherLinkedScopes=@($plan.preview.impact.existingLinkScopes);fullGpoRestore=$true;checkedAt=[DateTimeOffset]::UtcNow.ToString('O')}
    }
    'gpoRollback'{
        $plan=$Data.plan;$map=$Data.mapping;$s=$plan.selection;$directory=Run-Directory $plan;if(!(Test-Path -LiteralPath (Join-Path $directory 'manifest.json'))){Fail 'ROLLBACK_NOT_AVAILABLE' 'No backup exists because this operation did not change the GPO.'};$manifest=Get-Content -LiteralPath (Join-Path $directory 'manifest.json') -Raw|ConvertFrom-Json;if(!$manifest.backupId){Fail 'ROLLBACK_BACKUP_INCOMPLETE' 'The operation manifest exists but no completed Backup-GPO ID was recorded. Verify current policy and inspect the operation directory; automatic rollback is unavailable.'};if(!$manifest.postFingerprint){Fail 'ROLLBACK_VERSION_UNKNOWN' 'A completed post-write fingerprint is missing. Recover the recorded Backup-GPO snapshot manually after inspecting AD/SYSVOL.'};$lock=$null
        try{$lock=[IO.File]::Open((Join-Path (Split-Path $directory -Parent) (([guid]$s.gpoId).ToString()+'.lock')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{Fail 'GPO_BUSY' 'Another operation is writing this GPO.'}
        try{
            if([string]$manifest.phase -notin @('PUBLISHED','VERIFY_MISMATCH','ROLLED_BACK')){Fail 'ROLLBACK_CONFLICT' 'The backup manifest requires independent review before another restore.'}
            $currentFingerprint=Fingerprint $s.gpoId $s.scopeDn
            $expectedFingerprint=Rollback-ExpectedFingerprint $plan $manifest $currentFingerprint
            if(!$expectedFingerprint){Fail 'ROLLBACK_CONFLICT' 'The current GPO no longer matches the recorded restored snapshot.'}
            $anchor=Read-Field $Data 'rollbackAnchor' $null
            if($anchor -and [string]$manifest.phase -ne 'ROLLED_BACK'){
                $anchorPlan=$anchor.plan
                if([string]$anchorPlan.selection.gpoId -ne [string]$s.gpoId -or [string]$anchorPlan.selection.scopeDn -ne [string]$s.scopeDn){Fail 'ROLLBACK_CONFLICT' 'Batch recovery anchor has a different GPO or scope.'}
                $anchorDirectory=Run-Directory $anchorPlan
                $anchorManifest=Get-Content -LiteralPath (Join-Path $anchorDirectory 'manifest.json') -Raw | ConvertFrom-Json
                if([string]$anchorManifest.phase -ne 'PUBLISHED' -or [string]$anchorManifest.postFingerprint -cne [string]$anchor.postFingerprint){Fail 'ROLLBACK_CONFLICT' 'The last batch publication is not a valid recovery anchor.'}
                $expectedFingerprint=[string]$anchorManifest.postFingerprint
            }
            if((Fingerprint $s.gpoId $s.scopeDn) -cne $expectedFingerprint){Fail 'ROLLBACK_CONFLICT' 'The GPO or links changed after Apply. Automatic full-GPO restore is blocked.'}
            $null=Assert-SelectionAccess $s $map
            Emit-Stage 'RESTORING_GPO'
            $manifest | Add-Member -NotePropertyName rollbackAttempts -NotePropertyValue ([int](Read-Field $manifest 'rollbackAttempts' 0)+1) -Force
            $manifest.phase='ROLLING_BACK';Save-Manifest $manifest $directory
            Import-GPO -BackupId ([guid]$manifest.backupId) -TargetGuid ([guid]$s.gpoId) -Path $directory -Domain $cfg.domain -Server $cfg.domainController|Out-Null
            Emit-Stage 'RESTORING_LINK'
            $before=$plan.preview.existingLink
            if($null -eq $before){Remove-GPLink -Guid ([guid]$s.gpoId) -Target $s.scopeDn -Domain $cfg.domain -Server $cfg.domainController -Confirm:$false|Out-Null}
            else{Set-GPLink -Guid ([guid]$s.gpoId) -Target $s.scopeDn -Domain $cfg.domain -Server $cfg.domainController -Order ([int]$before.order) -LinkEnabled $(if($before.enabled){'Yes'}else{'No'}) -Enforced $(if($before.enforced){'Yes'}else{'No'})|Out-Null}
            Emit-Stage 'RESTORE_CHECK'
            $matches=(Get-NormalizedGpoContentFingerprint (Gpo-Folder $s.gpoId)) -ceq $manifest.beforeContent
            $matches=$matches -and (Snapshot-ExtensionsMatch $manifest $s.gpoId $s) -and ((Scope-Links $s.scopeDn) -ceq [string]$plan.preview.scopeLinks)
            $manifest.phase=if($matches){'ROLLED_BACK'}else{'ROLLBACK_REVIEW_REQUIRED'}
            if($matches){$manifest | Add-Member -NotePropertyName rollbackFingerprint -NotePropertyValue (Fingerprint $s.gpoId $s.scopeDn) -Force}
            Save-Manifest $manifest $directory
            return Result $manifest.phase 'GPO snapshot and selected link restored. Endpoint refresh/replication still need to converge.' $manifest @{published=$false;linked=$false;effective='ROLLBACK_ENDPOINT_PENDING';currentValue=$null} @()
        }catch{
            if($_.Exception.Message -like 'ROLLBACK_CONFLICT*'){throw}
            if($manifest){$manifest.phase='ROLLBACK_REVIEW_REQUIRED';Save-Manifest $manifest $directory;return Result 'ROLLBACK_REVIEW_REQUIRED' 'Rollback did not finish cleanly. Do not retry automatically; inspect the saved backup and verify the live GPO/link state.' $manifest @{published=$false;linked=$false;effective='ROLLBACK_ENDPOINT_PENDING';currentValue=$null} @()}
            throw
        }finally{if($lock){$lock.Dispose()}}
    }
    default{Fail 'OPERATION_DENIED' 'Unknown GPO operation.'}
}
} catch {
    $failure=Operation-Failure $_ $script:workerStage
    Fail $failure.code $failure.message
}
