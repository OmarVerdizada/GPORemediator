# Trusted functions injected from the verified product bundle. No AD/policy writes.
function Access-Report($Selection,$Map){
    $access=Selection-Access $Selection $Map
    $displayFolder='\\'+$cfg.domainController+'\SYSVOL\'+$cfg.domain+'\Policies\'+([guid]$Selection.gpoId).ToString('B')
    try{$displayFolder=Gpo-Folder $Selection.gpoId}catch{}
    $gpoDn='CN='+([guid]$Selection.gpoId).ToString('B').ToUpperInvariant()+',CN=Policies,CN=System,'+$domainDn
    $rows=@()
    foreach($check in @($access.checks)){
        $target=if($check.id -eq 'gpo-edit'){$gpoDn}elseif($check.id -eq 'link-write'){[string]$Selection.scopeDn}else{$displayFolder}
        $required=if($check.id -eq 'gpo-edit'){'Edit settings: version and CSE attributes'}elseif($check.id -eq 'link-write'){'Write gPLink if the link needs changing'}else{'Read/execute and write on policy targets'}
        $remedy=switch($check.id){
          'gpo-edit' {'GPMC > Group Policy Objects > this GPO > Delegation: grant the execution account/group Edit settings.'}
          'link-write' {'GPMC > this OU/domain > Delegation: grant Link GPOs. This permission is separate from GPO Edit settings.'}
          'sysvol-write' {'Review GPMC delegation and NTFS Effective Access for this GPO only. Do not grant broad write access to SYSVOL.'}
        }
        $rows+=@{id=$check.id;label=$check.label;state=$check.state;target=$target;requiredRight=$required;remedy=$remedy;required=$true}
    }
    try{foreach($path in @(Policy-WritePaths $Selection $Map)){
        $rows+=@{id='file';label='Policy file/directory';target=$path;state=$(if(Test-FileSystemWrite $path){'ALLOWED'}else{'DENIED'});requiredRight='Read/execute and write';remedy='Inspect Effective Access for the execution account on this exact path and its parent.';required=$true}
    }}catch{$rows+=@{id='file';label='Policy file paths';target=$displayFolder;state='UNKNOWN';requiredRight='Read effective filesystem permissions';remedy='Check SYSVOL reachability and metadata/ACL read access.';required=$true}}
    $environment=Environment-Status
    foreach($check in @($environment.checks|Where-Object{$_.id -in @('backup','backup-acl','disk','sysvol')})){
        $rows+=@{id=$check.id;label=$check.label;target=$(if($check.id -like 'backup*' -or $check.id -eq 'disk'){[string]$cfg.backupPath}else{'Local DC SYSVOL'});state=$(if($check.state -eq 'PASS'){'ALLOWED'}elseif($check.state -eq 'FAIL'){'DENIED'}else{'UNKNOWN'});requiredRight=$(if($check.id -eq 'backup'){'Create/delete backup workspace files'}else{'Read/check component'});remedy=[string]$check.message;required=[bool]$check.required}
    }
    $container='CN=Password Settings Container,CN=System,'+$domainDn;$pso='UNKNOWN'
    try{$object=Get-ADObject -Identity $container -Server $cfg.domainController -Properties allowedChildClassesEffective -ErrorAction Stop;$classes=@(Read-Field $object 'allowedChildClassesEffective' @());if($classes.Count){$pso=if(@($classes|Where-Object{[string]$_ -match '(^|CN=)msDS-PasswordSettings(,|$)'}).Count){'ALLOWED'}else{'DENIED'}}}catch{}
    $rows+=@{id='pso-create';label='PSO creation (separate from GPO)';target=$container;state=$pso;requiredRight='Create msDS-PasswordSettings child';remedy='ADAC > domain > System > Password Settings Container: delegate PSO creation. Editing subjects/settings and deletion need separate rights on the selected PSO. This row does not prove those rights.';required=$false}
    return @{executionUser=$access.executionUser;domain=$cfg.domain;domainController=$cfg.domainController;gpoId=$Selection.gpoId;scopeDn=$Selection.scopeDn;checkedAt=[DateTimeOffset]::UtcNow.ToString('O');checks=$rows;ready=(@($rows|Where-Object{$_.required -and $_.state -ne 'ALLOWED'}).Count -eq 0);note='Read-only AD/effective-ACL inspection. Backup readiness creates/deletes disposable local probe files; no policy or delegation is changed.'}
}

function Explain-Policy($Plan,$Map,[string]$Hostname){
    $s=$Plan.selection
    if([bool]$Map.domainPolicySensitive){return @{state='DOMAIN_ACCOUNT_CONTEXT';hostname=$cfg.domainController;checkedAt=[DateTimeOffset]::UtcNow.ToString('O');findings=@(@{state='INFORMATION';message='Domain account policy is evaluated through the domain root. Check the selected-DC effective account value and competing domain-root GPOs; endpoint local-account RSoP is not domain-user policy evidence.'});items=@();gpos=@();events=@();requiresRestart=[bool]$Map.requiresRestart}}
    $live=@(Refresh-Targets 'Scope' $s.scopeDn ([string](Read-Field $s 'endpointScopeDn' '')) ([string]$Map.scope))
    if($Hostname -notin $live){Fail 'ENDPOINT_OUTSIDE_SCOPE' 'The endpoint is no longer enabled in the authorized OU/host scope.'}
    $sid=''
    if([string]$Map.scope -eq 'User'){
        $identity=[string](Read-Field $s 'verificationUser' '')
        if(!$identity){Fail 'VERIFICATION_USER_REQUIRED' 'Choose a verification user in a fresh preview for user RSoP attribution.'}
        $user=Verification-User $identity
        if(!$user.Enabled -or !([string]$user.DistinguishedName).EndsWith(','+[string]$s.scopeDn,[StringComparison]::OrdinalIgnoreCase)){Fail 'VERIFICATION_USER_OUTSIDE_SCOPE' 'The verification user is no longer enabled in the selected user OU.'}
        $sid=[string]$user.SID.Value
    }
    $credential=Endpoint-CredentialOptions
    if(!$credential.Count){Fail 'DELEGATED_CREDENTIAL_REQUIRED' 'Endpoint diagnostics require explicit delegated credentials.'}
    $probe=Invoke-Command -ComputerName $Hostname -Authentication Kerberos @credential -ArgumentList ([string]$Map.handler),@($Map.items),([string]$s.gpoId),$sid -ScriptBlock {
        param($Handler,$Items,$SelectedGpo,$UserSid)
        $ErrorActionPreference='Stop'
        function Field($Object,[string]$Name,$Default=$null){$p=$Object.PSObject.Properties[$Name];if($p){return $p.Value};return $Default}
        function Id([string]$Value){$m=[regex]::Match($Value,'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');if($m.Success){return $m.Value.ToLowerInvariant()};return ''}
        function Key([string]$Value){return ($Value -replace '^(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|MACHINE|USER)\\','').ToLowerInvariant()}
        $namespace='root\rsop\computer';$findings=@();$gpos=@();$values=@();$events=@()
        if($UserSid){
            if($UserSid -notmatch '^S-\d-(?:\d+-){1,14}\d+$'){throw 'Invalid user SID'}
            $child=@(Get-CimInstance -Namespace 'root\rsop\user' -ClassName __NAMESPACE -ErrorAction Stop|Where-Object{([string]$_.Name).Replace('_','-') -ieq $UserSid}|Select-Object -First 1)
            if(!$child.Count){return @{state='USER_RSOP_UNAVAILABLE';namespace=$namespace;findings=@(@{state='UNKNOWN';message='No logged RSoP namespace exists for this user. Sign in/process user policy on this computer, then retry.'});items=@();gpos=@();events=@()}}
            $namespace='root\rsop\user\'+[string]$child[0].Name
        }
        try{
            $gpos=@(Get-CimInstance -Namespace $namespace -ClassName RSOP_GPO -ErrorAction Stop|Select-Object -First 501|ForEach-Object{
                @{id=(Id ([string](Field $_ 'guidName' (Field $_ 'id' ''))));name=[string](Field $_ 'name' 'Unknown');enabled=[bool](Field $_ 'enabled' $false);accessDenied=[bool](Field $_ 'accessDenied' $false);filterAllowed=Field $_ 'filterAllowed' $null;filterId=[string](Field $_ 'filterId' '')}
            })
            if($gpos.Count -gt 500){$gpos=@($gpos|Select-Object -First 500);$findings+=@{state='BOUNDED_GPO_LIST';message='Only the first 500 logged GPO records are shown; absence does not prove exclusion.'}}
            $selected=@($gpos|Where-Object{$_.id -eq (Id $SelectedGpo)}|Select-Object -First 1)
            if(!$selected.Count){$findings+=@{state='NOT_RECORDED';message='The selected GPO is absent from this logged RSoP snapshot. Inspect link scope, inheritance, Read/Apply filtering, WMI and policy processing; absence alone does not establish a specific cause.'}}
            else{
                if($selected[0].accessDenied){$findings+=@{state='SECURITY_FILTER_DENIED';message='RSoP reports security access denied for the selected GPO. Check target Read and Apply Group Policy permissions and explicit Deny entries.'}}
                if($selected[0].filterAllowed -eq $false){$findings+=@{state='WMI_FILTER_DENIED';message='RSoP reports that the selected GPO did not pass its filter. Review its WMI query against this endpoint.'}}
                if(!$selected[0].enabled){$findings+=@{state='DISABLED';message='RSoP records the GPO as disabled.'}}
            }
            $classes=@{}
            foreach($item in @($Items)){
                $type=[string](Field $item 'type' '');$section=[string](Field $item 'section' '');$itemKey=[string](Field $item 'key' '')
                $class=if($Handler -in @('Registry','RegistrySet')){'RSOP_RegistryPolicySetting'}elseif($Handler -eq 'SecurityTemplate' -and $section -eq 'Privilege Rights'){'RSOP_UserPrivilegeRight'}elseif($Handler -eq 'SecurityTemplate' -and $section -eq 'System Access'){
                    if($itemKey -in @('ClearTextPassword','PasswordComplexity','RequireLogonToChangePassword','ForceLogoffWhenHourExpire','LSAAnonymousNameLookup','EnableAdminAccount','EnableGuestAccount','TicketValidateClient')){'RSOP_SecuritySettingBoolean'}
                    elseif($itemKey -in @('NewAdministratorName','NewGuestName')){'RSOP_SecuritySettingString'}else{'RSOP_SecuritySettingNumeric'}
                }else{''}
                if(!$class){$values+=@{key=$itemKey;state='NOT_SUPPORTED';message='This handler/field has no reliable per-setting RSoP provider mapping. Use the native verifier and GroupPolicy events; no winning GPO is inferred.'};continue}
                try{
                    if(!$classes.ContainsKey($class)){
                        $classes[$class]=@(Get-CimInstance -Namespace $namespace -ClassName $class -ErrorAction Stop|Select-Object -First 10001)
                        if($classes[$class].Count -gt 10000){throw 'RSoP class exceeded its bounded inventory limit'}
                    }
                    $rows=@($classes[$class]|Where-Object{
                        if($class -eq 'RSOP_RegistryPolicySetting'){(Key ([string](Field $_ 'registryKey' ''))) -eq (Key $itemKey) -and [string](Field $_ 'valueName' '') -ieq [string](Field $item 'name' '') -and !(Field $_ 'deleted' $false)}
                        elseif($class -eq 'RSOP_UserPrivilegeRight'){[string](Field $_ 'UserRight' '') -ieq $itemKey}
                        else{[string](Field $_ 'KeyName' '') -ieq $itemKey}
                    }|Sort-Object @{Expression={[uint32](Field $_ 'precedence' ([uint32]::MaxValue))}})
                    if(!$rows.Count){$values+=@{key=$itemKey;name=[string](Field $item 'name' '');state='NOT_RECORDED';message='No matching per-setting RSoP record was found.'};continue}
                    $winner=$rows[0];$winnerId=Id ([string](Field $winner 'GPOID' ''));$winnerName=@($gpos|Where-Object id -eq $winnerId|Select-Object -First 1)
                    $values+=@{key=$itemKey;name=[string](Field $item 'name' '');state=$(if(!$winnerId){'UNKNOWN_SOURCE'}elseif($winnerId -eq (Id $SelectedGpo)){'SELECTED_GPO'}else{'OTHER_GPO_WINS'});winningGpo=$winnerId;winningName=$(if($winnerName.Count){$winnerName[0].name}else{$winnerId});precedence=Field $winner 'precedence' $null;creationTime=[string](Field $winner 'creationTime' '');message='Source attribution from logged RSoP. It may be older than the latest change; reprocess policy and compare timestamps before treating it as current.'}
                }catch{$values+=@{key=$itemKey;state='UNAVAILABLE';message='The required RSoP class could not be queried. Check RSoP read access and client extension support.'}}
            }
        }catch{$findings+=@{state='RSOP_UNAVAILABLE';message='RSoP could not be read. The execution account needs RSoP/WMI access on this endpoint; policy value equality is not source attribution.'}}
        try{$events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-GroupPolicy/Operational';StartTime=(Get-Date).AddDays(-1)} -MaxEvents 20 -ErrorAction Stop|ForEach-Object{@{id=$_.Id;level=[string]$_.LevelDisplayName;time=$_.TimeCreated.ToUniversalTime().ToString('O');message=([string]$_.Message).Substring(0,[math]::Min(2000,([string]$_.Message).Length))}})}catch{$findings+=@{state='EVENTS_UNAVAILABLE';message='GroupPolicy Operational events could not be read with this account.'}}
        $restart=@{state='NOT_DETECTED';signals=@()}
        try{
            foreach($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')){if(Test-Path -LiteralPath $key -ErrorAction Stop){$restart.signals+=$key}}
            $session=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
            if(@(Field $session 'PendingFileRenameOperations' @()).Count){$restart.signals+='PendingFileRenameOperations'}
            if($restart.signals.Count){$restart.state='DETECTED'}
        }catch{$restart.state='UNKNOWN'}
        return @{state=$(if(@($values|Where-Object state -eq 'OTHER_GPO_WINS').Count){'CONFLICT_RECORDED'}elseif($values.Count -and @($values|Where-Object state -ne 'SELECTED_GPO').Count -eq 0){'SELECTED_GPO_RECORDED'}else{'PARTIAL_EVIDENCE'});namespace=$namespace;findings=$findings;items=$values;gpos=$gpos;events=$events;pendingRestart=$restart}
    } -ErrorAction Stop
    $single=@{selection=$s;preview=@{verificationComputers=@($Hostname);refreshComputers=@($Hostname);impact=$Plan.preview.impact}}
    return @{state=[string]$probe.state;hostname=$Hostname;domain=$cfg.domain;executionUser=[Security.Principal.WindowsIdentity]::GetCurrent().Name;checkedAt=[DateTimeOffset]::UtcNow.ToString('O');requiresRestart=[bool]$Map.requiresRestart;pendingRestart=(Read-Field $probe 'pendingRestart' @{state='UNKNOWN';signals=@()});namespace=[string]$probe.namespace;findings=@($probe.findings);items=@($probe.items);gpos=@($probe.gpos);events=@($probe.events);effectiveChecks=@(Verify-EffectiveSamples $single $Map);note='Read-only logged RSoP, native values and recent events. No refresh/restart was triggered; logged source records may be stale and do not certify runtime prerequisites.'}
}
