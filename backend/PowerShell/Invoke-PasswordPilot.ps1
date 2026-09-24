# Windows PowerShell 5.1. Fixed operations and typed JSON only; never execute browser command text.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Fail([string]$Code, [string]$Message) { throw ($Code + '|' + $Message) }
function Get-Values($Policy) {
    foreach ($key in @('LockoutDuration','LockoutObservationWindow')) {
        if ($Policy.$key.TotalSeconds -ne [math]::Truncate($Policy.$key.TotalSeconds) -or $Policy.$key.TotalSeconds -gt [int]::MaxValue -or $Policy.$key.TotalSeconds -lt 0) {
            Fail 'POLICY_PRECISION_UNSUPPORTED' 'The current lockout interval cannot be preserved as whole seconds. Administrator review is required.'
        }
    }
    foreach ($key in @('MinPasswordAge','MaxPasswordAge')) {
        if ($Policy.$key.TotalDays -ne [math]::Truncate($Policy.$key.TotalDays)) {
            Fail 'POLICY_PRECISION_UNSUPPORTED' 'The current policy has fractional-day password ages. The pilot will not round existing settings; administrator review is required.'
        }
    }
    return [ordered]@{
        PasswordHistoryCount = [int]$Policy.PasswordHistoryCount
        MaxPasswordAge = [int]$Policy.MaxPasswordAge.TotalDays
        MinPasswordAge = [int]$Policy.MinPasswordAge.TotalDays
        MinPasswordLength = [int]$Policy.MinPasswordLength
        ComplexityEnabled = [int][bool]$Policy.ComplexityEnabled
        ReversibleEncryptionEnabled = [int][bool]$Policy.ReversibleEncryptionEnabled
        LockoutThreshold = [int]$Policy.LockoutThreshold
        LockoutDuration = [int]$Policy.LockoutDuration.TotalSeconds
        LockoutObservationWindow = [int]$Policy.LockoutObservationWindow.TotalSeconds
    }
}
function Test-Values($Left, $Right) {
    foreach ($key in @('PasswordHistoryCount','MaxPasswordAge','MinPasswordAge','MinPasswordLength','ComplexityEnabled','ReversibleEncryptionEnabled','LockoutThreshold','LockoutDuration','LockoutObservationWindow')) {
        if ([int]$Left.$key -ne [int]$Right.$key) { return $false }
    }
    return $true
}
function Connect-Domain {
    if (-not (Get-Module -ListAvailable ActiveDirectory)) { Fail 'RSAT_REQUIRED' 'ActiveDirectory RSAT is missing. Start Windows mode with GpoRemediator.cmd to install prerequisites, then retry.' }
    Import-Module ActiveDirectory
    if ([string]$cfg.domain -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$' -or [string]$cfg.domainController -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$') { Fail 'DOMAIN_REQUIRED' 'Save a domain and writable DC before preparing a real policy.' }
    $script:domainInfo = Get-ADDomain -Identity $cfg.domain -Server $cfg.domainController
    $dc = Get-ADDomainController -Identity $cfg.domainController -Server $cfg.domainController
    if ($dc.IsReadOnly -or $dc.Domain -ine $domainInfo.DNSRoot) { Fail 'WRITABLE_DC_REQUIRED' 'The configured DC must be writable and in the configured domain.' }
    if ([int]$domainInfo.DomainMode -lt 3) { Fail 'DOMAIN_LEVEL_UNSUPPORTED' 'Fine-grained password policies require Windows Server 2008 domain functional level or later.' }
}
function Read-User([string]$Identity) {
    if ($Identity.Contains('@')) {
        $matches = @(Get-ADUser -Filter { UserPrincipalName -eq $Identity } -Server $cfg.domainController -Properties adminCount)
        if ($matches.Count -ne 1) { Fail 'USER_NOT_FOUND' 'Enter one exact test-user UPN in the configured domain.' }
        $user = $matches[0]
    } else {
        if ($Identity.Contains('\')) {
            $parts = $Identity.Split('\')
            if ($parts.Count -ne 2 -or $parts[0] -ine $domainInfo.NetBIOSName) { Fail 'USER_DOMAIN_MISMATCH' 'Use a test account in the configured domain.' }
            $Identity = $parts[1]
        }
        $user = Get-ADUser -Identity $Identity -Server $cfg.domainController -Properties adminCount
    }
    if ([int]$user.adminCount -eq 1 -or [string]$user.SID -match '-(500|502)$') { Fail 'PRIVILEGED_TEST_USER' 'Use a dedicated non-privileged test user for this pilot.' }
    if (-not $user.DistinguishedName.EndsWith(',' + $domainInfo.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) { Fail 'USER_DOMAIN_MISMATCH' 'The selected user is outside the configured domain.' }
    $policy = Get-ADUserResultantPasswordPolicy -Identity $user -Server $cfg.domainController
    $sourceId = $null; $precedence = 0
    if ($policy) { $sourceId = $policy.ObjectGUID.ToString(); $precedence = [int]$policy.Precedence }
    else { $policy = Get-ADDefaultDomainPasswordPolicy -Identity $domainInfo.DistinguishedName -Server $cfg.domainController }
    return @{
        userId=$user.ObjectGUID.ToString(); user=$user.SamAccountName; distinguishedName=$user.DistinguishedName
        sourceId=$sourceId; precedence=$precedence; values=(Get-Values $policy)
        warnings=@('Only this selected domain user receives the pilot PSO. Domain defaults and GPOs are unchanged.', 'Other password and lockout values are copied from the current effective policy. Existing passwords are not reset.', 'Verification reads resultant policy on the selected DC; replication and SecHard retesting remain separate.')
    }
}
function Assert-Before($Current, $Before) {
    if ($Current.userId -ine $Before.userId -or $Current.distinguishedName -ine $Before.distinguishedName -or [string]$Current.sourceId -ine [string]$Before.sourceId -or $Current.precedence -ne $Before.precedence -or -not (Test-Values $Current.values $Before.values)) {
        Fail 'STALE_PASSWORD_PLAN' 'The selected user or effective policy changed after preview. Prepare a new plan.'
    }
}
function Assert-Plan($Plan) {
    if ($Plan.id -notmatch '^[a-f0-9]{32}$' -or $Plan.domain -ine $cfg.domain -or $Plan.domainController -ine $cfg.domainController) { Fail 'PLAN_CONTEXT_CHANGED' 'Plan identity/domain/DC no longer matches.' }
    $ranges = @{ PasswordHistoryCount=@(0,1024); MaxPasswordAge=@(0,999); MinPasswordAge=@(0,998); MinPasswordLength=@(0,255); ComplexityEnabled=@(0,1); ReversibleEncryptionEnabled=@(0,1) }
    if (-not $ranges.ContainsKey([string]$Plan.setting)) { Fail 'PASSWORD_SETTING_UNSUPPORTED' 'Unknown password setting.' }
    $range=$ranges[[string]$Plan.setting]
    if ([int]$Plan.value -lt $range[0] -or [int]$Plan.value -gt $range[1]) { Fail 'PASSWORD_VALUE_INVALID' 'The selected value is outside the supported range.' }
    foreach ($property in $Plan.before.values.PSObject.Properties) {
        $expected = if ($property.Name -eq $Plan.setting) { [int]$Plan.value } else { [int]$property.Value }
        if ([int]$Plan.after.($property.Name) -ne $expected) { Fail 'PLAN_VALUES_INVALID' 'The plan must change only the selected password setting.' }
    }
    if ($Plan.after.MaxPasswordAge -ne 0 -and $Plan.after.MinPasswordAge -ge $Plan.after.MaxPasswordAge) { Fail 'PASSWORD_AGE_CONFLICT' 'Minimum age must be less than maximum age.' }
}
function Get-PilotPolicy($Plan) {
    $name='GpoRemediator-Pilot-' + $Plan.id
    $policies=@(Get-ADFineGrainedPasswordPolicy -Filter { Name -eq $name } -Server $cfg.domainController -Properties Description,AppliesTo)
    if ($policies.Count -gt 1) { Fail 'PILOT_POLICY_AMBIGUOUS' 'More than one policy matches the pilot identity.' }
    if ($policies.Count -eq 1) { return $policies[0] }
    return $null
}
function Backup-Plan($Plan) {
    $root=[IO.Path]::GetFullPath([string]$cfg.backupPath)
    if ($root -notmatch '^[a-zA-Z]:\\') { Fail 'BACKUP_PATH_INVALID' 'A local absolute backup path is required.' }
    $directory=Join-Path $root 'PasswordPilot'
    $null=New-Item -ItemType Directory -Path $directory -Force
    # Backup contains the complete effective policy and user identity. Restrict it to the service account/admins.
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')) {
        $rule=New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $acl
    $path=Join-Path $directory ($Plan.id + '.json')
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Plan | ConvertTo-Json -Depth 20))
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
try {
    $request=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $cfg=$request.configuration; $p=$request.payload
    $operation=[string]$request.operation
    if ($operation -eq 'discover') {
        $warnings=[Collections.Generic.List[string]]::new()
        $computer=Get-CimInstance Win32_ComputerSystem
        $domain=''; $dc=''; $dns=[string]$env:COMPUTERNAME
        try { $dns=[Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $warnings.Add('Management DNS lookup failed. Enter the full management hostname manually.') }
        if ($computer.PartOfDomain) {
            $domain=[string]$computer.Domain
            try {
                $context=New-Object DirectoryServices.ActiveDirectory.DirectoryContext('Domain',$domain)
                $adDomain=[DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
                try { $dc=$adDomain.PdcRoleOwner.Name } finally { $adDomain.Dispose() }
            } catch { $warnings.Add('Domain detected; DC discovery failed. Enter its FQDN manually or check domain connectivity.') }
        } else { $warnings.Add('This computer is not domain-joined. Enter the test-domain settings manually and run the service on a domain-connected Windows host.') }
        if (-not (Get-Module -ListAvailable ActiveDirectory)) { $warnings.Add('ActiveDirectory RSAT is missing. The Windows launcher installs prerequisites when you save and restart.') }
        # Use the read-only .NET store: the Cert: provider may not be loaded in a noninteractive child process.
        $certStore=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine')
        try {
            $certStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $cert=@($certStore.Certificates | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and $_.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName,$false) -ieq $dns })
            if ($cert.Count -eq 0) { $warnings.Add('No matching HTTPS certificate detected. Install a trusted server certificate for the management hostname before Windows mode can start.') }
        } catch { $warnings.Add('Certificate lookup was unavailable. Check the management HTTPS certificate before starting Windows mode.') }
        finally { $certStore.Close() }
        $data=@{ domain=$domain; domainController=$dc; urls=('https://' + $dns.ToLowerInvariant() + ':5443'); operator=[Security.Principal.WindowsIdentity]::GetCurrent().Name; backupPath='C:\ProgramData\GpoRemediator\Backups'; warnings=$warnings.ToArray() }
    } else {
        Connect-Domain
        switch ($operation) {
            'passwordReadiness' {
                $data=@{ mode='WINDOWS'; ready=$true; identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name; domainController=[string]$cfg.domainController; checkedAt=[DateTimeOffset]::UtcNow.ToString('o'); checks=@(
                    @{ id='ad'; label='Domain / writable DC / RSAT'; status='PASS'; message='Connected to the configured writable DC. Fine-grained password policies are supported.'; required=$true },
                    @{ id='permissions'; label='Selected-user write permission'; status='WARN'; message='Readiness does not prove create/assign rights. Apply requires delegated PSO permissions; no test writes are made during discovery.'; required=$false }
                ) }
            }
            'passwordRead' { $data=Read-User ([string]$p.user) }
            'passwordApply' {
                $plan=$p.plan; Assert-Plan $plan
                $current=Read-User ([string]$plan.before.userId)
                Assert-Before $current $plan.before
                if ($current.sourceId -and $current.precedence -le 1) { Fail 'PSO_PRECEDENCE_CONFLICT' 'Existing precedence cannot be safely superseded.' }
                if (Get-PilotPolicy $plan) { Fail 'PILOT_ALREADY_EXISTS' 'This pilot policy already exists. Review or roll back the recorded operation instead of retrying creation.' }
                Backup-Plan $plan
                $v=$plan.after
                $precedence=if ($current.sourceId) { [int]$current.precedence - 1 } else { 1000 }
                $args=@{
                    Name=('GpoRemediator-Pilot-' + $plan.id); Description=('GpoRemediator pilot ' + $plan.id + ' user ' + $current.userId)
                    Precedence=$precedence; ComplexityEnabled=([bool][int]$v.ComplexityEnabled)
                    ReversibleEncryptionEnabled=([bool][int]$v.ReversibleEncryptionEnabled)
                    MinPasswordLength=[int]$v.MinPasswordLength; PasswordHistoryCount=[int]$v.PasswordHistoryCount
                    MinPasswordAge=[TimeSpan]::FromDays([int]$v.MinPasswordAge); MaxPasswordAge=[TimeSpan]::FromDays([int]$v.MaxPasswordAge)
                    LockoutThreshold=[int]$v.LockoutThreshold; LockoutDuration=[TimeSpan]::FromSeconds([int]$v.LockoutDuration)
                    LockoutObservationWindow=[TimeSpan]::FromSeconds([int]$v.LockoutObservationWindow)
                    Server=[string]$cfg.domainController; PassThru=$true
                }
                $created=New-ADFineGrainedPasswordPolicy @args
                # Recheck after creation and immediately before assignment; a failed assignment leaves an identifiable empty pilot PSO.
                Assert-Before (Read-User ([string]$plan.before.userId)) $plan.before
                Add-ADFineGrainedPasswordPolicySubject -Identity $created -Subjects ([guid]$plan.before.userId) -Server $cfg.domainController -Confirm:$false
                $actual=Read-User ([string]$plan.before.userId)
                $verified=([string]$actual.sourceId -ieq $created.ObjectGUID.ToString()) -and (Test-Values $actual.values $plan.after)
                $data=@{ policyId=$created.ObjectGUID.ToString(); verified=$verified; message=$(if($verified){'Selected-user resultant policy verified on the configured DC. Replication and SecHard retest are still required.'}else{'Policy created, but resultant policy does not match. Review this record and use rollback; no success is asserted.'}) }
            }
            'passwordRollback' {
                $plan=$p.plan; Assert-Plan $plan
                $policy=Get-PilotPolicy $plan
                if ($policy) {
                    $description='GpoRemediator pilot ' + $plan.id + ' user ' + $plan.before.userId
                    $expectedPrecedence=if($plan.before.sourceId){[int]$plan.before.precedence-1}else{1000}
                    if ($policy.Description -cne $description -or [int]$policy.Precedence -ne $expectedPrecedence -or -not (Test-Values (Get-Values $policy) $plan.after)) { Fail 'ROLLBACK_CONFLICT' 'The pilot PSO was edited after creation. Automatic removal is blocked.' }
                    $subjects=@($policy.AppliesTo)
                    if (@($subjects | Where-Object { [string]$_ -ine [string]$plan.before.distinguishedName }).Count) { Fail 'ROLLBACK_SHARED_POLICY' 'The pilot PSO now has other subjects. Automatic removal is blocked.' }
                    $actual=Read-User ([string]$plan.before.userId)
                    if ($subjects.Count -gt 0) {
                        if ([string]$actual.sourceId -ine $policy.ObjectGUID.ToString()) { Fail 'ROLLBACK_CONFLICT' 'A different effective policy is now active. Recover later changes first.' }
                        Remove-ADFineGrainedPasswordPolicySubject -Identity $policy -Subjects ([guid]$plan.before.userId) -Server $cfg.domainController -Confirm:$false
                    }
                    # Delete only our exact, unchanged, empty PSO. Never delete pre-existing policies.
                    $check=Get-ADFineGrainedPasswordPolicy -Identity $policy.ObjectGUID -Server $cfg.domainController -Properties AppliesTo,Description
                    if (@($check.AppliesTo).Count -ne 0 -or $check.Description -cne $description -or -not(Test-Values (Get-Values $check) $plan.after)) { Fail 'ROLLBACK_CONFLICT' 'Policy changed during recovery; it was left in place for administrator review.' }
                    Remove-ADFineGrainedPasswordPolicy -Identity $policy.ObjectGUID -Server $cfg.domainController -Confirm:$false
                }
                $restored=Read-User ([string]$plan.before.userId)
                $verified=([string]$restored.sourceId -ieq [string]$plan.before.sourceId) -and (Test-Values $restored.values $plan.before.values)
                $data=@{ policyId=('GpoRemediator-Pilot-' + $plan.id); verified=$verified; message=$(if($verified){'Pilot assignment removed; previous effective password policy verified.'}else{'Pilot removed, but the previous source policy has changed. Administrator review is required.'}) }
            }
            default { Fail 'OPERATION_DENIED' 'Unknown password-pilot operation.' }
        }
    }
    [Console]::Out.Write((@{ok=$true; data=$data} | ConvertTo-Json -Depth 30 -Compress))
} catch {
    $message=[string]$_.Exception.Message
    if ($message -match '^([A-Z][A-Z0-9_]+)\|(.+)$') { $code=$Matches[1]; $safe=$Matches[2] }
    else { $code='PASSWORD_OPERATION_FAILED'; $safe='AD operation failed. Check the selected user, DC connectivity and delegated PSO create/assign permissions. Review the backup and pilot record before recovery. Category: ' + [string]$_.CategoryInfo.Category }
    [Console]::Out.Write((@{ok=$false;code=$code;message=$safe} | ConvertTo-Json -Compress))
    exit 1
}
