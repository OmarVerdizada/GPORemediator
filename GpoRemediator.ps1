param(
    [ValidateSet('Auto','Setup','Windows')]
    [string]$Mode = 'Auto',
    [ValidateRange(1024,65535)]
    [int]$Port = 5080,
    [switch]$NoBrowser,
    [switch]$Repair
)

# Start-Process can inherit PowerShell 7 module paths. Resolve Windows modules first.
$windowsModules = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$env:PSModulePath = $windowsModules + ';' + $env:PSModulePath
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')

$stateRoot = Join-Path $env:ProgramData 'GpoRemediator'
$workRoot = Join-Path $stateRoot 'State'
$configRoot = Join-Path $stateRoot 'Config'
$dataRoot = Join-Path $stateRoot 'Data'
$backupRoot = Join-Path $stateRoot 'Backups'
$recoveryRoot = Join-Path $stateRoot 'Recovery'
$localConfig = Join-Path $configRoot 'appsettings.Local.json'
$stateFile = Join-Path $workRoot 'service.json'
$restartMarker = Join-Path $workRoot 'restart.request.json'
$stopMarker = Join-Path $workRoot 'stop.request.json'
$logFile = Join-Path $workRoot 'bootstrap.log'
$windowsFailureLog = Join-Path $workRoot 'windows-startup-error.log'
$startupDiagnosisFile = Join-Path $workRoot 'startup-diagnosis.json'
$runtimeRoot = Join-Path $PSScriptRoot 'runtime'
$runtime = Join-Path $runtimeRoot 'GpoRemediator.exe'
$runtimeMarker = Join-Path $runtimeRoot 'production-backend-v4.ready'
$runtimeInstallManifest = Join-Path $runtimeRoot 'runtime-install.json'
$runtimeArchive = Join-Path $PSScriptRoot 'release\GpoRemediator-runtime-win-x64.zip'
$runtimeArchiveHash = $runtimeArchive + '.sha256'
$releaseVersion = '3.5.0'
# 3.1.2 keeps the 3.0 durable schema. It hardens startup recovery, removes the Setup->Windows restart race, and makes early backend failures self-diagnosing.
# 3.1.2 intentionally uses fresh Setup/Windows state databases so incompatible serialized records from earlier preview builds cannot crash startup. Older databases are left untouched in ProgramData for archival/review.
$stateSchemaVersion = '3.1.2'
$windowsDb = Join-Path $dataRoot ('windows-'+$stateSchemaVersion+'.db')
$setupDb = Join-Path $dataRoot ('setup-'+$stateSchemaVersion+'.db')
$activeConfig = Join-Path $workRoot 'appsettings.Active.json'
$launcherMutex = $null
$ownsLauncher = $false
$script:startupIssue = ''
$script:dbRecoveryUsed = $false
$script:runtimeRecoveryAttempts = 0
$script:runtimePackageRecoveryUsed = $false

function Write-Log([string]$Message,[ConsoleColor]$Color=[ConsoleColor]::Gray) {
    $line='[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message
    Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
    try { Write-Host $Message -ForegroundColor $Color } catch { }
}

function Initialize-SecureState {
    foreach($path in @($stateRoot,$workRoot,$configRoot,$dataRoot,$backupRoot,$recoveryRoot)) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
        try {
            $item=Get-Item -LiteralPath $path
            $acl=$item.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
            $acl.SetAccessRuleProtection($true,$false)
            foreach($rule in @(
                (New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')),
                (New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')),
                (New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
            )) { $acl.AddAccessRule($rule) | Out-Null }
            $item.SetAccessControl($acl)
        } catch {
            # The launcher can still continue when ACL hardening is already enforced by a parent policy.
        }
    }
}

function Trim-Log([string]$Path,[int]$MaxBytes=3145728,[int]$TailLines=1800) {
    try {
        if((Test-Path -LiteralPath $Path) -and (Get-Item -LiteralPath $Path).Length -gt $MaxBytes) {
            @(Get-Content -LiteralPath $Path -Encoding UTF8 -Tail $TailLines -ErrorAction SilentlyContinue) | Set-Content -LiteralPath $Path -Encoding UTF8
        }
    } catch { }
}

function Clear-TransientState {
    foreach($name in @('restart.request.json','stop.request.json','service.json.tmp','appsettings.Local.json.tmp')) {
        $path = if($name -like 'appsettings*'){ Join-Path $configRoot $name } else { Join-Path $workRoot $name }
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    Get-ChildItem -LiteralPath $workRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^runtime-(install|old)-[a-f0-9]{32}$' } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    foreach($name in @('bootstrap.log','server.log','server-error.log','windows-startup-error.log','preflight.log','panel-error.log','startup-diagnosis.json')) { Trim-Log (Join-Path $workRoot $name) }
}

function Test-ReleaseArchive {
    if(!(Test-Path -LiteralPath $runtimeArchive) -or !(Test-Path -LiteralPath $runtimeArchiveHash)){ return $false }
    try {
        $expected=(Get-Content -LiteralPath $runtimeArchiveHash -Raw -Encoding ASCII).Trim().ToUpperInvariant()
        if($expected -notmatch '^[A-F0-9]{64}$'){ return $false }
        return ((Get-FileHash -LiteralPath $runtimeArchive -Algorithm SHA256).Hash -ceq $expected)
    } catch { return $false }
}

function Test-RuntimeInstalled {
    $required=@(
        'GpoRemediator.exe','GpoRemediator.dll','GpoRemediator.deps.json','GpoRemediator.runtimeconfig.json',
        'appsettings.json','production-backend-v4.ready',
        'PowerShell\Invoke-GpoWorkflow.ps1','PowerShell\GpoWorkflow.Worker.ps1','PowerShell\SecurityTemplate.psm1'
    )
    foreach($name in $required){ if(!(Test-Path -LiteralPath (Join-Path $runtimeRoot $name))){ return $false } }
    if(!(Test-Path -LiteralPath $runtimeInstallManifest)){ return $false }
    try {
        $manifest=Get-Content -LiteralPath $runtimeInstallManifest -Raw -Encoding UTF8 | ConvertFrom-Json
        $expected=(Get-Content -LiteralPath $runtimeArchiveHash -Raw -Encoding ASCII).Trim().ToUpperInvariant()
        return ([string]$manifest.archiveSha256 -ceq $expected)
    } catch { return $false }
}

function Install-Runtime {
    if(!(Test-ReleaseArchive)){ throw 'Verified runtime package is missing or its SHA-256 check failed. Re-extract the complete release ZIP.' }
    $expected=(Get-Content -LiteralPath $runtimeArchiveHash -Raw -Encoding ASCII).Trim().ToUpperInvariant()
    $stage=Join-Path $workRoot ('runtime-install-'+[Guid]::NewGuid().ToString('N'))
    $old=Join-Path $workRoot ('runtime-old-'+[Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        Expand-Archive -LiteralPath $runtimeArchive -DestinationPath $stage -Force
        foreach($required in @('GpoRemediator.exe','GpoRemediator.dll','GpoRemediator.deps.json','GpoRemediator.runtimeconfig.json','appsettings.json','production-backend-v4.ready','PowerShell\Invoke-GpoWorkflow.ps1','PowerShell\GpoWorkflow.Worker.ps1','PowerShell\SecurityTemplate.psm1')) {
            if(!(Test-Path -LiteralPath (Join-Path $stage $required))){ throw "Runtime archive is incomplete: $required is missing." }
        }
        @{ archiveSha256=$expected; installedAt=[DateTimeOffset]::UtcNow.ToString('o'); package='production-win-x64' } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'runtime-install.json') -Encoding UTF8
        if(Test-Path -LiteralPath $runtimeRoot){ Move-Item -LiteralPath $runtimeRoot -Destination $old -Force }
        try {
            Move-Item -LiteralPath $stage -Destination $runtimeRoot -Force
            Remove-Item -LiteralPath $old -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Remove-Item -LiteralPath $runtimeRoot -Recurse -Force -ErrorAction SilentlyContinue
            if(Test-Path -LiteralPath $old){ Move-Item -LiteralPath $old -Destination $runtimeRoot -Force }
            throw
        }
        Write-Log 'Verified self-contained runtime installed. No SDK, Node.js, build cache, or internet download was used.' Green
    } finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-Runtime {
    if($Repair){ Write-Log 'Runtime repair requested.' Yellow; Install-Runtime; return }
    if(Test-RuntimeInstalled){ Write-Log 'Verified packaged runtime is ready.'; return }
    Install-Runtime
}

function Convert-DomainToDn([string]$Domain) {
    return (($Domain.Trim().Trim('.') -split '\.') | Where-Object { $_ } | ForEach-Object { 'DC='+$_ }) -join ','
}

function Convert-ToStringArray($Value) {
    return @($Value) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }
}

function Save-CanonicalConfig([string]$Domain,[string]$Dc,[object]$Existing=$null) {
    $domain=([string]$Domain).Trim().Trim('.').ToLowerInvariant()
    $dc=([string]$Dc).Trim().Trim('.').ToLowerInvariant()
    if(!$domain -or !$dc){ return $null }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    $win=if($Existing -and $Existing.Windows){$Existing.Windows}else{$null}
    $approved=if($win){Convert-ToStringArray $win.ApprovedGpoIds}else{@()}
    if($approved.Count -eq 0){$approved=@('*')}
    $ous=if($win){Convert-ToStringArray $win.AuthorizedOus}else{@()}
    if($ous.Count -eq 0){$ous=@((Convert-DomainToDn $domain))}
    $hosts=if($win){Convert-ToStringArray $win.AllowedHosts}else{@()}
    $operators=if($win){Convert-ToStringArray $win.AllowedOperators}else{@()}
    if($operators.Count -eq 0 -and $identity -match '\\'){$operators=@($identity)}
    $roles=if($win -and $win.Roles){$win.Roles}else{$null}
    # Web UI RBAC is intentionally separate from the delegated AD execution identity.
    # Older packages could persist the same Windows account in several role arrays which the
    # backend correctly rejects as ambiguous. Normalize legacy state deterministically on every
    # launcher start: AllowedOperators are Administrators; the remaining roles are mutually exclusive.
    $admins=@($operators | Sort-Object -Unique)
    $adminSet=@{}; foreach($a in $admins){$adminSet[$a.ToLowerInvariant()]=$true}
    $remediators=@(); foreach($a in $(if($roles){Convert-ToStringArray $roles.Remediators}else{@()})){if(!$adminSet.ContainsKey($a.ToLowerInvariant())){$remediators+=$a}}
    $remediators=@($remediators | Sort-Object -Unique); $remSet=@{}; foreach($a in $remediators){$remSet[$a.ToLowerInvariant()]=$true}
    $auditors=@(); foreach($a in $(if($roles){Convert-ToStringArray $roles.Auditors}else{@()})){if(!$adminSet.ContainsKey($a.ToLowerInvariant()) -and !$remSet.ContainsKey($a.ToLowerInvariant())){$auditors+=$a}}
    $auditors=@($auditors | Sort-Object -Unique); $auditSet=@{}; foreach($a in $auditors){$auditSet[$a.ToLowerInvariant()]=$true}
    $viewers=@(); foreach($a in $(if($roles){Convert-ToStringArray $roles.Viewers}else{@()})){if(!$adminSet.ContainsKey($a.ToLowerInvariant()) -and !$remSet.ContainsKey($a.ToLowerInvariant()) -and !$auditSet.ContainsKey($a.ToLowerInvariant())){$viewers+=$a}}
    $viewers=@($viewers | Sort-Object -Unique)
    $writes=$false
    if($win -and $null -ne $win.EnableWrites){$writes=[bool]$win.EnableWrites}
    $canonical=[ordered]@{
        Mode='Windows'
        Urls="http://127.0.0.1:$Port"
        Windows=[ordered]@{
            Workflow='GpoRemediation'
            EnableWrites=$writes
            Domain=$domain
            DomainController=$dc
            ApprovedGpoIds=@($approved)
            AuthorizedOus=@($ous)
            AllowedHosts=@($hosts)
            AllowedOperators=@($operators)
            Roles=[ordered]@{
                Administrators=@($admins)
                Remediators=@($remediators)
                Auditors=@($auditors)
                Viewers=@($viewers)
            }
            BackupPath=$backupRoot
        }
    }
    $tmp=$localConfig+'.tmp'
    $canonical | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $localConfig -Force
    return (Get-Content -LiteralPath $localConfig -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Test-UnsafeWriteScope([object]$Config) {
    if(!$Config -or !$Config.Windows){ return $true }
    $approved=Convert-ToStringArray $Config.Windows.ApprovedGpoIds
    $scopes=Convert-ToStringArray $Config.Windows.AuthorizedOus
    if($approved.Count -eq 0 -or $scopes.Count -eq 0){ return $true }
    if($approved -contains '*' -or $scopes -contains '*'){ return $true }
    return $false
}

function Enforce-WriteScopeSafety([object]$Config) {
    if(!$Config -or !$Config.Windows){ return $Config }
    if([bool]$Config.Windows.EnableWrites -and (Test-UnsafeWriteScope $Config)){
        # Discovery may intentionally use wildcard scope, but production writes must never start
        # with an unrestricted GPO or OU allowlist. Force the durable gate closed before the
        # Windows backend starts so an API call cannot bypass the browser-side safety check.
        $Config.Windows.EnableWrites=$false
        $tmp=$localConfig+'.tmp'
        $Config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $localConfig -Force
        Write-Log 'Write authorization was forced to read-only because the configured GPO/scope allowlist is unrestricted or empty. This is normal for discovery. Create a remediation preview and authorize its selected GPO + scope to open a production change gate.' Yellow
        $script:startupIssue='Write mode is read-only until a remediation plan authorizes one explicit GPO + AD scope.'
    }
    return $Config
}

function Get-DomainDiscovery {
    $domain=''; $dc=''
    try {
        $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if($cs.PartOfDomain -and [string]$cs.Domain -and [string]$cs.Domain -match '\.'){$domain=([string]$cs.Domain).Trim().Trim('.').ToLowerInvariant()}
    } catch { }
    if(!$domain){
        try {
            $candidate=[System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
            if($candidate -and $candidate -match '\.'){$domain=$candidate.Trim().Trim('.').ToLowerInvariant()}
        } catch { }
    }
    if($domain){
        try {
            $nl=(& "$env:SystemRoot\System32\nltest.exe" "/dsgetdc:$domain" 2>$null | Out-String)
            if($nl -match '(?im)^\s*DC:\s*\\\\([^\s]+)'){$dc=$Matches[1].Trim().Trim('.').ToLowerInvariant()}
        } catch { }
        if(!$dc){
            $logon=([string]$env:LOGONSERVER).Trim().TrimStart('\').Trim().ToLowerInvariant()
            if($logon){$dc=if($logon -match '\.'){$logon}else{"$logon.$domain"}}
        }
        if($dc){
            try { [void][System.Net.Dns]::GetHostAddresses($dc) } catch { $dc='' }
        }
    }
    return [pscustomobject]@{Domain=$domain;DomainController=$dc}
}

function Normalize-LocalConfig {
    $cfg=$null
    if(Test-Path -LiteralPath $localConfig){
        try { $cfg=Get-Content -LiteralPath $localConfig -Raw -Encoding UTF8 | ConvertFrom-Json } catch {
            $broken=Join-Path $recoveryRoot ('invalid-config-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')
            Copy-Item -LiteralPath $localConfig -Destination $broken -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $localConfig -Force -ErrorAction SilentlyContinue
            $script:startupIssue='Saved configuration was invalid JSON. The invalid copy was preserved and domain discovery will rebuild a clean read-only configuration.'
        }
    }
    $domain=if($cfg -and $cfg.Windows){([string]$cfg.Windows.Domain).Trim().Trim('.').ToLowerInvariant()}else{''}
    $dc=if($cfg -and $cfg.Windows){([string]$cfg.Windows.DomainController).Trim().Trim('.').ToLowerInvariant()}else{''}
    if(!$domain -or !$dc){
        $discovery=Get-DomainDiscovery
        if(!$domain){$domain=$discovery.Domain}
        if(!$dc){$dc=$discovery.DomainController}
    }
    if(!$domain -or !$dc){ return $cfg }
    # Always rewrite a minimal canonical config. This drops stale DatabasePath/Kestrel/LocalSetup
    # keys left by older packages and makes the Setup -> Windows transition deterministic.
    $canonical=Save-CanonicalConfig $domain $dc $cfg
    $canonical=Enforce-WriteScopeSafety $canonical
    Write-Log ('Canonical Windows configuration ready for '+$domain+' via '+$dc+'.') Green
    return $canonical
}

function Write-ActiveWindowsConfig {
    $cfg=Normalize-LocalConfig
    if(!$cfg -or !$cfg.Windows -or !$cfg.Windows.Domain -or !$cfg.Windows.DomainController){ throw 'Windows configuration is incomplete. Save Domain and writable DC first.' }
    # Use a launcher-owned immutable snapshot for the production process. This removes the
    # Setup->Windows race with the editable configuration file and avoids stale keys from older builds.
    $json=$cfg | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText($activeConfig,$json,(New-Object Text.UTF8Encoding($false)))
    try {
        $probe=Get-Content -LiteralPath $activeConfig -Raw -Encoding UTF8 | ConvertFrom-Json
        if(!$probe.Windows.Domain -or !$probe.Windows.DomainController){ throw 'Active configuration snapshot is incomplete.' }
    } catch {
        Remove-Item -LiteralPath $activeConfig -Force -ErrorAction SilentlyContinue
        throw ('Active Windows configuration validation failed: '+$_.Exception.Message)
    }
    return $activeConfig
}

function Wait-LocalPortFree([int]$DesiredPort,[int]$Seconds=12) {
    $deadline=(Get-Date).AddSeconds($Seconds)
    do {
        $listener=Get-NetTCPConnection -LocalPort $DesiredPort -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if(!$listener){ return $true }
        $owner=[int]$listener.OwningProcess
        try {
            $proc=Get-Process -Id $owner -ErrorAction Stop
            if($proc.ProcessName -ieq 'GpoRemediator'){
                Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 350
                continue
            }
        } catch { }
        Start-Sleep -Milliseconds 300
    } while((Get-Date) -lt $deadline)
    return $false
}

function Read-LocalConfig { return (Normalize-LocalConfig) }

function Resolve-RunMode([string]$Requested) {
    if($Requested -eq 'Setup'){ return 'Setup' }
    $cfg=Read-LocalConfig
    if($cfg -and [string]$cfg.Mode -eq 'Windows' -and $cfg.Windows -and $cfg.Windows.Domain -and $cfg.Windows.DomainController){ return 'Windows' }
    if($Requested -eq 'Windows'){ throw 'Windows configuration could not be completed automatically. The machine must be domain-joined or Domain/DC must be saved in Setup.' }
    return 'Setup'
}

function Get-StartupFailureCategory([string]$Details) {
    $text=[string]$Details
    if($text -match 'Another GPO Remediator process is already using this database'){ return 'DATABASE_LOCK_OWNER' }
    if($text -match 'address already in use|failed to bind|Only one usage of each socket address|Local port .+ already'){ return 'PORT_IN_USE' }
    if($text -match 'database disk image is malformed|SQLite Error|SQLiteException|no such column|no such table|database is locked|execution mode does not match|malformed database|schema|Store\.List|Store\.RecoverInterrupted|gpo_runs|could not be converted to.+GpoRemediator|JsonException.+GpoRemediator\.Domain'){ return 'DATABASE' }
    if($text -match 'Access.+denied|UnauthorizedAccessException|permission denied'){ return 'STATE_ACCESS' }
    if($text -match 'invalid JSON|configuration file|appsettings|Configuration\.Json'){ return 'CONFIGURATION' }
    if($text -match 'Negotiate|authentication initialization|SSPI'){ return 'WINDOWS_AUTH' }
    if($text -match 'hostfxr|hostpolicy|coreclr|BadImageFormat|DllNotFound|FileNotFoundException|Could not load file or assembly|entry point|0xc0000135|0xc000007b'){ return 'RUNTIME_PACKAGE' }
    if($text -match 'readiness timeout'){ return 'READINESS_TIMEOUT' }
    if($text -match 'process exited with code'){ return 'PROCESS_EXIT' }
    return 'UNKNOWN'
}

function Save-StartupDiagnosis([string]$Details,[string]$RunMode='Windows') {
    try {
        $category=Get-StartupFailureCategory $Details
        $safe=([string]$Details) -replace '(?i)(password|passwd|pwd|secret|token)(\s*[:=]\s*)[^\s,;]+','$1$2[REDACTED]'
        if($safe.Length -gt 12000){ $safe=$safe.Substring($safe.Length-12000) }
        [ordered]@{
            timestamp=[DateTimeOffset]::UtcNow.ToString('o')
            mode=$RunMode
            category=$category
            summary=(Get-SafeStartupIssue $Details)
            details=$safe
            windowsErrorLog=$windowsFailureLog
            serverErrorLog=(Join-Path $workRoot 'server-error.log')
            serverLog=(Join-Path $workRoot 'server.log')
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $startupDiagnosisFile -Encoding UTF8
    } catch { }
}

function Save-WindowsStartupFailure([string]$Details) {
    $header='[{0}] WINDOWS startup failure' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    @($header,$Details,'') | Add-Content -LiteralPath $windowsFailureLog -Encoding UTF8
    Trim-Log $windowsFailureLog
    Save-StartupDiagnosis $Details 'Windows'
}

function Get-SafeStartupIssue([string]$Details) {
    switch(Get-StartupFailureCategory $Details){
        'DATABASE_LOCK_OWNER' { return 'A previous GPO Remediator process still owns the local database. The launcher will stop stale product processes before retrying.' }
        'PORT_IN_USE' { return "Local port $Port is already in use by another application." }
        'DATABASE' { return 'The durable Windows state database reported a SQLite/schema failure. It will be preserved before one clean-store retry.' }
        'STATE_ACCESS' { return 'The backend could not access protected ProgramData state. Run the launcher under an account that can access the GpoRemediator ProgramData folders.' }
        'CONFIGURATION' { return 'The saved Windows configuration could not be loaded. The launcher preserves invalid JSON and rebuilds only a canonical read-only configuration.' }
        'WINDOWS_AUTH' { return 'Windows Integrated Authentication could not initialize. This is a local backend/authentication startup failure, not a Kerberos/WinRM readiness result.' }
        'RUNTIME_PACKAGE' { return 'The installed self-contained backend runtime is incomplete or could not load. The verified local runtime package will be reinstalled once automatically.' }
        'READINESS_TIMEOUT' { return 'The local backend process stayed alive but did not expose its loopback readiness endpoint in time. Review server-error.log and server.log.' }
        'PROCESS_EXIT' { return 'The local backend process exited before readiness. The verified runtime package will be repaired once before Setup recovery is used.' }
        default { return 'The local Windows backend failed before its readiness endpoint became available. The exact failure is preserved in startup-diagnosis.json and windows-startup-error.log.' }
    }
}

function Backup-WindowsDatabaseForRecovery {
    $db=$windowsDb
    if(!(Test-Path -LiteralPath $db)){ return $false }
    $stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
    $dest=Join-Path $recoveryRoot ('windows-db-'+$releaseVersion+'-'+$stamp)
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    foreach($src in @($db,($db+'-wal'),($db+'-shm'))){
        if(Test-Path -LiteralPath $src){ Move-Item -LiteralPath $src -Destination (Join-Path $dest ([IO.Path]::GetFileName($src))) -Force }
    }
    @("Recovered at: $(Get-Date -Format s)","Release: $releaseVersion","Reason: backend could not reach readiness","Original files were moved, not deleted.") | Set-Content -LiteralPath (Join-Path $dest 'RECOVERY.txt') -Encoding UTF8
    Write-Log ('Preserved the current Windows database under '+$dest+' and prepared a clean retry.') Yellow
    return $true
}

function Stop-OrphanedRuntimeProcesses {
    $tracked=Get-RemediatorService
    $keepPid=if($tracked){[int]$tracked.processId}else{-1}
    try {
        $items=Get-CimInstance Win32_Process -Filter "Name='GpoRemediator.exe'" -ErrorAction Stop
        foreach($item in $items){
            $pidValue=[int]$item.ProcessId
            if($pidValue -eq $keepPid){ continue }
            $path=[string]$item.ExecutablePath
            if($path -and $path -match '(?i)GpoRemediator'){
                Write-Log ('Stopping orphaned GpoRemediator runtime PID '+$pidValue+' from '+$path) Yellow
                Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}

function Assert-LocalPortAvailable {
    try {
        $listener=Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if(!$listener){ return }
        $owner=[int]$listener.OwningProcess
        $proc=Get-Process -Id $owner -ErrorAction SilentlyContinue
        if($proc -and $proc.ProcessName -ieq 'GpoRemediator'){
            Stop-Process -Id $owner -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 350
            return
        }
        throw "Local port $Port is already used by PID $owner ($($proc.ProcessName)). Stop that application or choose another port."
    } catch {
        if($_.Exception.Message -like 'Local port*'){ throw }
    }
}

function Stop-StaleProductInstance {
    $existing=Get-RemediatorService
    if(!$existing){ return }
    $current=[IO.Path]::GetFullPath($runtime)
    $existingPath=[string]$existing.executablePath
    if(!$existingPath){
        try { $existingPath=(Get-Process -Id ([int]$existing.processId) -ErrorAction Stop).Path } catch { $existingPath='' }
    }
    if($existingPath -and [IO.Path]::GetFullPath($existingPath) -ieq $current){
        throw 'GPO Remediator is already running. Open the existing Local Control Center instead of starting a second instance.'
    }
    Write-Log 'An older GPO Remediator instance is still registered. Requesting a controlled stop before migration.' Yellow
    try { Invoke-RemediatorServiceAction -Action stop | Out-Null } catch {
        try {
            $p=Get-Process -Id ([int]$existing.processId) -ErrorAction Stop
            if($p.ProcessName -ieq 'GpoRemediator'){ Stop-Process -Id $p.Id -Force -ErrorAction Stop }
        } catch { throw 'An older GPO Remediator instance could not be stopped. Stop it manually before starting this release.' }
    }
    for($i=0;$i -lt 30;$i++){ if(!(Get-RemediatorService)){ break }; Start-Sleep -Milliseconds 250 }
    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
}

function Wait-ApplicationReady([System.Diagnostics.Process]$Process,[string]$Url,[int]$TimeoutSeconds=75) {
    $deadline=(Get-Date).AddSeconds($TimeoutSeconds)
    $last=''
    do {
        if($Process.HasExited){ return [pscustomobject]@{Ready=$false;Reason=('process exited with code '+$Process.ExitCode);Status=$null} }
        foreach($endpoint in @('/api/v1/health/ready','/api/v1/health/live')){
            try {
                $r=Invoke-WebRequest -UseBasicParsing -Uri ($Url.TrimEnd('/')+$endpoint) -TimeoutSec 3
                if($endpoint -like '*ready' -and $r.StatusCode -eq 200){ return [pscustomobject]@{Ready=$true;Reason='ready endpoint returned HTTP 200';Status=200} }
                $last=$endpoint+' returned HTTP '+$r.StatusCode
            } catch { $last=$endpoint+': '+$_.Exception.Message }
        }
        Start-Sleep -Milliseconds 450
    } while((Get-Date) -lt $deadline)
    return [pscustomobject]@{Ready=$false;Reason=('readiness timeout after '+$TimeoutSeconds+'s; last probe: '+$last);Status=$null}
}
function Start-Application([string]$RunMode) {
    $serverLog=Join-Path $workRoot 'server.log'
    $serverError=Join-Path $workRoot 'server-error.log'
    Remove-Item -LiteralPath $serverLog,$serverError -Force -ErrorAction SilentlyContinue
    $url="http://127.0.0.1:$Port"
    if($RunMode -eq 'Windows'){
        $cfg=Read-LocalConfig
        if(!$cfg -or !$cfg.Windows.Domain -or !$cfg.Windows.DomainController){ throw 'Windows configuration is incomplete. Open Setup and save Domain and writable DC.' }
        # Keep a launch snapshot for diagnostics, but run the backend from the canonical ProgramData
        # configuration. IConfiguration is immutable for the lifetime of the process, so a write-gate
        # transition is persisted first and then applied by one controlled restart.
        Write-ActiveWindowsConfig | Out-Null
        if(!(Wait-LocalPortFree $Port 12)){ throw "Local port $Port did not become free before Windows mode startup." }
        $arguments=@('--contentRoot',('"'+$runtimeRoot+'"'),'--LocalConfigPath',('"'+$localConfig+'"'),'--DatabasePath',('"'+$windowsDb+'"'),'--Mode','Windows','--LocalSetup','false','--urls',$url,'--LauncherManaged','true')
        Write-Log ('Starting WINDOWS / AD service at '+$url+' with canonical persistent configuration. Launch snapshot preserved for diagnostics.') Cyan
    } elseif($RunMode -eq 'Setup'){
        $arguments=@('--contentRoot',('"'+$runtimeRoot+'"'),'--LocalConfigPath',('"'+$localConfig+'"'),'--DatabasePath',('"'+$setupDb+'"'),'--Mode','Setup','--LocalSetup','true','--urls',$url,'--LauncherManaged','true')
        Write-Log ('Starting configuration-only SETUP service at '+$url) Cyan
    } else { throw ('Unsupported mode: '+$RunMode) }

    Remove-Item -LiteralPath $restartMarker,$stopMarker -Force -ErrorAction SilentlyContinue
    $process=Start-Process -FilePath $runtime -ArgumentList $arguments -WorkingDirectory $runtimeRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverLog -RedirectStandardError $serverError
    $openPath=if($RunMode -eq 'Setup' -and $script:startupIssue){'/#/settings'}else{'/#/dashboard'}
    $serviceState=@{processId=$process.Id;startedAt=$process.StartTime.ToUniversalTime().ToString('o');url=$url;mode=$RunMode;launcherId=$PID;ready=$false;openPath=$openPath;startupIssue=$script:startupIssue;executablePath=$runtime;packageVersion=$releaseVersion}
    $serviceState | ConvertTo-Json | Set-Content -LiteralPath ($stateFile+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($stateFile+'.tmp') -Destination $stateFile -Force

    $readyProbe=Wait-ApplicationReady $process $url 75
    if(!$readyProbe.Ready){
        if(!$process.HasExited){ Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue; try{$process.WaitForExit(3000)}catch{} }
        Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
        $err=if(Test-Path -LiteralPath $serverError){(Get-Content -LiteralPath $serverError -Encoding UTF8 -Tail 80 -ErrorAction SilentlyContinue)-join [Environment]::NewLine}else{''}
        $out=if(Test-Path -LiteralPath $serverLog){(Get-Content -LiteralPath $serverLog -Encoding UTF8 -Tail 80 -ErrorAction SilentlyContinue)-join [Environment]::NewLine}else{''}
        $details=(($err,$out | Where-Object { $_ }) -join [Environment]::NewLine)
        $probeDetail='Launcher readiness probe: '+[string]$readyProbe.Reason
        if([string]::IsNullOrWhiteSpace($details)){ $details=$probeDetail+'; the process wrote no additional startup exception.' } else { $details=$probeDetail+[Environment]::NewLine+$details }
        if($RunMode -eq 'Windows'){ Save-WindowsStartupFailure $details }
        $script:startupIssue=Get-SafeStartupIssue $details
        Write-Log ("$RunMode service did not become ready.`n$details") Red
        Write-Log ('Startup classification: '+$script:startupIssue) Yellow
        return @{ExitCode=if($process.HasExited){$process.ExitCode}else{1};FailedEarly=$true;Details=$details;Url=$url}
    }

    if($RunMode -eq 'Windows'){
        if($script:startupIssue){ Write-Log 'Windows service recovered and passed readiness. Previous startup warning is cleared.' Green }
        $script:startupIssue=''
    }
    $serviceState.ready=$true
    $serviceState.startupIssue=$script:startupIssue
    $serviceState.openPath=if($RunMode -eq 'Setup' -and $script:startupIssue){'/#/settings'}else{'/#/dashboard'}
    $serviceState | ConvertTo-Json | Set-Content -LiteralPath ($stateFile+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($stateFile+'.tmp') -Destination $stateFile -Force
    if(!$NoBrowser){ Start-Process ($url.TrimEnd('/')+[string]$serviceState.openPath) | Out-Null }
    Write-Log ('Service is healthy in '+$RunMode+' mode.') Green
    $healthyAt=[DateTimeOffset]::UtcNow
    $configStampAtHealthy=$null
    try { if(Test-Path -LiteralPath $localConfig){$configStampAtHealthy=(Get-Item -LiteralPath $localConfig).LastWriteTimeUtc} } catch { }
    try {
        # Do not rely solely on the web backend to terminate itself after a Setup -> Windows
        # transition request. Older runtime builds could persist the new configuration without
        # completing the handoff, leaving the operator trapped in Setup mode. The launcher is the
        # authoritative lifecycle owner, so it watches both control markers and a saved canonical
        # Windows configuration while the Setup backend is healthy.
        while(!$process.HasExited){
            if((Test-Path -LiteralPath $stopMarker) -or (Test-Path -LiteralPath $restartMarker)){ break }
            if($RunMode -eq 'Setup' -and (Test-Path -LiteralPath $localConfig)){
                try {
                    $configItem=Get-Item -LiteralPath $localConfig
                    $changedAfterReady=(!$configStampAtHealthy) -or ($configItem.LastWriteTimeUtc -gt $configStampAtHealthy.AddMilliseconds(150))
                    if($changedAfterReady){
                        $candidate=Get-Content -LiteralPath $localConfig -Raw -Encoding UTF8 | ConvertFrom-Json
                        if($candidate -and [string]$candidate.Mode -eq 'Windows' -and $candidate.Windows -and $candidate.Windows.Domain -and $candidate.Windows.DomainController){
                            @{mode='Windows';reason='canonical-config-saved';requestedAt=[DateTimeOffset]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $restartMarker -Encoding UTF8
                            Write-Log 'Setup configuration was saved. Launcher is promoting the service to WINDOWS / AD mode.' Cyan
                            break
                        }
                    }
                } catch { Write-Log ('Setup handoff watcher ignored an incomplete config update: '+$_.Exception.Message) Yellow }
            }
            Start-Sleep -Milliseconds 300
        }
    } finally {
        # The launcher owns the transition. Once a control marker exists, terminate the current
        # backend cleanly from the launcher side instead of waiting indefinitely for self-exit.
        if(!$process.HasExited -and ((Test-Path -LiteralPath $stopMarker) -or (Test-Path -LiteralPath $restartMarker))){
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            try{$process.WaitForExit(5000)}catch{}
        }
        Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
        if(!$process.HasExited){ Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }

    $controlled=(Test-Path -LiteralPath $stopMarker) -or (Test-Path -LiteralPath $restartMarker)
    if(!$controlled){
        $err=if(Test-Path -LiteralPath $serverError){(Get-Content -LiteralPath $serverError -Encoding UTF8 -Tail 100 -ErrorAction SilentlyContinue)-join [Environment]::NewLine}else{''}
        $out=if(Test-Path -LiteralPath $serverLog){(Get-Content -LiteralPath $serverLog -Encoding UTF8 -Tail 100 -ErrorAction SilentlyContinue)-join [Environment]::NewLine}else{''}
        $details=(($err,$out | Where-Object { $_ }) -join [Environment]::NewLine)
        if([string]::IsNullOrWhiteSpace($details)){ $details=('The healthy '+$RunMode+' service exited unexpectedly with code '+$process.ExitCode+'.') }
        if($RunMode -eq 'Windows'){ Save-WindowsStartupFailure ('Runtime exit after readiness'+[Environment]::NewLine+$details) }
        $script:startupIssue=Get-SafeStartupIssue $details
        Write-Log ("$RunMode service exited unexpectedly after readiness (exit code $($process.ExitCode)).`n$details") Red
        $uptime=[Math]::Max(0,([DateTimeOffset]::UtcNow-$healthyAt).TotalSeconds)
        return @{ExitCode=$process.ExitCode;FailedEarly=$false;UnexpectedExit=$true;Details=$details;Url=$url;UptimeSeconds=$uptime}
    }
    return @{ExitCode=$process.ExitCode;FailedEarly=$false;UnexpectedExit=$false;Url=$url}
}

Initialize-SecureState
Clear-TransientState

try {
    $launcherMutex=New-Object Threading.Mutex($false,'Global\GpoRemediatorLauncher-Production-v5')
    try { $ownsLauncher=$launcherMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsLauncher=$true }
    if(!$ownsLauncher){ throw 'Another GPO Remediator launcher is already active.' }

    Write-Log ('Launcher mode: '+$Mode)
    Stop-StaleProductInstance
    Stop-OrphanedRuntimeProcesses
    Assert-LocalPortAvailable
    Ensure-Runtime
    if($Repair){ Write-Log 'Runtime repair completed. Start workspace normally.' Green; exit 0 }

    $nextMode=Resolve-RunMode $Mode
    $setupRecoveryUsed=$false
    while($true){
        try { $result=Start-Application $nextMode }
        catch {
            if($nextMode -ne 'Windows'){ throw }
            $script:startupIssue=$_.Exception.Message
            Save-WindowsStartupFailure $script:startupIssue
            Write-Log ('Windows startup needs attention: '+$script:startupIssue) Yellow
            $result=@{ExitCode=1;FailedEarly=$true;Details=$script:startupIssue}
        }

        if(Test-Path -LiteralPath $stopMarker){
            Remove-Item -LiteralPath $stopMarker -Force -ErrorAction SilentlyContinue
            Write-Log 'Controlled stop completed.' Yellow
            Clear-RemediatorTransientState -PreserveDiagnostics
            exit 0
        }
        if(Test-Path -LiteralPath $restartMarker){
            try { $requested=[string](Get-Content -LiteralPath $restartMarker -Raw -Encoding UTF8 | ConvertFrom-Json).mode } catch { $requested='Windows' }
            Remove-Item -LiteralPath $restartMarker -Force -ErrorAction SilentlyContinue
            if($requested -notin @('Windows','Setup')){ $requested='Windows' }
            # Setup's backend restart endpoint naturally writes a Setup marker before the Control
            # Center can promote it to Windows. The launcher is authoritative: when a complete
            # canonical Windows configuration exists, a restart from a healthy Setup session is
            # always a promotion, even if the short-lived marker still says Setup.
            if($nextMode -eq 'Setup' -and $requested -eq 'Setup'){
                try {
                    $candidate=Get-Content -LiteralPath $localConfig -Raw -Encoding UTF8 | ConvertFrom-Json
                    if($candidate -and [string]$candidate.Mode -eq 'Windows' -and $candidate.Windows -and $candidate.Windows.Domain -and $candidate.Windows.DomainController){
                        $requested='Windows'
                        Write-Log 'Resolved Setup restart marker race: complete Windows configuration is present, so restart is promoted to WINDOWS / AD.' Cyan
                    }
                } catch { }
            }
            Write-Log ('UI requested restart into '+$requested+' mode.') Yellow
            $nextMode=$requested
            if($requested -eq 'Windows'){ $script:startupIssue=''; $setupRecoveryUsed=$false }
            Start-Sleep -Milliseconds 600
            continue
        }


        if($result.UnexpectedExit -and $nextMode -eq 'Windows'){
            $details=[string]$result.Details
            if([double]$result.UptimeSeconds -ge 300){ $script:runtimeRecoveryAttempts=0 }
            if($script:runtimeRecoveryAttempts -lt 3){
                $script:runtimeRecoveryAttempts++
                $script:startupIssue=('Windows service stopped unexpectedly. Automatic recovery attempt '+$script:runtimeRecoveryAttempts+'/3 is starting.')
                Write-Log $script:startupIssue Yellow
                Start-Sleep -Seconds ([Math]::Min(4,$script:runtimeRecoveryAttempts))
                $nextMode='Windows'
                continue
            }
            Write-Log 'Windows service could not remain healthy after three controlled recovery attempts. Falling back to Setup while preserving diagnostics.' Red
            $script:startupIssue='Windows service repeatedly stopped after becoming healthy. Review windows-startup-error.log before enabling changes.'
            $setupRecoveryUsed=$true
            $nextMode='Setup'
            Start-Sleep -Milliseconds 500
            continue
        }
        if($result.FailedEarly -and $nextMode -eq 'Windows'){
            $details=[string]$result.Details
            $category=Get-StartupFailureCategory $details

            # A damaged/stale extracted runtime is far more common than an AD transport problem at
            # this stage: the health endpoint is local and does not contact the DC. Reinstall the
            # cryptographically verified package once, then retry Windows before falling back.
            if(!$script:runtimePackageRecoveryUsed -and $category -in @('RUNTIME_PACKAGE','PROCESS_EXIT','UNKNOWN')){
                $script:runtimePackageRecoveryUsed=$true
                try {
                    Write-Log ('Early Windows backend failure classified as '+$category+'. Reinstalling the verified self-contained runtime once before recovery mode.') Yellow
                    Install-Runtime
                    $script:startupIssue='Verified runtime was reinstalled after an early backend startup failure. Windows mode retry is in progress.'
                    Start-Sleep -Milliseconds 500
                    $nextMode='Windows'
                    continue
                } catch {
                    Save-WindowsStartupFailure ('Automatic runtime reinstall failed: '+$_.Exception.Message)
                    Write-Log ('Automatic runtime reinstall failed: '+$_.Exception.Message) Red
                }
            }

            $looksLikeStateCorruption = ($category -in @('DATABASE','DATABASE_LOCK_OWNER')) -and ($details -match 'SQLite|database disk image|database is locked|no such column|no such table|schema|execution mode does not match|malformed database|Store\.List|Store\.RecoverInterrupted|gpo_runs|could not be converted to.+GpoRemediator|JsonException.+GpoRemediator\.Domain')
            # Never rotate a healthy small/new database merely because another startup component
            # failed. Database recovery is allowed only when the captured error actually identifies
            # SQLite/schema state as the failure source.
            $shouldTryDbRecovery = !$script:dbRecoveryUsed -and (Test-Path -LiteralPath $windowsDb) -and $looksLikeStateCorruption
            if($shouldTryDbRecovery){
                $script:dbRecoveryUsed=$true
                if(Backup-WindowsDatabaseForRecovery){
                    $script:startupIssue='The failed Windows database was preserved and a clean database retry is in progress.'
                    Start-Sleep -Milliseconds 500
                    $nextMode='Windows'
                    continue
                }
            }
            if(!$setupRecoveryUsed){
                $setupRecoveryUsed=$true
                Write-Log ('Opening safe Setup recovery after local backend startup failure. '+$script:startupIssue) Yellow
                $nextMode='Setup'
                Start-Sleep -Milliseconds 500
                continue
            }
            throw ('Windows mode could not be recovered: '+$script:startupIssue)
        }
        exit ([int]$result.ExitCode)
    }
} catch {
    Write-Log ('FATAL: '+$_.Exception.Message) Red
    Write-Log 'No policy write was attempted by the bootstrapper.' Yellow
    Clear-RemediatorTransientState -PreserveDiagnostics
    exit 1
} finally {
    if($ownsLauncher -and $launcherMutex){ try{$launcherMutex.ReleaseMutex()}catch{} }
    if($launcherMutex){ $launcherMutex.Dispose() }
}
