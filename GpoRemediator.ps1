param(
    [ValidateSet('Auto','Setup','Windows','Build','Test')]
    [string]$Mode = 'Auto',
    [ValidateRange(1024,65535)]
    [int]$Port = 5080,
    [switch]$NoBrowser,
    [switch]$Repair
)

$ErrorActionPreference = 'Stop'
# A PowerShell 7 parent can omit the Windows PowerShell module directory.
$windowsModules = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$env:PSModulePath = "$windowsModules;" + (($env:PSModulePath -split ';' | Where-Object { $_ -ine $windowsModules }) -join ';')
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\Tooling.ps1')
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')

$stateRoot = Join-Path $env:ProgramData 'GpoRemediator'
$workRoot = Join-Path $stateRoot 'State'
$restartMarker = Join-Path $workRoot 'restart.request.json'
$backend = Join-Path $PSScriptRoot 'backend'
$runtime = Join-Path $PSScriptRoot 'runtime\GpoRemediator.exe'
$localConfig = Join-Path $stateRoot 'Config\appsettings.Local.json'
$runtimeGeneration = Join-Path $PSScriptRoot 'runtime\production-backend-v4.ready'
$runtimeArchive = Join-Path $PSScriptRoot 'release\GpoRemediator-runtime-win-x64.zip'
$runtimeArchiveHash = Join-Path $PSScriptRoot 'release\GpoRemediator-runtime-win-x64.zip.sha256'
function Initialize-SecureState {
    foreach ($path in @($stateRoot,$workRoot,(Split-Path $localConfig -Parent),(Join-Path $stateRoot 'Data'),(Join-Path $stateRoot 'Backups'))) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
        # Read/write only the DACL. Re-applying inherited SACL data through Set-Acl
        # can require SeSecurityPrivilege even when the operator already owns this
        # product directory.
        $item = Get-Item -LiteralPath $path
        $acl = $item.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
        $acl.SetAccessRuleProtection($true,$false)
        foreach($rule in @(
            (New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')),
            (New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')),
            (New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        )) { $acl.AddAccessRule($rule) | Out-Null }
        $item.SetAccessControl($acl)
    }
}
Initialize-SecureState
$logFile = Join-Path $workRoot 'bootstrap.log'
$stateFile = Join-Path $workRoot 'service.json'
$launcherMutex = $null
$ownsLauncher = $false
$script:startupIssue = ''

function Write-Log([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    $line = ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
    Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
    Write-Host $Message -ForegroundColor $Color
}
function Test-Dotnet8Sdk([string]$Exe) {
    if (!(Test-Path -LiteralPath $Exe) -and !(Get-Command $Exe -ErrorAction SilentlyContinue)) { return $false }
    try { return [bool]((& $Exe --list-sdks 2>$null) -match '^8\.') } catch { return $false }
}
function Require-Dotnet8Sdk {
    $existing = Get-Command dotnet.exe,dotnet -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing -and (Test-Dotnet8Sdk $existing.Source)) { Write-Log '.NET 8 SDK: OK'; return }
    throw '.NET 8 SDK is required only for an explicit developer Build/Test. Production startup never downloads or compiles code.'
}
function Ensure-BuildToolchain {
    # The shipped UI is static and dependency-free. Only .NET is required to rebuild the backend.
    Require-Dotnet8Sdk
}
function Test-PackagedRelease {
    $required = @(
        $runtime,
        (Join-Path $PSScriptRoot 'frontend\dist\index.html'),
        (Join-Path $PSScriptRoot 'frontend\dist\workspace.js'),
        (Join-Path $PSScriptRoot 'frontend\dist\client.js'),
        (Join-Path $PSScriptRoot 'frontend\dist\automation.js'),
        (Join-Path $PSScriptRoot 'frontend\dist\ui-domain.js'),
        (Join-Path $PSScriptRoot 'frontend\dist\i18n.js'),
        (Join-Path $PSScriptRoot 'frontend\dist\router.js'),
        (Join-Path $PSScriptRoot 'frontend\dist\workspace.css'),
        (Join-Path $PSScriptRoot 'frontend\dist\benchmark-v4.json')
    )
    return @($required | Where-Object { !(Test-Path -LiteralPath $_) }).Count -eq 0
}
function Install-PackagedRuntime {
    if (!(Test-Path -LiteralPath $runtimeArchive) -or !(Test-Path -LiteralPath $runtimeArchiveHash)) { return $false }
    $expected = (Get-Content -LiteralPath $runtimeArchiveHash -Raw -Encoding ASCII).Trim()
    if ($expected -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Packaged runtime hash manifest is invalid.' }
    $actual = (Get-FileHash -LiteralPath $runtimeArchive -Algorithm SHA256).Hash
    if ($actual -cne $expected.ToUpperInvariant()) { throw 'Packaged runtime archive failed SHA-256 verification.' }
    $stage = Join-Path $workRoot ('runtime-install-' + [Guid]::NewGuid().ToString('N'))
    $old = Join-Path $workRoot ('runtime-old-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        Expand-Archive -LiteralPath $runtimeArchive -DestinationPath $stage -Force
        foreach ($required in @('GpoRemediator.exe','backend-source.sha256','production-backend-v4.ready')) {
            if (!(Test-Path -LiteralPath (Join-Path $stage $required))) { throw "Packaged runtime archive is incomplete: $required is missing." }
        }
        $sourceHash = (Get-BackendSourceFingerprint)
        $archiveSourceHash = (Get-Content -LiteralPath (Join-Path $stage 'backend-source.sha256') -Raw).Trim()
        if ($archiveSourceHash -cne $sourceHash) { throw 'Packaged runtime does not match the current backend source.' }
        $runtimeRoot = Split-Path $runtime -Parent
        if (Test-Path -LiteralPath $runtimeRoot) { Move-Item -LiteralPath $runtimeRoot -Destination $old }
        try {
            Move-Item -LiteralPath $stage -Destination $runtimeRoot
            if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Recurse -Force }
        } catch {
            if (Test-Path -LiteralPath $runtimeRoot) { Remove-Item -LiteralPath $runtimeRoot -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path -LiteralPath $old) { Move-Item -LiteralPath $old -Destination $runtimeRoot -Force }
            throw
        }
        Write-Log 'Verified packaged runtime installed locally; no SDK or compilation was used.' Green
        return $true
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
function Ensure-CurrentBuild {
    # Normal operators run the prebuilt package. A missing/stale runtime fails closed;
    # source is never compiled implicitly on a customer machine.
    if (!$Repair -and $Mode -notin @('Build','Test') -and (Test-PackagedRelease) -and (Test-Path -LiteralPath $runtimeGeneration) -and (Test-PortableBackendMatchesSource) -and (Test-FrontendDistMatchesSource)) {
        Write-Log 'Packaged local-only runtime: ready (no SDK download required).'
        return
    }
    if (!$Repair -and $Mode -notin @('Build','Test')) {
        if ((Install-PackagedRuntime) -and (Test-PackagedRelease) -and (Test-PortableBackendMatchesSource) -and (Test-FrontendDistMatchesSource)) {
            Write-Log 'Packaged local-only runtime: ready (no SDK download required).'
            return
        }
        throw 'Packaged runtime integrity check failed. Install a complete verified release; production startup will not download or compile source.'
    }
    Write-Log 'Explicit developer build requested. Checking source fingerprints...' Yellow
    Ensure-BuildToolchain
    & (Join-Path $PSScriptRoot 'Build-Portable.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Application build failed.' }
    if (!(Test-PortableBackendMatchesSource) -or !(Test-FrontendDistMatchesSource)) { throw 'Build completed but source fingerprints do not match.' }
    Write-Log 'Application build completed and fingerprints match.' Green
}
function Read-LocalConfig {
    if (!(Test-Path -LiteralPath $localConfig)) { return $null }
    try { return Get-Content -LiteralPath $localConfig -Encoding UTF8 -Raw | ConvertFrom-Json } catch { Write-Log ('Ignoring invalid local config: ' + $_.Exception.Message) Yellow; return $null }
}
function Resolve-RunMode([string]$Requested) {
    if ($Requested -ne 'Auto') { return $Requested }
    $cfg = Read-LocalConfig
    if ($cfg -and [string]$cfg.Mode -eq 'Windows') { return 'Windows' }
    if (Test-Path -LiteralPath $localConfig) { $script:startupIssue = 'Saved Windows configuration is incomplete or invalid. Complete Setup & settings.' }
    return 'Setup'
}
function Wait-ApplicationReady([System.Diagnostics.Process]$Process,[string]$Url) {
    for ($i=0; $i -lt 40; $i++) {
        if ($Process.HasExited) { return $false }
        try { $r = Invoke-WebRequest -UseBasicParsing -Uri ($Url.TrimEnd('/') + '/api/v1/health/ready') -TimeoutSec 2; if ($r.StatusCode -eq 200) { return $true } } catch { }
        Start-Sleep -Milliseconds 300
    }
    return $false
}
function Start-Application([string]$RunMode) {
    $serverLog = Join-Path $workRoot 'server.log'; $serverError = Join-Path $workRoot 'server-error.log'
    Remove-Item -LiteralPath $serverLog,$serverError -Force -ErrorAction SilentlyContinue
    if ($RunMode -eq 'Windows') {
        $cfg = Read-LocalConfig
        if (!$cfg) { throw 'Windows configuration is missing. Complete the first-run Setup screen.' }
        foreach ($field in @('Domain','DomainController','BackupPath','AllowedOperators')) {
            if (!$cfg.Windows.$field) { throw "Windows configuration needs $field. Complete Setup & settings." }
        }
        # GPO/AD modules execute on the pinned writable DC over Kerberos PowerShell remoting.
        # The local management host therefore does not need RSAT/GPMC installed.
        $url = "http://127.0.0.1:$Port"
        $arguments = @('--contentRoot',('"'+$backend+'"'),'--LocalConfigPath',('"'+$localConfig+'"'),'--Mode','Windows','--urls',$url)
        Write-Log ('Starting local-only WINDOWS / AD mode at ' + $url) Cyan
    } elseif ($RunMode -eq 'Setup') {
        $url = "http://localhost:$Port"
        $arguments = @('--contentRoot',('"'+$backend+'"'),'--LocalConfigPath',('"'+$localConfig+'"'),'--Mode','Setup','--LocalSetup','true','--urls',$url)
        Write-Log ('Starting configuration-only SETUP mode at ' + $url) Cyan
    } else { throw ('Unsupported runtime mode: ' + $RunMode) }
    Remove-Item -LiteralPath $restartMarker -Force -ErrorAction SilentlyContinue
    $arguments += @('--LauncherManaged','true')
    $process = Start-Process -FilePath $runtime -ArgumentList $arguments -WorkingDirectory $backend -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverLog -RedirectStandardError $serverError
    $openPath = if ($script:startupIssue) { '/#/settings' } else { '/#/dashboard' }
    $serviceState = @{ processId=$process.Id; startedAt=$process.StartTime.ToUniversalTime().ToString('o'); url=$url; mode=$RunMode; launcherId=$PID; ready=$false; openPath=$openPath; startupIssue=$script:startupIssue }
    $serviceState | ConvertTo-Json | Set-Content -LiteralPath ($stateFile+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($stateFile+'.tmp') -Destination $stateFile -Force
    $ready = Wait-ApplicationReady $process $url
    if (!$ready) {
        if (!$process.HasExited) { Stop-Process -Id $process.Id -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
        $details = if (Test-Path -LiteralPath $serverError) { (Get-Content -LiteralPath $serverError -Encoding UTF8 -Tail 30) -join [Environment]::NewLine } else { 'No server error log was produced.' }
        Write-Log "Application did not start successfully.`n$details" Red
        return @{ ExitCode = if ($process.HasExited) { $process.ExitCode } else { 1 }; FailedEarly = $true; Url = $url }
    }
    $serviceState.ready = $true
    $serviceState | ConvertTo-Json | Set-Content -LiteralPath ($stateFile+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($stateFile+'.tmp') -Destination $stateFile -Force
    if (!$NoBrowser) {
        $openUrl = $url
        $openUrl = $url.TrimEnd('/') + $openPath
        Start-Process $openUrl | Out-Null
    }
    Write-Log 'Web UI is running. Closing this console stops the local service.' Green
    try { Wait-Process -Id $process.Id -ErrorAction SilentlyContinue } finally {
        Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
        if (!$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    return @{ ExitCode = $process.ExitCode; FailedEarly = $false; Url = $url }
}

try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $rootHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($PSScriptRoot.ToLowerInvariant()))).Replace('-','').Substring(0,24) } finally { $sha.Dispose() }
    $launcherMutex = New-Object Threading.Mutex($false, ('Global\GpoRemediatorLauncher-' + $rootHash))
    try { $ownsLauncher = $launcherMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsLauncher = $true }
    if (!$ownsLauncher) {
        Write-Log 'This project is already running or building. Use the control panel to open or stop it.' Yellow
        if ($Mode -in @('Build','Test')) { exit 1 }
        exit 0
    }
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host ' GPO Remediator - Unified Bootstrap / Operator Launcher' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Log ('Launcher mode: ' + $Mode)

    Ensure-CurrentBuild
    if ($Mode -eq 'Build') { Write-Log 'Build-only operation completed.' Green; exit 0 }
    if ($Mode -eq 'Test') {
        Ensure-BuildToolchain
        & (Join-Path $PSScriptRoot 'Test.ps1')
        exit $LASTEXITCODE
    }

    $nextMode = Resolve-RunMode $Mode
    $recoverySetupUsed = $false
    while ($true) {
        try { $result = Start-Application $nextMode }
        catch {
            if ($nextMode -ne 'Windows') { throw }
            $script:startupIssue = $_.Exception.Message
            Write-Log ('Windows startup needs attention: ' + $script:startupIssue) Yellow
            $result = @{ ExitCode=1; FailedEarly=$true }
        }
        if (Test-Path -LiteralPath $restartMarker) {
            try {
                $marker = Get-Content -LiteralPath $restartMarker -Encoding UTF8 -Raw | ConvertFrom-Json
                $requested = [string]$marker.mode
            } catch { $requested = 'Windows' }
            Remove-Item -LiteralPath $restartMarker -Force -ErrorAction SilentlyContinue
            if ($requested -notin @('Windows','Setup')) { $requested = 'Windows' }
            Write-Log ('UI requested a controlled restart into ' + $requested + ' mode.') Yellow
            $nextMode = $requested
            if ($requested -eq 'Windows') { $recoverySetupUsed = $false }
            Start-Sleep -Milliseconds 700
            continue
        }
        if ($result.FailedEarly -and $nextMode -eq 'Windows') {
            if (!$script:startupIssue) { $script:startupIssue = 'Windows service could not start. Check the saved domain/DC configuration, Kerberos/WinRM connectivity and operator settings.' }
            if (!$recoverySetupUsed) {
                # Recovery is configuration-only, loopback-only and cannot perform GPO writes.
                # This keeps the product usable without ever falling back to a simulation mode.
                Write-Log ('Opening safe Setup mode so the Windows / AD issue can be corrected: ' + $script:startupIssue) Yellow
                $recoverySetupUsed = $true
                $nextMode = 'Setup'
                Start-Sleep -Milliseconds 500
                continue
            }
            Write-Log ('Windows mode could not be recovered. ' + $script:startupIssue) Red
            exit 1
        }
        Clear-RemediatorEphemeralState
        exit ([int]$result.ExitCode)
    }
} catch {
    Write-Log ('FATAL: ' + $_.Exception.Message) Red
    Write-Log 'No policy write was attempted by the bootstrapper.' Yellow
    Clear-RemediatorEphemeralState -PreserveDiagnostics
    exit 1
} finally {
    if ($ownsLauncher -and $launcherMutex) { $launcherMutex.ReleaseMutex() }
    if ($launcherMutex) { $launcherMutex.Dispose() }
}
