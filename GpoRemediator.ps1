param(
    [ValidateSet('Auto','Demo','Windows','Build','Test')]
    [string]$Mode = 'Auto',
    [ValidateRange(1024,65535)]
    [int]$Port = 5080,
    [switch]$NoBrowser,
    [switch]$Repair,
    [switch]$PrereqHelper
)

$ErrorActionPreference = 'Stop'
# A PowerShell 7 parent can omit the Windows PowerShell module directory.
$windowsModules = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$env:PSModulePath = "$windowsModules;" + (($env:PSModulePath -split ';' | Where-Object { $_ -ine $windowsModules }) -join ';')
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'scripts\Tooling.ps1')

$toolsRoot = Join-Path $PSScriptRoot '.tools'
$workRoot = Join-Path $PSScriptRoot 'work'
$restartMarker = Join-Path $workRoot 'restart.request.json'
$backend = Join-Path $PSScriptRoot 'backend'
$runtime = Join-Path $PSScriptRoot 'runtime\GpoRemediator.exe'
$localConfig = Join-Path $backend 'appsettings.Local.json'
New-Item -ItemType Directory -Force -Path $toolsRoot,$workRoot | Out-Null
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
function Add-ToolPath([string]$Path) {
    if ((Test-Path -LiteralPath $Path) -and (($env:Path -split ';') -notcontains $Path)) { $env:Path = "$Path;$env:Path" }
}
function Test-Dotnet8Sdk([string]$Exe) {
    if (!(Test-Path -LiteralPath $Exe) -and !(Get-Command $Exe -ErrorAction SilentlyContinue)) { return $false }
    try { return [bool]((& $Exe --list-sdks 2>$null) -match '^8\.') } catch { return $false }
}
function Ensure-Dotnet8Sdk {
    $existing = Get-Command dotnet.exe,dotnet -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing -and (Test-Dotnet8Sdk $existing.Source)) { Write-Log '.NET 8 SDK: OK'; return }
    $installRoot = Join-Path $toolsRoot 'dotnet'
    $localExe = Join-Path $installRoot 'dotnet.exe'
    if (Test-Dotnet8Sdk $localExe) { Add-ToolPath $installRoot; Write-Log '.NET 8 SDK: portable cache OK'; return }
    Write-Log 'Downloading portable .NET 8 SDK...' Yellow
    New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
    $installer = Join-Path $toolsRoot 'dotnet-install.ps1'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installer
    & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $installer -Channel 8.0 -InstallDir $installRoot -NoPath
    if ($LASTEXITCODE -ne 0 -or !(Test-Dotnet8Sdk $localExe)) { throw 'Portable .NET 8 SDK installation failed.' }
    Add-ToolPath $installRoot
    Write-Log '.NET 8 SDK installed.' Green
}
function Ensure-BuildToolchain {
    # The shipped UI is static and dependency-free. Only .NET is required to rebuild the backend.
    Ensure-Dotnet8Sdk
}
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Install-RsatComponents {
    $ad = Get-Module -ListAvailable ActiveDirectory | Select-Object -First 1
    $gp = Get-Module -ListAvailable GroupPolicy | Select-Object -First 1
    if ($ad -and $gp) { return }
    if (!(Test-Administrator)) { throw 'RSAT installation helper must run elevated.' }
    Write-Log 'Installing missing RSAT ActiveDirectory / GroupPolicy components...' Yellow
    $serverInstaller = Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue
    if ($serverInstaller) {
        Import-Module ServerManager -ErrorAction Stop
        $features = @()
        if (!$ad) { $features += 'RSAT-AD-PowerShell' }
        if (!$gp) { $features += 'GPMC' }
        if ($features.Count) { Install-WindowsFeature -Name $features -IncludeManagementTools -ErrorAction Stop | Out-Null }
    } else {
        $capability = Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue
        if (!$capability) { throw 'RSAT is missing and this Windows edition does not expose Install-WindowsFeature or Add-WindowsCapability.' }
        if (!$ad) { Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ErrorAction Stop | Out-Null }
        if (!$gp) { Add-WindowsCapability -Online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0' -ErrorAction Stop | Out-Null }
    }
}
function Ensure-Rsat {
    $ad = Get-Module -ListAvailable ActiveDirectory | Select-Object -First 1
    $gp = Get-Module -ListAvailable GroupPolicy | Select-Object -First 1
    if ($ad -and $gp) { Write-Log 'RSAT ActiveDirectory + GroupPolicy: OK'; return }
    if (!(Test-Administrator)) {
        Write-Log 'RSAT requires a one-time UAC-approved installation. The application itself will remain in this non-elevated launcher process.' Yellow
        $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode Windows -Port {1} -PrereqHelper' -f $PSCommandPath,$Port
        $helper = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -PassThru
        while (!$helper.WaitForExit(15000)) {
            Write-Log 'RSAT installation is still running. Windows is preparing optional components; do not start another installation.' Yellow
        }
        if ($helper.ExitCode -ne 0) { throw 'Elevated RSAT prerequisite installation failed or was cancelled.' }
    } else { Install-RsatComponents }
    if (!(Get-Module -ListAvailable ActiveDirectory) -or !(Get-Module -ListAvailable GroupPolicy)) { throw 'RSAT was installed but the required PowerShell modules are still unavailable. Restart Windows once, then run GpoRemediator.cmd again.' }
    Write-Log 'RSAT installed.' Green
}
function Ensure-CurrentBuild {
    $backendMatch = Test-PortableBackendMatchesSource
    $frontendMatch = Test-FrontendDistMatchesSource
    if (!$Repair -and $backendMatch -and $frontendMatch -and (Test-Path -LiteralPath $runtime)) { Write-Log 'Application build: current'; return }
    Write-Log 'Source is newer than the packaged runtime (or repair was requested). Building the current product without Node.js/pnpm...' Yellow
    Ensure-BuildToolchain
    & (Join-Path $PSScriptRoot 'Build-Portable.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Application build failed.' }
    if (!(Test-PortableBackendMatchesSource) -or !(Test-FrontendDistMatchesSource)) { throw 'Build completed but source fingerprints do not match.' }
    Write-Log 'Application build completed and fingerprints match.' Green
}
function Read-LocalConfig {
    if (!(Test-Path -LiteralPath $localConfig)) { return $null }
    try { return Get-Content -LiteralPath $localConfig -Raw | ConvertFrom-Json } catch { Write-Log ('Ignoring invalid local config: ' + $_.Exception.Message) Yellow; return $null }
}
function Resolve-RunMode([string]$Requested) {
    if ($Requested -ne 'Auto') { return $Requested }
    $cfg = Read-LocalConfig
    if ($cfg -and [string]$cfg.Mode -eq 'Windows' -and [string]$cfg.Urls -match '^https://') { return 'Windows' }
    if (Test-Path -LiteralPath $localConfig) { $script:startupIssue = 'Saved Windows configuration is incomplete or invalid. Complete Setup & settings.' }
    return 'Demo'
}
function Wait-ApplicationReady([System.Diagnostics.Process]$Process,[string]$Url) {
    for ($i=0; $i -lt 40; $i++) {
        if ($Process.HasExited) { return $false }
        try { $r = Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($Url.TrimEnd('/') + '/api/session') -TimeoutSec 2; if ($r.StatusCode -eq 200) { return $true } } catch { }
        Start-Sleep -Milliseconds 300
    }
    return $false
}
function Start-Application([string]$RunMode) {
    $serverLog = Join-Path $workRoot 'server.log'; $serverError = Join-Path $workRoot 'server-error.log'
    Remove-Item -LiteralPath $serverLog,$serverError -Force -ErrorAction SilentlyContinue
    if ($RunMode -eq 'Windows') {
        $cfg = Read-LocalConfig
        if (!$cfg -or !$cfg.Urls -or [string]$cfg.Urls -notmatch '^https://') { throw 'Windows configuration is missing or invalid. Start Demo mode and use Setup & settings.' }
        foreach ($field in @('Domain','DomainController','BackupPath','ApprovedGpoIds','AuthorizedOus','AllowedHosts','AllowedOperators')) {
            if (!$cfg.Windows.$field) { throw "Windows configuration needs $field. Complete Setup & settings." }
        }
        Ensure-Rsat
        $url = [string]$cfg.Urls
        $uri = [Uri]$url
        $certHost = $uri.DnsSafeHost
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and $_.Subject -match [regex]::Escape($certHost) } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
        if (!$cert) { throw ("HTTPS certificate not found in LocalMachine\My for host '{0}'. Install an enterprise/server certificate for this DNS name, then the same launcher can start Windows mode." -f $certHost) }
        Write-Log ('HTTPS certificate: ' + $cert.Thumbprint)
        $arguments = @('--contentRoot',('"'+$backend+'"'),'--Mode','Windows','--urls',('"'+$url+'"'))
        Write-Log ('Starting WINDOWS mode at ' + $url) Cyan
    } else {
        $url = "http://localhost:$Port"
        $arguments = @('--contentRoot',('"'+$backend+'"'),'--Mode','Mock','--urls',$url)
        if ($script:startupIssue) { $arguments += @('--LocalSetup','true') }
        Write-Log ('Starting safe MOCK mode at ' + $url) Cyan
    }
    Remove-Item -LiteralPath $restartMarker -Force -ErrorAction SilentlyContinue
    $arguments += @('--LauncherManaged','true')
    $process = Start-Process -FilePath $runtime -ArgumentList $arguments -WorkingDirectory $backend -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverLog -RedirectStandardError $serverError
    $openPath = if ($script:startupIssue) { '/#/settings' } else { '/#/home' }
    $serviceState = @{ processId=$process.Id; startedAt=$process.StartTime.ToUniversalTime().ToString('o'); url=$url; mode=$RunMode; launcherId=$PID; ready=$false; openPath=$openPath; startupIssue=$script:startupIssue }
    $serviceState | ConvertTo-Json | Set-Content -LiteralPath ($stateFile+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($stateFile+'.tmp') -Destination $stateFile -Force
    $ready = Wait-ApplicationReady $process $url
    if (!$ready) {
        if (!$process.HasExited) { Stop-Process -Id $process.Id -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
        $details = if (Test-Path -LiteralPath $serverError) { (Get-Content -LiteralPath $serverError -Tail 30) -join [Environment]::NewLine } else { 'No server error log was produced.' }
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
    if ($PrereqHelper) { Install-RsatComponents; Write-Log 'Elevated prerequisite helper completed.' Green; exit 0 }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $rootHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($PSScriptRoot.ToLowerInvariant()))).Replace('-','').Substring(0,24) } finally { $sha.Dispose() }
    $launcherMutex = New-Object Threading.Mutex($false, ('Local\GpoRemediatorLauncher-' + $rootHash))
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
                $marker = Get-Content -LiteralPath $restartMarker -Raw | ConvertFrom-Json
                $requested = [string]$marker.mode
            } catch { $requested = 'Windows' }
            Remove-Item -LiteralPath $restartMarker -Force -ErrorAction SilentlyContinue
            if ($requested -notin @('Windows','Demo')) { $requested = 'Windows' }
            Write-Log ('UI requested a controlled restart into ' + $requested + ' mode.') Yellow
            $nextMode = $requested
            $script:startupIssue = ''
            Start-Sleep -Milliseconds 700
            continue
        }
        if ($result.FailedEarly -and $nextMode -eq 'Windows') {
            if (!$script:startupIssue) { $script:startupIssue = 'Windows service could not start. Check server logs, HTTPS certificate and operator permissions.' }
            Write-Log 'Windows mode could not start (often certificate/config/permission related). Falling back to safe Demo UI so Setup remains accessible.' Yellow
            $nextMode = 'Demo'
            continue
        }
        exit ([int]$result.ExitCode)
    }
} catch {
    Write-Log ('FATAL: ' + $_.Exception.Message) Red
    Write-Log 'No policy write was attempted by the bootstrapper. Review the message and work\bootstrap.log.' Yellow
    exit 1
} finally {
    if ($ownsLauncher -and $launcherMutex) { $launcherMutex.ReleaseMutex() }
    if ($launcherMutex) { $launcherMutex.Dispose() }
}
