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

$toolsRoot = Join-Path $PSScriptRoot '.tools'
$workRoot = Join-Path $PSScriptRoot 'work'
$restartMarker = Join-Path $workRoot 'restart.request.json'
$backend = Join-Path $PSScriptRoot 'backend'
$runtime = Join-Path $PSScriptRoot 'runtime\GpoRemediator.exe'
$localConfig = Join-Path $backend 'appsettings.Local.json'
$runtimeGeneration = Join-Path $PSScriptRoot 'runtime\production-backend-v3.ready'
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
function Test-PackagedRelease {
    $required = @(
        $runtime,
        (Join-Path $PSScriptRoot 'frontend\dist\index.html'),
        (Join-Path $PSScriptRoot 'frontend\dist\workspace.js'),
        (Join-Path $PSScriptRoot 'frontend\dist\workspace.css'),
        (Join-Path $PSScriptRoot 'frontend\dist\benchmark-v4.json')
    )
    return @($required | Where-Object { !(Test-Path -LiteralPath $_) }).Count -eq 0
}
function Ensure-CurrentBuild {
    # Normal operators run the signed/packaged self-contained runtime directly.
    # Source fingerprint checks belong to Build/Test/Repair workflows and must not
    # turn every ordinary startup into a development build or an SDK download.
    if (!$Repair -and $Mode -notin @('Build','Test') -and (Test-PackagedRelease) -and (Test-Path -LiteralPath $runtimeGeneration)) {
        Write-Log 'Packaged local-only runtime: ready (no SDK download required).'
        return
    }
    if (!$Repair -and $Mode -notin @('Build','Test') -and (Test-PackagedRelease) -and !(Test-Path -LiteralPath $runtimeGeneration)) {
        Write-Log 'This package contains a newer production remediation backend. Performing the one-time runtime upgrade...' Yellow
    }
    if (!$Repair -and $Mode -notin @('Build','Test')) {
        Write-Log 'A one-time runtime build is required. After it completes, normal starts do not download the SDK.' Yellow
    } else {
        Write-Log 'Developer/repair build requested. Checking source fingerprints...' Yellow
    }
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
    if ($cfg -and [string]$cfg.Mode -eq 'Windows') { return 'Windows' }
    if (Test-Path -LiteralPath $localConfig) { $script:startupIssue = 'Saved Windows configuration is incomplete or invalid. Complete Setup & settings.' }
    return 'Setup'
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
        if (!$cfg) { throw 'Windows configuration is missing. Complete the first-run Setup screen.' }
        foreach ($field in @('Domain','DomainController','BackupPath','AllowedOperators')) {
            if (!$cfg.Windows.$field) { throw "Windows configuration needs $field. Complete Setup & settings." }
        }
        # GPO/AD modules execute on the pinned writable DC over Kerberos PowerShell remoting.
        # The local management host therefore does not need RSAT/GPMC installed.
        $url = "http://127.0.0.1:$Port"
        $arguments = @('--contentRoot',('"'+$backend+'"'),'--Mode','Windows','--urls',$url)
        Write-Log ('Starting local-only WINDOWS / AD mode at ' + $url) Cyan
    } elseif ($RunMode -eq 'Setup') {
        $url = "http://localhost:$Port"
        $arguments = @('--contentRoot',('"'+$backend+'"'),'--Mode','Setup','--LocalSetup','true','--urls',$url)
        Write-Log ('Starting configuration-only SETUP mode at ' + $url) Cyan
    } else { throw ('Unsupported runtime mode: ' + $RunMode) }
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
                $marker = Get-Content -LiteralPath $restartMarker -Raw | ConvertFrom-Json
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
