param(
    [Parameter(Mandatory=$true)][string]$QueueRoot,
    [Parameter(Mandatory=$true)][string]$PublisherCertificatePath,
    [string]$ReceiptCertificateThumbprint,
    [string]$TaskName,
    [string]$TaskPath = '\'
)
$ErrorActionPreference = 'Stop'
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if (!$computer.PartOfDomain -or [int]$computer.DomainRole -notin 1,3) {
    throw 'The refresh worker runs only on domain member workstations and servers.'
}
$hostName = ($computer.DNSHostName + '.' + $computer.Domain).ToLowerInvariant()
if ($hostName -notmatch '\A[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\z' -or
    $QueueRoot -notmatch '^\\\\[a-zA-Z0-9.-]+\\[^\\]+(?:\\[^\\]+)*$' -or
    ($QueueRoot -split '\\' | Where-Object { $_ -in @('.','..') })) {
    throw 'The endpoint name or queue UNC path is invalid.'
}

$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($PublisherCertificatePath)
$key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
if (!$key -or $key.KeySize -lt 2048 -or $cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -lt (Get-Date)) {
    throw 'The provisioned publisher certificate is invalid.'
}
$hostRoot = Join-Path $QueueRoot $hostName
$requests = Join-Path $hostRoot 'requests'
$results = Join-Path $hostRoot 'results'

function Write-Receipt([string]$Path,[string]$Id,[string]$State,[Nullable[long]]$DurationMs,$Evidence=$null) {
    $data = @{id=$Id;computer=$hostName;state=$State;durationMs=$DurationMs}
    if ($Evidence) {
        $data.readAt = [DateTimeOffset]::UtcNow.ToString('O')
        $data.actual = $Evidence.actual
        $data.message = $Evidence.message
    }
    $body = $data | ConvertTo-Json -Compress
    if ($Evidence) {
        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $signature = $script:receiptKey.SignData($bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $body = @{payload=[Convert]::ToBase64String($bytes);signature=[Convert]::ToBase64String($signature)} | ConvertTo-Json -Compress
    }
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temp,$body,[Text.UTF8Encoding]::new($false))
        if ($State -eq 'STARTED') { [IO.File]::Move($temp,$Path) }
        else { [IO.File]::Replace($temp,$Path,[System.Management.Automation.Language.NullString]::Value) }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

function Publish-CheckIn {
    $path = Join-Path $results 'check-in.json'
    $now = [DateTimeOffset]::UtcNow
    $temp = $path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $next = $null
        if ($TaskName) {
            $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
            if ($info -and $info.NextRunTime -gt (Get-Date)) {
                $next = ([DateTimeOffset]$info.NextRunTime).ToUniversalTime()
            }
        }
        if (!$next -and [IO.File]::Exists($path) -and (Get-Item -LiteralPath $path).Length -le 2048) {
            $previous = [IO.File]::ReadAllText($path) | ConvertFrom-Json
            $interval = $now - [DateTimeOffset]::Parse($previous.seenAt)
            if ($interval.TotalSeconds -ge 15 -and $interval.TotalMinutes -le 15) { $next = $now + $interval }
        }
        $schedule = @{
            computer = $hostName
            seenAt = $now.ToString('O')
            userRefresh = [IO.File]::Exists((Join-Path $env:SystemRoot 'System32\quser.exe')) -and [bool](Get-Module -ListAvailable -Name GroupPolicy | Select-Object -First 1)
        }
        if ($next) { $schedule.nextCheckAt = $next.ToString('O') }
        [IO.File]::WriteAllText($temp,($schedule | ConvertTo-Json -Compress))
        if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp,$path,[Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temp,$path) }
    } catch { Write-Warning 'Could not publish the worker check-in estimate.' }
    finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

function Initialize-EndpointEvidence {
    if ($script:evidenceReady) { return }
    if ($script:receiptKey) { $script:receiptKey.Dispose(); $script:receiptKey = $null }
    $receiptCert = Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$ReceiptCertificateThumbprint)
    if (!$receiptCert.HasPrivateKey -or $receiptCert.NotBefore -gt (Get-Date) -or $receiptCert.NotAfter -lt (Get-Date)) { throw 'Invalid endpoint evidence certificate.' }
    $script:receiptKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($receiptCert)
    if (!$script:receiptKey -or $script:receiptKey.KeySize -lt 2048) { throw 'Endpoint evidence requires an RSA key of at least 2048 bits.' }
    $root = $script:evidenceRoot
    $script:catalog = (Get-Content -LiteralPath (Join-Path $root 'backend\data\gpo-production-mappings.json') -Raw -Encoding UTF8 | ConvertFrom-Json).mappings
    $tokens=$null;$errors=$null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'backend\PowerShell\GpoWorkflow.Worker.ps1'),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'The installed probe source could not be parsed.' }
    $verify = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Verify-EffectiveSamples'},$false)
    $native = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'UserRight-ProbeSource'},$false)
    # Use only the two local, installed probe blocks. Requests never carry code.
    $script:readers = @{}
    foreach ($command in $verify.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-Command'},$true)) {
        foreach ($element in $command.CommandElements) {
            if ($element -isnot [Management.Automation.Language.ScriptBlockExpressionAst]) { continue }
            $block = $element.ScriptBlock
            $first = $block.ParamBlock.Parameters[0].Name.VariablePath.UserPath
            if ($first -eq 'UserSid') { $script:readers.User = $block.GetScriptBlock() }
            if ($first -eq 'Handler') { $script:readers.Computer = $block.GetScriptBlock() }
        }
    }
    $script:lsaSource = & $native.Body.GetScriptBlock()
    if (!$script:readers.User -or !$script:readers.Computer -or !$script:lsaSource) { throw 'The installed worker probe contract is incomplete.' }
    $script:evidenceReady = $true
}

function Read-EndpointEvidence($Probe) {
    $allowed = @($script:catalog | Where-Object { $_.id -ceq [string]$Probe.controlId })
    if ($allowed.Count -ne 1 -or $Probe.scope -notin @('User','Computer')) { throw 'The control or scope is not allowlisted.' }
    $mapping = $allowed[0]
    $handler = [string]$mapping.handler
    if ($handler -eq 'Manual') { $handler = 'SecurityTemplate' }
    $legacyPrint = $mapping.id -in @('18.7.11','18.7.12') -and $Probe.handler -eq 'Registry' -and @($Probe.items).Count -eq 1
    if (($Probe.scope -ne $mapping.scope -and !($mapping.domainPolicySensitive -and $Probe.scope -eq 'Computer')) -or
        ($Probe.handler -ne $handler -and !$legacyPrint) -or $Probe.handler -notin @('SecurityTemplate','Registry','RegistrySet','AdvancedAudit')) {
        throw 'The scope or probe handler does not match the installed mapping.'
    }
    $items = @($Probe.items)
    $expected = @($mapping.items)
    if (!$items.Count -or $items.Count -gt 32 -or (!$legacyPrint -and $items.Count -ne $expected.Count)) { throw 'The probe field count is invalid.' }
    for ($index=0; $index -lt $items.Count; $index++) {
        foreach ($field in @('section','key','name','type','guid')) {
            if ([string]$items[$index].$field -ine [string]$expected[$index].$field) { throw 'A probe field is outside the installed allowlist.' }
        }
    }
    if ($Probe.scope -eq 'User') {
        if ([string]$Probe.userSid -notmatch '^S-1-5-21-(?:\d+-){3}\d+$') { throw 'A selected domain user SID is required.' }
        return & $script:readers.User ([string]$Probe.userSid) $items
    }
    return & $script:readers.Computer ([string]$Probe.handler) $items ([string]$Probe.comparator) $script:lsaSource $false
}

$script:receiptKey = $null
$script:evidenceReady = $false
$script:evidenceRoot = Split-Path $PSScriptRoot -Parent
try {
    if (!(Test-Path -LiteralPath $requests -PathType Container) -or !(Test-Path -LiteralPath $results -PathType Container)) {
        throw 'This computer has no enrolled request and result folders.'
    }
    Publish-CheckIn
    $pending = Get-ChildItem -LiteralPath $requests -File -Filter '*.json' |
        Where-Object { $_.BaseName -cmatch '^[0-9a-f]{32}$' -and $_.Length -le 32768 -and
            $_.LastWriteTimeUtc -ge [DateTime]::UtcNow.AddDays(-1) -and
            !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
            ![IO.File]::Exists((Join-Path $results $_.Name)) } |
        Sort-Object LastWriteTimeUtc
    $processed = 0
    $sessionAvailable = $null
    foreach ($file in $pending) {
        if ($processed -ge 8) { break }
        try {
            $envelope = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
            $payload = [Convert]::FromBase64String($envelope.payload)
            $signature = [Convert]::FromBase64String($envelope.signature)
            if (!$key.VerifyData($payload,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) { continue }
            $request = [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json
            $expires = [DateTimeOffset]::ParseExact($request.expiresAt,'O',[Globalization.CultureInfo]::InvariantCulture)
            if ($request.id -cne $file.BaseName -or $request.computer -cne $hostName -or
                $request.action -cnotin @('RefreshComputerPolicy','RefreshUserPolicy','VerifyPolicySnapshot') -or $expires -le [DateTimeOffset]::UtcNow -or
                $expires -gt [DateTimeOffset]::UtcNow.AddDays(1).AddMinutes(5)) { continue }
            $receipt = Join-Path $results $file.Name
            $verify = $request.action -ceq 'VerifyPolicySnapshot'
            $userRefresh = $request.action -ceq 'RefreshUserPolicy'
            if ($userRefresh) {
                # Leave the request unclaimed until a user session is available.
                if ($null -eq $sessionAvailable) {
                    $sessionAvailable = $false
                    & (Join-Path $env:SystemRoot 'System32\quser.exe') 2>$null | Out-Null
                    $sessionAvailable = $LASTEXITCODE -eq 0
                }
                if (!$sessionAvailable) { continue }
            }
            if ($verify) {
                if ($ReceiptCertificateThumbprint -notmatch '^[a-fA-F0-9]{40}$' -or $expires -gt [DateTimeOffset]::UtcNow.AddMinutes(6)) { continue }
                Initialize-EndpointEvidence
                Write-Receipt $receipt $request.id 'STARTED' $null @{message='Worker accepted the read-only request.'}
            } else { Write-Receipt $receipt $request.id 'STARTED' $null }
        } catch { continue }

        $processed++
        if ($verify) {
            try {
                $probeResult = Read-EndpointEvidence $request.probe
                $state = if ($probeResult.supported) { if ($probeResult.match) { 'VERIFIED' } else { 'MISMATCH' } }
                    elseif ($probeResult.state -in @('UNAVAILABLE','OBSERVED')) { $probeResult.state }
                    else { 'PENDING' }
                $actual = [string]$probeResult.actual
                if ($actual.Length -gt 4096) { $state = 'UNAVAILABLE'; $actual = '' }
                $message = [string]$probeResult.message
                if ($message.Length -gt 2048) { $message = 'Consult endpoint diagnostics for the full evidence details.' }
            } catch {
                $state='UNAVAILABLE';$actual='';$message='The worker could not run this installed read-only policy probe.'
            }
            Write-Receipt $receipt $request.id $state $null @{actual=$actual;message=$message}
            continue
        }
        if ($userRefresh) {
            try {
                GroupPolicy\Invoke-GPUpdate -Target User -Force -RandomDelayInMinutes 0 -ErrorAction Stop | Out-Null
                $state = 'USER_SCHEDULED'
            } catch { $state = 'FAILED' }
            Write-Receipt $receipt $request.id $state $null
            continue
        }
        $elapsed = [Diagnostics.Stopwatch]::StartNew()
        $process = [Diagnostics.Process]::new()
        $state = 'FAILED'
        try {
            $process.StartInfo = [Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\gpupdate.exe'),'/target:computer /force /wait:-1')
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.CreateNoWindow = $true
            if ($process.Start()) {
                if ($process.WaitForExit(120000)) {
                    if ($process.ExitCode -eq 0) { $state = 'COMPLETED' }
                } else { $process.Kill() }
            }
        } catch { $state = 'FAILED' }
        finally { $process.Dispose() }
        Write-Receipt $receipt $request.id $state $elapsed.ElapsedMilliseconds
    }
} finally {
    if ($script:receiptKey) { $script:receiptKey.Dispose() }
    $key.Dispose()
    $cert.Dispose()
}
