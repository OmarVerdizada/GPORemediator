param(
    [Parameter(Mandatory=$true)][string]$QueueRoot,
    [Parameter(Mandatory=$true)][string]$PublisherCertificatePath
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

function Write-Receipt([string]$Path,[string]$Id,[string]$State,[Nullable[long]]$DurationMs) {
    $body = @{id=$Id;computer=$hostName;state=$State;durationMs=$DurationMs} | ConvertTo-Json -Compress
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temp,$body,[Text.UTF8Encoding]::new($false))
        if ($State -eq 'STARTED') { [IO.File]::Move($temp,$Path) }
        else { [IO.File]::Replace($temp,$Path,$null) }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

try {
    if (!(Test-Path -LiteralPath $requests -PathType Container) -or !(Test-Path -LiteralPath $results -PathType Container)) {
        throw 'This computer has no enrolled request and result folders.'
    }
    $pending = Get-ChildItem -LiteralPath $requests -File -Filter '*.json' |
        Where-Object { $_.BaseName -cmatch '^[0-9a-f]{32}$' -and $_.Length -le 8192 -and
            $_.LastWriteTimeUtc -ge [DateTime]::UtcNow.AddDays(-1) -and
            !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
            ![IO.File]::Exists((Join-Path $results $_.Name)) } |
        Sort-Object LastWriteTimeUtc | Select-Object -First 8
    foreach ($file in $pending) {
        try {
            $envelope = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
            $payload = [Convert]::FromBase64String($envelope.payload)
            $signature = [Convert]::FromBase64String($envelope.signature)
            if (!$key.VerifyData($payload,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) { continue }
            $request = [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json
            $expires = [DateTimeOffset]::ParseExact($request.expiresAt,'O',[Globalization.CultureInfo]::InvariantCulture)
            if ($request.id -cne $file.BaseName -or $request.computer -cne $hostName -or
                $request.action -cne 'RefreshComputerPolicy' -or $expires -le [DateTimeOffset]::UtcNow -or
                $expires -gt [DateTimeOffset]::UtcNow.AddDays(1).AddMinutes(5)) { continue }
            $receipt = Join-Path $results $file.Name
            Write-Receipt $receipt $request.id 'STARTED' $null
        } catch { continue }

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
    $key.Dispose()
    $cert.Dispose()
}
