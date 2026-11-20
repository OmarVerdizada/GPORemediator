# Fixtures exercise the deployed worker's actual parser, allowlist and proof format.
# No AD, endpoint connection, audit policy or gpupdate is invoked.
$ErrorActionPreference = 'Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-EndpointRefreshWorker.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($function in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
function Check($Condition,[string]$Name) {
    if (!$Condition) { throw $Name }
    Write-Output ('PASS ' + $Name)
}
function Reject([scriptblock]$Block,[string]$Name) {
    try { & $Block | Out-Null } catch { Write-Output ('PASS ' + $Name); return }
    throw $Name
}
$hostName='endpoint.example.test'
$ReceiptCertificateThumbprint='0'*40
$script:receiptKey=$null
$script:evidenceReady=$false
$script:evidenceRoot=Split-Path $PSScriptRoot -Parent
$temp=Join-Path ([IO.Path]::GetTempPath()) ('gpor-proof-'+[guid]::NewGuid().ToString('N')+'.json')
$rsa=[Security.Cryptography.RSA]::Create(2048)
$certificateRequest=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=gpor fixture',$rsa,
    [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
$certificate=$certificateRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddHours(-1),[DateTimeOffset]::UtcNow.AddHours(1))
function Get-Item {
    param($LiteralPath)
    if ($LiteralPath -eq ('Cert:\LocalMachine\My\'+$ReceiptCertificateThumbprint)) { return $certificate }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath
}
try {
    Initialize-EndpointEvidence
    Check ($script:evidenceReady -and $script:lsaSource -match 'LsaEnumerateAccountsWithUserRight') 'installed native probes and catalog can load without running the domain worker'
    $script:readers.Computer={param($Handler,$Items,$Comparator,$Native,$Rollback) @{supported=$true;match=$true;actual=$Items[0].key} }
    $script:readers.User={param($Sid,$Items) @{supported=$true;match=$true;actual=$Sid} }
    $computer=$script:catalog | Where-Object id -eq '2.2.3'
    $probe=@{controlId=$computer.id;scope=$computer.scope;handler=$computer.handler;items=@($computer.items);comparator=$computer.comparator}
    $evidence=Read-EndpointEvidence $probe
    Check ($evidence.actual -eq 'SeNetworkLogonRight') 'allowed LSA control routes to the computer probe'
    $probe.items=@(@{section='Privilege Rights';key='SeDebugPrivilege';type='Principals'})
    Reject {Read-EndpointEvidence $probe} 'signed payload cannot select a different LSA right'
    $user=$script:catalog | Where-Object id -eq '19.7.8.1'
    $probe=@{controlId=$user.id;scope='User';handler=$user.handler;items=@($user.items);userSid='S-1-5-21-1-2-3-1001'}
    $evidence=Read-EndpointEvidence $probe
    Check ($evidence.actual -eq $probe.userSid) 'allowlisted User GPO routes to the selected user hive probe'
    $probe.userSid='S-1-5-18'
    Reject {Read-EndpointEvidence $probe} 'system SID cannot be supplied as a domain user'
    $id=[guid]::NewGuid().ToString('N')
    Write-Receipt $temp $id 'STARTED' $null @{message='pending'}
    Write-Receipt $temp $id 'VERIFIED' $null @{actual='value=2';message='fixture'}
    $file=[IO.File]::ReadAllText($temp)|ConvertFrom-Json
    $payload=[Convert]::FromBase64String($file.payload)
    $signature=[Convert]::FromBase64String($file.signature)
    Check ($rsa.VerifyData($payload,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'worker proof is signed by its pinned identity'
    $receipt=[Text.Encoding]::UTF8.GetString($payload)|ConvertFrom-Json
    Check ($receipt.id -ceq $id -and $receipt.computer -ceq $hostName -and $receipt.actual -ceq 'value=2' -and $receipt.readAt) 'signed result binds request, host, time and observed value'
    $payload[0]=$payload[0] -bxor 1
    Check (!$rsa.VerifyData($payload,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'changed evidence invalidates the signature'
    $results = [IO.Directory]::CreateDirectory($temp+'.results').FullName
    $checkIn = Join-Path $results 'check-in.json'
    try {
        $TaskName = 'Fixture worker'
        $TaskPath = '\'
        function Get-ScheduledTaskInfo { ( [pscustomobject]@{ NextRunTime=(Get-Date).AddSeconds(55) } ) }
        Publish-CheckIn
        $entry = [IO.File]::ReadAllText($checkIn) | ConvertFrom-Json
        Check ($entry.computer -eq $hostName -and [DateTimeOffset]::Parse($entry.nextCheckAt) -gt [DateTimeOffset]::UtcNow) 'worker publishes a future Task Scheduler check-in'
        $TaskName = ''
        $entry.seenAt = [DateTimeOffset]::UtcNow.AddMinutes(-60).ToString('O')
        [IO.File]::WriteAllText($checkIn,($entry|ConvertTo-Json))
        Publish-CheckIn
        $entry = [IO.File]::ReadAllText($checkIn) | ConvertFrom-Json
        Check (!$entry.nextCheckAt) 'a long offline gap does not produce a fictitious refresh countdown'
    } finally {
        if ([IO.File]::Exists($checkIn)) { [IO.File]::Delete($checkIn) }
        [IO.Directory]::Delete($results)
    }
} finally {
    if ($script:receiptKey) { $script:receiptKey.Dispose() }
    $certificate.Dispose()
    $rsa.Dispose()
    if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
}
