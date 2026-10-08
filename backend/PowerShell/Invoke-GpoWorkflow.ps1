# Credentials arrive through private stdin from the local-only backend, never command arguments or files.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$stage='configuration'
$clock=[Diagnostics.Stopwatch]::StartNew()
$session=$null;$secure=$null;$credential=$null;$request=$null
try {
    $request=[Console]::In.ReadToEnd() | ConvertFrom-Json
    if(!$request -or !$request.configuration -or !$request.payload -or !$request.payload.credential){throw 'INVALID_REQUEST|The operation requires configuration and an explicit delegated credential.'}
    if($request.operation -notin @('gpoInventory','gpoReadiness','gpoPreview','gpoApply','gpoRollback','gpoVerify','gpoRefresh')){throw 'OPERATION_DENIED|Unknown GPO operation.'}
    $cfg=$request.configuration
    $hostPattern='^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    if([string]::IsNullOrWhiteSpace([string]$cfg.domain) -or [string]$cfg.domain -notmatch $hostPattern -or [string]$cfg.domainController -notmatch $hostPattern -or -not ([string]$cfg.domainController).EndsWith('.'+[string]$cfg.domain,[StringComparison]::OrdinalIgnoreCase)){throw 'DC_REQUIRED|Save the exact domain and writable DC first.'}
    # Remote deadlines finish before the backend watchdog, leaving time for cleanup.
    $remoteTimeout=if([string]$request.operation -in @('gpoApply','gpoRollback')){900000}elseif([string]$request.operation -eq 'gpoRefresh'){660000}elseif([string]$request.operation -in @('gpoPreview','gpoVerify')){540000}else{65000}
    $options=@{ComputerName=[string]$cfg.domainController;Authentication='Kerberos';SessionOption=(New-PSSessionOption -OpenTimeout 15000 -OperationTimeout $remoteTimeout)}
    if([string]::IsNullOrWhiteSpace([string]$request.payload.credential.userName) -or [string]::IsNullOrEmpty([string]$request.payload.credential.password)){throw 'DELEGATED_CREDENTIAL_REQUIRED|Supply explicit delegated credentials for every GPO operation.'}
    if(([string]$request.payload.credential.userName).Length -gt 256 -or ([string]$request.payload.credential.password).Length -gt 1024 -or [string]$request.payload.credential.userName -match '[\r\n\x00]'){throw 'CREDENTIAL_FORMAT|Invalid delegated credential format.'}
    if($request.payload.credential.userName){
        $secure=ConvertTo-SecureString -String $request.payload.credential.password -AsPlainText -Force
        $credential=[Management.Automation.PSCredential]::new([string]$request.payload.credential.userName,$secure)
        $options.Credential=$credential
    }
    $request.payload.credential.password=$null
    $stage='connection'
    $session=New-PSSession @options
    $stage=[string]$request.operation
    # Both script texts come exclusively from the installed, bundled product; browser data is passed as arguments.
    $worker=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'GpoWorkflow.Worker.ps1'))
    $module=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'SecurityTemplate.psm1'))
    $data=Invoke-Command -Session $session -ScriptBlock ([scriptblock]::Create($worker)) -ArgumentList ([string]$request.operation),$cfg,$request.payload.data,$module
    [Console]::Out.Write((@{ok=$true;data=$data;durationMs=$clock.ElapsedMilliseconds} | ConvertTo-Json -Depth 50 -Compress))
} catch {
    $message=[string]$_.Exception.Message
    if($message -match '^([A-Z][A-Z0-9_]+)\|(.+)$'){$code=$Matches[1];$safe=$Matches[2]}
    else{
        # Emit only bounded, product-owned guidance, never raw remote errors/credentials.
        switch($stage){
            'connection' {
                if($_.FullyQualifiedErrorId -match 'AccessDenied|LogonFailure|AuthenticationFailed'){$code='GPO_AUTH_FAILED';$safe='Windows rejected the delegated account. Check DOMAIN\user, password and remoting permissions.'}
                elseif($_.FullyQualifiedErrorId -match 'OperationTimeout|PSSessionOpenFailed' -and $message -match 'timed out|timeout'){$code='GPO_CONNECTION_TIMEOUT';$safe='The connection deadline expired. Check DC DNS, TCP/5985, WinRM and Kerberos reachability.'}
                else{$code='GPO_REMOTING_FAILED';$safe='The domain controller could not be reached through Kerberos/WinRM. Check its DNS name, WinRM service and the account remoting permission.'}
            }
            'gpoReadiness' {$code='GPO_READINESS_FAILED';$safe='Connected to the domain, but readiness checks could not finish. Update the tool on the management host, then retry Check connection. Verify access to SYSVOL and the backup folder on the DC.'}
            'gpoInventory' {$code='GPO_DISCOVERY_FAILED';$safe='Connected to the DC, but GPO and OU discovery failed. Check ActiveDirectory/GroupPolicy modules and read permissions on the selected domain.'}
            'gpoPreview' {$code='GPO_PREVIEW_FAILED';$safe='The selected policy could not be inspected. Refresh the GPO list and check read access to the GPO, SYSVOL and target OU.'}
            default {$code='GPO_OPERATION_FAILED';$safe='The operation could not finish. Open Operations and verify its recorded state before trying a change again.'}
        }
    }
    [Console]::Out.Write((@{ok=$false;code=$code;message=$safe;stage=$stage;durationMs=$clock.ElapsedMilliseconds} | ConvertTo-Json -Compress))
    exit 1
} finally {
    if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}
    if($secure){$secure.Dispose()}
    $credential=$null;$request=$null
}
