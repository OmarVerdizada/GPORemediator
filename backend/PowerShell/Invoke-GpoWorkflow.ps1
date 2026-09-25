# Credentials arrive through private stdin from the local-only backend, never command arguments or files.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$session=$null;$secure=$null;$credential=$null;$request=$null
try {
    $request=[Console]::In.ReadToEnd() | ConvertFrom-Json
    if($request.operation -notin @('gpoInventory','gpoReadiness','gpoPreview','gpoApply','gpoRollback','gpoVerify')){throw 'OPERATION_DENIED|Unknown GPO operation.'}
    $cfg=$request.configuration
    if([string]$cfg.domainController -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$' -or -not ([string]$cfg.domainController).EndsWith('.'+[string]$cfg.domain,[StringComparison]::OrdinalIgnoreCase)){throw 'DC_REQUIRED|Save the exact domain and writable DC first.'}
    $remoteTimeout=if([string]$request.operation -in @('gpoApply','gpoRollback')){900000}elseif([string]$request.operation -in @('gpoPreview','gpoVerify')){540000}else{300000}
    $options=@{ComputerName=[string]$cfg.domainController;Authentication='Kerberos';SessionOption=(New-PSSessionOption -OpenTimeout 15000 -OperationTimeout $remoteTimeout)}
    if($request.payload.credential.userName){
        $secure=ConvertTo-SecureString -String $request.payload.credential.password -AsPlainText -Force
        $credential=[Management.Automation.PSCredential]::new([string]$request.payload.credential.userName,$secure)
        $options.Credential=$credential
    }
    $request.payload.credential.password=$null
    $session=New-PSSession @options
    # Both script texts come exclusively from the installed, bundled product; browser data is passed as arguments.
    $worker=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'GpoWorkflow.Worker.ps1'))
    $module=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'SecurityTemplate.psm1'))
    $data=Invoke-Command -Session $session -ScriptBlock ([scriptblock]::Create($worker)) -ArgumentList ([string]$request.operation),$cfg,$request.payload.data,$module
    [Console]::Out.Write((@{ok=$true;data=$data} | ConvertTo-Json -Depth 50 -Compress))
} catch {
    $message=[string]$_.Exception.Message
    if($message -match '^([A-Z][A-Z0-9_]+)\|(.+)$'){$code=$Matches[1];$safe=$Matches[2]}
    else{$code='GPO_CONNECTION_OR_OPERATION_FAILED';$safe='Unable to complete the GPO operation. Check the execution account, Kerberos/WinRM to the selected DC, the ActiveDirectory/GroupPolicy modules on that DC, GPO edit/link permissions and DC backup access. No password or raw remote error is logged.'}
    [Console]::Out.Write((@{ok=$false;code=$code;message=$safe} | ConvertTo-Json -Compress))
    exit 1
} finally {
    if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}
    if($secure){$secure.Dispose()}
    $credential=$null;$request=$null
}
