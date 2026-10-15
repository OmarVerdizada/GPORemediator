# GPORemediator generated, domain/GPO-bound launcher. DO NOT EDIT.
# This file contains no saved credentials and is verified by the compiled backend.
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$expectedDomain='__DOMAIN__'
$expectedGpo='__GPO__'
$trustedBootstrap='__BOOTSTRAP__'
$requestText=$null
try {
    $requestText=[Console]::In.ReadToEnd()
    $req=$requestText | ConvertFrom-Json -ErrorAction Stop
    if($null -eq $req -or $null -eq $req.configuration -or $null -eq $req.payload -or $null -eq $req.payload.data){throw 'GPO_ISOLATION_DENIED|Missing scoped request.'}
    if([string]$req.configuration.domain -ine $expectedDomain){throw 'GPO_ISOLATION_DENIED|Domain does not match this GPO script.'}
    $operation=[string]$req.operation
    if($operation -notin @('gpoPreview','gpoApply','gpoVerify','gpoRollback','gpoRollbackInspect','gpoRefresh')){throw 'GPO_ISOLATION_DENIED|Only a selected-GPO operation can use this script.'}
    $selected=if($operation -eq 'gpoPreview'){$req.payload.data.selection}else{$req.payload.data.plan.selection}
    if($null -eq $selected){throw 'GPO_ISOLATION_DENIED|Missing GPO selection.'}
    $guid=[guid]::Empty
    if(![guid]::TryParse([string]$selected.gpoId,[ref]$guid) -or $guid.ToString('D') -ine $expectedGpo){throw 'GPO_ISOLATION_DENIED|Selected GPO does not match this script.'}
    # In-process call: secrets are NEVER passed through a process argument list.
    # The trusted worker maintains its existing validation, authentication, and audit paths.
    & $trustedBootstrap -RequestJson $requestText
} catch {
    $message=[string]$_.Exception.Message
    $code='GPO_ISOLATION_DENIED'
    if($message -notmatch '^GPO_ISOLATION_DENIED\|'){$message='Domain/GPO isolation guard could not validate the request.'}
    else{$message=$message.Substring('GPO_ISOLATION_DENIED|'.Length)}
    [Console]::Out.Write((@{ok=$false;code=$code;message=$message} | ConvertTo-Json -Compress))
    exit 1
} finally {
    $requestText=$null
}
