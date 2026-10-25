param(
    [Parameter(Mandatory=$true)][string]$GpoId,
    [Parameter(Mandatory=$true)][string]$OuDn,
    [Parameter(Mandatory=$true)][string]$ControlId,
    [string]$BaseUrl='http://127.0.0.1:5080',
    [Nullable[int]]$Value=$null,
    [ValidateRange(1,5)][int]$MaxComputers=5,
    [Parameter(Mandatory=$true)][string]$Confirmation,
    [string]$OutputDirectory=(Join-Path $env:LOCALAPPDATA 'GpoRemediator\PilotReports')
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Secure-Files.ps1')
function Assert-PilotPlan($Plan,$Mapping,[string]$ExpectedGpo,[string]$ExpectedOu,[int]$Limit){
    if([string]$Plan.selection.gpoId -ine $ExpectedGpo -or [string]$Plan.selection.scopeDn -ine $ExpectedOu -or $ExpectedOu -notmatch '^OU='){throw 'Pilot selection must match the exact reviewed GPO and OU.'}
    if($Plan.preview.gpo.protected -or $Mapping.domainPolicySensitive -or $Mapping.scope -ne 'Computer' -or $Mapping.requiresRestart -or $Mapping.automation -ne 'Automated'){throw 'Live pilot accepts only an unprotected dedicated GPO and an automated computer control without domain-wide or restart requirements.'}
    $objects=$Plan.preview.impact.affectedObjects;$hosts=@($Plan.preview.verificationComputers)
    if($objects.truncated -or $objects.computers -lt 1 -or $objects.computers -gt $Limit -or $hosts.Count -ne $objects.computers){throw 'Pilot requires a complete, DNS-addressable OU containing 1–5 enabled computers.'}
    if(@($Plan.preview.impact.existingLinkScopes|Where-Object{[string]$_ -ine $ExpectedOu}).Count){throw 'Dedicated pilot GPO is linked outside the pilot OU. No write will be performed.'}
    if(!$Plan.writeAuthorized -or !$Plan.preview.preflight.ready){throw 'Approve this exact GPO/OU and pass readiness in the application before running the live pilot.'}
    if($Mapping.requiresInput -or $Mapping.requiresRestart -or $Mapping.domainPolicySensitive -or $Mapping.scope -ne 'Computer' -or $Mapping.automation -ne 'Automated'){throw 'Pilot requires an automated computer control without restart or custom-input requirements.'}
    if($Plan.preview.noChange){throw 'This preview needs no change. Choose a different explicitly reviewed control/value; a no-op does not certify the write/rollback chain.'}
}
function Assert-PilotUrl([string]$Url){
    $uri=$null
    if(![Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or !$uri.IsLoopback -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment){throw 'BaseUrl must be a local application origin; credentials are never sent to an arbitrary server.'}
    return $uri.GetLeftPart([UriPartial]::Authority)
}
$origin=Assert-PilotUrl $BaseUrl
if($Confirmation -cne 'RUN PILOT'){throw 'Type -Confirmation "RUN PILOT" only for a dedicated authorized test OU/GPO.'}
$pilotGuid=[guid]::Empty
if(![guid]::TryParse($GpoId,[ref]$pilotGuid) -or $OuDn -notmatch '^OU=' -or $OuDn -match '[\r\n\x00]'){throw 'Supply a valid GPO GUID and an explicit pilot OU DN.'}
$GpoId=$pilotGuid.ToString('D')
$session=New-Object Microsoft.PowerShell.Commands.WebRequestSession
$headers=@{Origin=$origin};$csrf='';$credential=$null;$login=$null
function Pilot-Api([string]$Path,$Body=$null){
    $options=@{Uri=($origin+'/api'+$Path);UseBasicParsing=$true;UseDefaultCredentials=$true;WebSession=$session;TimeoutSec=1100;ErrorAction='Stop'}
    if($null -ne $Body){$options.Method='Post';$options.ContentType='application/json';$options.Body=($Body|ConvertTo-Json -Depth 30);$options.Headers=@{Origin=$origin;'X-CSRF-Token'=$script:csrf}}
    try{return (Invoke-WebRequest @options).Content|ConvertFrom-Json}
    catch{
        $safe='The local API request failed. Inspect the recorded operation and service status; writes are never retried automatically.'
        try{$details=$_.ErrorDetails.Message|ConvertFrom-Json;if($details.code -and $details.message){$safe=[string]$details.code+': '+[string]$details.message}}catch{}
        throw $safe
    }finally{$options.Body=$null}
}
$report=@{kind='LIVE_PILOT';state='STARTING';startedAt=[DateTimeOffset]::UtcNow.ToString('O');gpoId=$GpoId;ouDn=$OuDn;control=$ControlId;steps=@();baseline=@();final=@();notes=@('Configuration lifecycle verification is not certification of every runtime prerequisite. No automatic restart, delegation grant, or write-gate activation is performed.')}
$plan=$null;$applied=$false;$changed=$false
try{
    $status=Pilot-Api '/session'
    if($status.mode -ne 'WINDOWS'){throw 'Start Windows / AD mode in the application first.'}
    $script:csrf=[string]$status.csrfToken
    $credential=Get-Credential -Message 'Use the delegated pilot execution account. Credentials are transport-only and are not saved.'
    if(!$credential){throw 'Pilot sign-in cancelled.'}
    $login=@{userName=$credential.UserName;password=$credential.GetNetworkCredential().Password}
    $null=Pilot-Api '/operator/sign-in' $login;$login.password=$null;$login=$null;$credential=$null
    $service=Pilot-Api '/service';if(!$service.writesEnabled){throw 'Enable the exact pilot GPO/OU change gate through the application before running this script.'}
    $mapping=@(Pilot-Api '/gpo/settings'|Where-Object id -eq $ControlId|Select-Object -First 1)
    if(!$mapping.Count){throw 'Unknown control ID.'};$mapping=$mapping[0]
    if($mapping.requiresInput){throw 'The unattended pilot runner does not infer organization-specific input. Choose another reviewed computer control.'}
    $selection=@{gpoId=$GpoId;scopeDn=$OuDn;setting=$ControlId;value=$(if($null -ne $Value){[int]$Value}elseif($null -ne $mapping.suggested){$mapping.suggested}else{0});accountScope='LocalComputers';refresh='None';firstLink=$true}
    $plan=Pilot-Api '/gpo/preview' $selection
    Assert-PilotPlan $plan $mapping $GpoId $OuDn $MaxComputers
    $report.plan=$plan;$report.steps+=@{step='PREVIEW';state='PASS';at=[DateTimeOffset]::UtcNow.ToString('O')}
    foreach($hostName in @($plan.preview.verificationComputers)){
        $probe=Pilot-Api ('/gpo/'+$plan.id+'/explain') @{hostname=$hostName};$report.baseline+=$probe
        if(@($probe.effectiveChecks).Count -ne 1 -or [string]$probe.effectiveChecks[0].state -notin @('VERIFIED','MISMATCH')){throw 'Baseline effective values are unavailable. No pilot write was performed.'}
    }
    $result=Pilot-Api ('/gpo/'+$plan.id+'/apply') @{confirmation='APPLY';acknowledgeImpact=$true;acknowledgeProtected=$false;changeReference=('LIVE-PILOT-'+$plan.id);approvedBy=$env:USERNAME}
    $applied=$true;$changed=[bool]$result.result.backupId
    $report.steps+=@{step='APPLY';result=$result.result}
    if($result.result.state -ne 'PUBLISHED'){throw 'Apply did not publish cleanly. Inspect the recorded DC manifest before another write.'}
    $refresh=Pilot-Api ('/gpo/'+$plan.id+'/refresh') @{refresh='Scope'}
    $report.steps+=@{step='REFRESH';result=$refresh.result}
    if(@($refresh.result.refreshResults).Count -ne @($plan.preview.verificationComputers).Count -or @($refresh.result.refreshResults|Where-Object state -ne 'COMPLETED').Count){throw 'Not every pilot endpoint completed computer policy processing.'}
    $verified=Pilot-Api ('/gpo/'+$plan.id+'/verify') @{}
    $report.steps+=@{step='VERIFY';result=$verified.result}
    if($verified.result.effectiveStatus -ne 'VERIFIED_ON_ALL_TARGETS' -or !$verified.result.verification.replicationConverged){throw 'Pilot endpoint/replication evidence is incomplete.'}
    $report.state='APPLIED_AND_VERIFIED'
}catch{$report.state='REVIEW_REQUIRED';$report.error=[string]$_.Exception.Message}
finally{
    if($changed -and $plan){
        try{
            $rollback=Pilot-Api ('/gpo/'+$plan.id+'/rollback') @{confirmation='ROLLBACK'}
            $report.steps+=@{step='ROLLBACK';result=$rollback.result}
            if($rollback.result.state -ne 'ROLLED_BACK'){throw 'Policy snapshot rollback requires review.'}
            $refresh=Pilot-Api ('/gpo/'+$plan.id+'/refresh') @{refresh='Scope'};$report.steps+=@{step='ROLLBACK_REFRESH';result=$refresh.result}
            foreach($hostName in @($plan.preview.verificationComputers)){$report.final+=Pilot-Api ('/gpo/'+$plan.id+'/explain') @{hostname=$hostName}}
            $same=$true
            foreach($before in @($report.baseline)){
                $after=@($report.final|Where-Object hostname -eq $before.hostname|Select-Object -First 1)
                if(!$after.Count -or @($after[0].effectiveChecks).Count -ne 1 -or [string]$after[0].effectiveChecks[0].state -notin @('VERIFIED','MISMATCH') -or [string]$after[0].effectiveChecks[0].actualValue -cne [string]$before.effectiveChecks[0].actualValue){$same=$false}
            }
            if($report.state -eq 'APPLIED_AND_VERIFIED' -and $same -and @($refresh.result.refreshResults).Count -eq @($plan.preview.verificationComputers).Count -and @($refresh.result.refreshResults|Where-Object state -ne 'COMPLETED').Count -eq 0){$report.state='CONFIGURATION_LIFECYCLE_VERIFIED'}else{$report.state='RESTORED_REVIEW_REQUIRED'}
        }catch{$report.recoveryError=[string]$_.Exception.Message;$report.state='RECOVERY_REVIEW_REQUIRED'}
    }
    $login=$null;$credential=$null
    $folder=Join-Path $OutputDirectory ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $folder -Force
    Initialize-ProtectedDirectory -Path $folder
    $report.finishedAt=[DateTimeOffset]::UtcNow.ToString('O')
    $file=Join-Path $folder 'pilot-report.json';[IO.File]::WriteAllText($file,($report|ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
    Write-Output ('Pilot state: '+$report.state+'. Private report: '+$file)
}
if($report.state -ne 'CONFIGURATION_LIFECYCLE_VERIFIED'){exit 1}
