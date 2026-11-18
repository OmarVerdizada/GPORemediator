function Assert-RemediatorLoopbackUrl {
    param([Parameter(Mandatory=$true)][string]$BaseUrl)
    $uri=$null
    if(![Uri]::TryCreate($BaseUrl,[UriKind]::Absolute,[ref]$uri) -or !$uri.IsLoopback -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo){throw 'LOOPBACK_URL_INVALID: Lifecycle requests require a local HTTP(S) endpoint.'}
    return $uri.GetLeftPart([UriPartial]::Authority).TrimEnd('/')
}
function Get-RemediatorLoopbackService {
    param([Parameter(Mandatory=$true)][string]$BaseUrl)
    $base=Assert-RemediatorLoopbackUrl $BaseUrl
    try {
        $health=Invoke-RestMethod -UseDefaultCredentials -Uri ($base+'/api/v1/health/live') -TimeoutSec 1
        if([string]$health.status -cne 'live' -or [string]$health.apiVersion -cne '1.0' -or [string]$health.productVersion -notmatch '^3\.') {return $null}
        # Readiness is intentionally bootstrap-safe. /api/service contains richer
        # lifecycle data but requires the browser's operator-confirmation proof;
        # a native launcher must not mistake that missing cookie for an offline service.
        $ready=Invoke-RestMethod -UseDefaultCredentials -Uri ($base+'/api/v1/health/ready') -TimeoutSec 2
        if([string]$ready.status -cne 'ready'){return $null}
        return [pscustomobject]@{mode=[string]$ready.mode;processId=0;ready=$true;url=$base;openPath='/#/dashboard';managed=$true;writesEnabled=$null;activeJobs=0;stopping=$false;startupIssue=''}
    } catch {return $null}
}
function Invoke-RemediatorLoopbackAction {
    param([ValidateSet('stop','restart')][string]$Action,[Parameter(Mandatory=$true)][string]$BaseUrl)
    $base=Assert-RemediatorLoopbackUrl $BaseUrl
    $session=Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($base+'/api/session') -SessionVariable lifecycle -TimeoutSec 8
    $token=($session.Content|ConvertFrom-Json).csrfToken
    if([string]::IsNullOrWhiteSpace([string]$token)){throw 'LIFECYCLE_SESSION_INVALID: The backend did not issue a CSRF token.'}
    $headers=@{'X-CSRF-Token'=[string]$token;'Origin'=$base}
    $result=Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri ($base+'/api/service/'+$Action) -WebSession $lifecycle -Headers $headers -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 8
    if($result.StatusCode -ne 202){throw ('LIFECYCLE_REQUEST_REJECTED: HTTP '+$result.StatusCode)}
    return $result.Content|ConvertFrom-Json
}
