using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

public static class OperatorSecurity
{
    public static void ConfigureLoginRateLimit(Microsoft.AspNetCore.RateLimiting.RateLimiterOptions options)
    {
        options.RejectionStatusCode=StatusCodes.Status429TooManyRequests;
        options.AddPolicy("operator-confirmation",context=>System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(WindowsAccount.Normalize(context.User.Identity?.Name).ToUpperInvariant(),_=>new System.Threading.RateLimiting.FixedWindowRateLimiterOptions{PermitLimit=5,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true}));
        options.AddPolicy("delegated-login",context=>System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(WindowsAccount.Normalize(context.User.Identity?.Name).ToUpperInvariant(),_=>new System.Threading.RateLimiting.FixedWindowRateLimiterOptions{PermitLimit=5,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true}));
    }
    // The Windows identity binds browser sessions and audit records, not application roles.
    // AD/GPO permissions are enforced by the DC using the explicitly supplied credential.
    public static void RequireIdentity(HttpContext context)
    {
        if(context.User.Identity?.IsAuthenticated!=true)
            throw new PolicyException("AUTHENTICATION_REQUIRED","Windows authentication is required.");
    }

    public static void ValidateHosts(string[] hosts,string domain)
    {
        if(hosts.Length>100||hosts.Any(host=>string.IsNullOrWhiteSpace(host)||host.Length>253||
            !System.Text.RegularExpressions.Regex.IsMatch(host,@"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",System.Text.RegularExpressions.RegexOptions.CultureInvariant)||
            !host.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("INVALID_HOST_ALLOWLIST","Authorize at most 100 exact host DNS names in the configured domain; wildcards are not permitted.");
    }
}
