using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// Attached to endpoints, so route casing/trailing slashes cannot change privileges.
public sealed record OperatorAccess(params string[] Roles);

public static class OperatorSecurity
{
    public static void ConfigureLoginRateLimit(Microsoft.AspNetCore.RateLimiting.RateLimiterOptions options)
    {
        options.RejectionStatusCode=StatusCodes.Status429TooManyRequests;
        options.AddPolicy("delegated-login",context=>System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(WindowsAccount.Normalize(context.User.Identity?.Name).ToUpperInvariant(),_=>new System.Threading.RateLimiting.FixedWindowRateLimiterOptions{PermitLimit=5,Window=TimeSpan.FromMinutes(1),QueueLimit=0,AutoReplenishment=true}));
    }
    public static string Role(IConfiguration configuration, string actor)
    {
        actor=WindowsAccount.Normalize(actor);
        if(string.IsNullOrWhiteSpace(actor))return "Denied";
        var roles=new[]{("Administrators","Administrator"),("Remediators","Remediator"),("Auditors","Auditor"),("Viewers","Viewer")};
        var matches=roles.Where(role=>(configuration.GetSection("Windows:Roles:"+role.Item1).Get<string[]>()??[])
            .Select(WindowsAccount.Normalize).Contains(actor,StringComparer.OrdinalIgnoreCase)).ToArray();
        // Ambiguous and legacy-only membership never silently elevates to Administrator.
        return matches.Length==1?matches[0].Item2:"Denied";
    }

    public static void Authorize(HttpContext context,IConfiguration configuration,bool real,string setupOwner)
    {
        if(context.User.Identity?.IsAuthenticated!=true)throw new PolicyException("AUTHENTICATION_REQUIRED","Windows authentication is required.");
        var actor=WindowsAccount.Normalize(context.User.Identity.Name);
        if(!real){
            if(!actor.Equals(WindowsAccount.Normalize(setupOwner),StringComparison.OrdinalIgnoreCase))
                throw new PolicyException("SETUP_OPERATOR_DENIED","Setup is restricted to the Windows identity that launched the service.");
            return;
        }
        var role=Role(configuration,actor);
        if(role=="Denied")throw new PolicyException("OPERATOR_DENIED","Your Windows identity has no unambiguous configured role.");
        var access=context.GetEndpoint()?.Metadata.GetMetadata<OperatorAccess>();
        if(access is not null){
            if(!access.Roles.Contains(role,StringComparer.Ordinal))throw new PolicyException("ROLE_DENIED","This action is not permitted for the authenticated operator role.");
        }else if(!HttpMethods.IsGet(context.Request.Method)&&!HttpMethods.IsHead(context.Request.Method)){
            throw new PolicyException("ROLE_DENIED","No mutation permission is declared for this endpoint.");
        }
    }

    public static void ValidateHosts(string[] hosts,string domain)
    {
        if(hosts.Length>100||hosts.Any(host=>string.IsNullOrWhiteSpace(host)||host.Length>253||
            !System.Text.RegularExpressions.Regex.IsMatch(host,@"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",System.Text.RegularExpressions.RegexOptions.CultureInvariant)||
            !host.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("INVALID_HOST_ALLOWLIST","Authorize at most 100 exact host DNS names in the configured domain; wildcards are not permitted.");
    }
}
