using System.Net;
using GpoRemediator.Domain;
using Microsoft.AspNetCore.Antiforgery;

namespace GpoRemediator.Infrastructure;

public static class RequestSecurity
{
    public static void RequireLoopback(HttpContext context)
    {
        if(!IPAddress.IsLoopback(context.Connection.RemoteIpAddress??IPAddress.None)||
            !new[]{"localhost","127.0.0.1","::1"}.Contains(context.Request.Host.Host,StringComparer.OrdinalIgnoreCase))
            throw new PolicyException("LOOPBACK_ONLY","Open the application on localhost on the management host.");
    }
    public static async Task ValidateMutationAsync(HttpContext context)
    {
        if(!context.Request.Path.StartsWithSegments("/api")||HttpMethods.IsGet(context.Request.Method)||HttpMethods.IsHead(context.Request.Method))return;
        var expected=$"{context.Request.Scheme}://{context.Request.Host}";
        if(!string.Equals(context.Request.Headers.Origin.ToString(),expected,StringComparison.OrdinalIgnoreCase))
            throw new PolicyException("ORIGIN_DENIED","Mutation requests must come from this application's exact origin.");
        if(!context.Request.HasJsonContentType())throw new PolicyException("CONTENT_TYPE_DENIED","API mutations require application/json.");
        await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context);
    }
}
