using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

public static class GpoEndpoints
{
    // Shared by production and HTTP regression tests: exercise the actual body-to-worker mapping.
    public static RouteHandlerBuilder MapRefresh(IEndpointRouteBuilder routes,Func<string,GpoConsent,HttpContext,Task<object>> execute)
        =>routes.MapPost("/api/gpo/{id}/refresh",async(string id,GpoRefreshRequest request,HttpContext context)=>{
            if(request.Refresh is not ("Pdc" or "Scope"))throw new PolicyException("INVALID_REQUEST","Choose Pdc or Scope for policy refresh.");
            return await execute(id,new("",Refresh:request.Refresh),context);
        });
}
