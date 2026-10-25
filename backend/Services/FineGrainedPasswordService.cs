using System.Text.Json;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
namespace GpoRemediator.Services;

public sealed class FineGrainedPasswordService(GpoWorkflowService gpo,Store store,IConfiguration config,OperationGate gate)
{
    private string Context=>PolicyValues.Hash(new{domain=config["Windows:Domain"],dc=config["Windows:DomainController"],backup=config["Windows:BackupPath"]});
    public async Task<FineGrainedPasswordPlan> Preview(string token,string actor,FineGrainedPasswordRequest request,CancellationToken ct){
        FineGrainedPasswordRules.Validate(request);var inventory=gpo.Inventory(token,actor);
        if(!inventory.Scopes.Any(x=>x.Kind=="OU"&&x.Dn.Equals(request.ScopeDn,StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("FGPP_OU_REQUIRED","Select a user OU from live inventory.");
        var previous=store.List<FineGrainedPasswordPlan>("fgpp_plans").Where(x=>x.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase)&&x.Domain.Equals(inventory.Domain,StringComparison.OrdinalIgnoreCase)&&x.Request.Name.Equals(request.Name,StringComparison.OrdinalIgnoreCase)&&x.Request.ScopeDn.Equals(request.ScopeDn,StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x=>x.CreatedAt).FirstOrDefault(x=>store.Get<JsonElement?>("fgpp_runs",x.Id) is JsonElement result&&result.TryGetProperty("state",out var value)&&value.GetString() is "VERIFIED" or "POLICY_ASSIGNED_REVIEW_REQUIRED");
        var previousUsers=previous is not null&&previous.Preview.TryGetProperty("users",out var users)?users:JsonSerializer.SerializeToElement(Array.Empty<object>());
        var preview=await gpo.RunDirectoryOperation<JsonElement>("fgppPreview",token,actor,new{request,previousUsers},ct);
        var plan=new FineGrainedPasswordPlan(Guid.NewGuid().ToString("N"),actor,inventory.ExecutionUser,inventory.Domain,inventory.DomainController,request,preview,PolicyValues.Now(),Context);
        store.Put("fgpp_plans",plan.Id,plan);store.Audit("FGPP_PREVIEW",actor,jobId:plan.Id,details:plan);return plan;
    }
    public object History(string actor)=>store.List<FineGrainedPasswordPlan>("fgpp_plans").Where(x=>x.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase))
        .Select(x=>new{plan=x,result=store.Get<JsonElement?>("fgpp_runs",x.Id)}).ToArray();
    public Task<FineGrainedPasswordPlan> Reconcile(string id,string token,string actor,CancellationToken ct){
        var original=store.Require<FineGrainedPasswordPlan>("fgpp_plans",id);
        if(!original.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase))throw new PolicyException("NOT_FOUND","Password policy operation not found.");
        var inventory=gpo.Inventory(token,actor);
        if(!inventory.Domain.Equals(original.Domain,StringComparison.OrdinalIgnoreCase)||!inventory.ExecutionUser.Equals(original.ExecutionUser,StringComparison.OrdinalIgnoreCase))
            throw new PolicyException("PLAN_CONTEXT_CHANGED","Reconnect to the recorded domain and execution account to compare membership.");
        return Preview(token,actor,original.Request,ct);
    }
    public async Task<JsonElement> Execute(string id,string action,string token,string actor,string confirmation,CancellationToken ct){
        var plan=store.Require<FineGrainedPasswordPlan>("fgpp_plans",id);var inventory=gpo.Inventory(token,actor);
        if(!plan.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase)||!inventory.ExecutionUser.Equals(plan.ExecutionUser,StringComparison.OrdinalIgnoreCase)||!inventory.Domain.Equals(plan.Domain,StringComparison.OrdinalIgnoreCase)||!inventory.DomainController.Equals(plan.DomainController,StringComparison.OrdinalIgnoreCase)||plan.ConfigHash!=Context)
            throw new PolicyException("PLAN_CONTEXT_CHANGED","Reconnect as the same account with unchanged domain/DC/backup settings.");
        if(action is not ("apply" or "verify" or "rollback"))throw new PolicyException("OPERATION_DENIED","Unknown password policy operation.");
        if(action!="verify"){
            if(!config.GetValue<bool>("Windows:EnableWrites"))throw new PolicyException("WRITES_DISABLED","Enable the production change gate before password policy writes.");
            var ous=config.GetSection("Windows:AuthorizedOus").Get<string[]>()??[];
            if(!ous.Any(x=>x.Equals(plan.Request.ScopeDn,StringComparison.OrdinalIgnoreCase)||plan.Request.ScopeDn.EndsWith(","+x,StringComparison.OrdinalIgnoreCase)))
                throw new PolicyException("FGPP_WRITE_NOT_AUTHORIZED","Authorize the selected user OU in Settings before this FGPP write.");
            if(confirmation!=(action=="apply"?"APPLY FGPP":"ROLLBACK FGPP"))throw new PolicyException("CONFIRMATION_REQUIRED","Type "+(action=="apply"?"APPLY FGPP":"ROLLBACK FGPP"));
        }
        if(action=="apply"&&DateTimeOffset.UtcNow-DateTimeOffset.Parse(plan.CreatedAt)>TimeSpan.FromMinutes(10))throw new PolicyException("GPO_PLAN_EXPIRED","Generate a fresh password policy preview.");
        var key="fgpp:"+plan.Domain+":"+plan.Request.Name.ToUpperInvariant();gate.BeginOperation(key,()=>{});
        try{
            var result=await gpo.RunDirectoryOperation<JsonElement>("fgpp"+char.ToUpperInvariant(action[0])+action[1..],token,actor,new{plan},action=="verify"?ct:CancellationToken.None);
            store.Put("fgpp_runs",id,result);store.Audit("FGPP_"+action.ToUpperInvariant(),actor,jobId:id,details:result);return result;
        }catch{
            if(action!="verify"){store.Put("fgpp_runs",id,new{state="REVIEW_REQUIRED",message="Transport interrupted. Verify this operation and inspect its retained DC manifest before another write."});store.Audit("FGPP_INTERRUPTED",actor,jobId:id);}
            throw;
        }finally{gate.EndOperation(key);}
    }
}
