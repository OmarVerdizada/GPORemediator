using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using Microsoft.AspNetCore.DataProtection;

namespace GpoRemediator.Services;

public sealed class GpoWorkflowService(IConfiguration config,Store store,OperationGate gate,IDataProtectionProvider protection,ILogger<GpoWorkflowService> logger) : IDisposable
{
    private static readonly TimeSpan ConnectionIdleTimeout=TimeSpan.FromMinutes(30);
    private sealed record Connection(string Actor,string UserName,byte[] Password,GpoInventory Inventory,DateTimeOffset Expires);
    private readonly ConcurrentDictionary<string,Connection> connections=new();
    private readonly IDataProtector protector=protection.CreateProtector("GpoWorkflow.EphemeralLogin.v1");
    private readonly WindowsPowerShellExecutor executor=new(logger);
    private bool Real=>!config.GetValue<bool>("LocalSetup")&&string.Equals(config["Mode"],"Windows",StringComparison.OrdinalIgnoreCase);
    private string Mode=>"WINDOWS";
    private void RequireReal(){if(!Real)throw new PolicyException("WINDOWS_MODE_REQUIRED","GPO discovery and remediation require Windows / AD mode. Setup mode cannot simulate domain operations.");}
    private string Domain=>config["Windows:Domain"]??"";
    private string Dc=>config["Windows:DomainController"]??"";
    private object Configuration=>new{domain=Domain,domainController=Dc,backupPath=config["Windows:BackupPath"]};
    private Timer? cleanup;
    private void Expire()
    {
        foreach(var pair in connections.Where(x=>x.Value.Expires<=DateTimeOffset.UtcNow)) Disconnect(pair.Key);
    }
    public async Task<(string Token,GpoInventory Inventory)> ConnectAsync(GpoLoginRequest request,string actor,CancellationToken ct)
    {
        Expire();
        RequireReal();
        request.UserName=WindowsAccount.Normalize(request.UserName);
        if(connections.Count>=32) throw new PolicyException("GPO_CONNECTION_LIMIT","Too many active GPO sessions. Disconnect unused sessions or wait for the 30-minute idle timeout.");
        if(request.UserName.Length>256||request.Password.Length>1024||request.UserName.IndexOfAny(['\r','\n','\0'])>=0) throw new PolicyException("CREDENTIAL_FORMAT","Invalid login fields.");
        if(string.IsNullOrEmpty(request.Password)!=string.IsNullOrEmpty(request.UserName)) throw new PolicyException("CREDENTIAL_PAIR_REQUIRED","Supply both username and password, or leave both empty to use the service identity.");
        GpoInventory inventory;
        try {
            inventory=await executor.RunAsync<GpoInventory>("gpoInventory",Configuration,new{credential=new{userName=request.UserName,password=request.Password}},ct);
            var bytes=Encoding.UTF8.GetBytes(request.Password);
            byte[] encrypted;
            try{encrypted=protector.Protect(bytes);}finally{CryptographicOperations.ZeroMemory(bytes);}
            var token=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            connections[token]=new(actor,request.UserName,encrypted,inventory,DateTimeOffset.UtcNow.Add(ConnectionIdleTimeout));
            lock(connections) cleanup??=new Timer(_=>Expire(),null,TimeSpan.FromMinutes(1),TimeSpan.FromMinutes(1));
            store.Audit("GPO_CONNECTED",actor,details:new{inventory.ExecutionUser,mode=Mode,gpoCount=inventory.Gpos.Length});
            return(token,inventory);
        } finally {request.Password="";}
    }
    // Called by a periodic callback installed at first use; secrets are also removed on access and disconnect.
    public void CleanupExpired()=>Expire();
    public void Disconnect(string token){if(connections.TryRemove(token,out var c))CryptographicOperations.ZeroMemory(c.Password);}
    private Connection Get(string token,string actor)
    {
        Expire();
        if(!connections.TryGetValue(token,out var c)||c.Actor!=actor)throw new PolicyException("GPO_LOGIN_REQUIRED","Connect again. The temporary GPO connection expired or the service restarted.");
        var refreshed=c with{Expires=DateTimeOffset.UtcNow.Add(ConnectionIdleTimeout)};
        connections.TryUpdate(token,refreshed,c);
        return refreshed;
    }
    private async Task<T> Run<T>(string op,Connection c,object data,CancellationToken ct)
    {
        // Decryption exists only for this subprocess invocation. No request/payload logging.
        var bytes=protector.Unprotect(c.Password);
        try{return await executor.RunAsync<T>(op,Configuration,new{credential=new{userName=c.UserName,password=Encoding.UTF8.GetString(bytes)},data},ct);}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    public GpoInventory Inventory(string token,string actor)=>Get(token,actor).Inventory;

    public object SessionStatus(string token,string actor)
    {
        var c=Get(token,actor);
        return new { connected=true, executionUser=c.Inventory.ExecutionUser, expiresAt=c.Expires.ToString("O"), idleTimeoutMinutes=(int)ConnectionIdleTimeout.TotalMinutes };
    }
    public async Task<GpoWorkflowPlan> ReplanAsync(string id,string token,string actor,CancellationToken ct)
    {
        RequireReal();
        var c=Get(token,actor);
        var previous=store.Require<GpoWorkflowRun>("gpo_runs",id);
        AssertContext(previous.Plan,c,actor);
        var fresh=await PreviewAsync(token,actor,previous.Plan.Selection,ct);
        store.Audit("GPO_REMEDIATION_REPLANNED",actor,details:new{sourceOperation=id,newPlan=fresh.Id});
        return fresh;
    }
    public async Task<GpoEnvironmentStatus> ReadinessAsync(string token,string actor,CancellationToken ct)
    {
        RequireReal();
        var c=Get(token,actor);
        return await Run<GpoEnvironmentStatus>("gpoReadiness",c,new{},ct);
    }
    public async Task<GpoInventory> DiscoverAsync(string token,string actor,CancellationToken ct)
    {
        var c=Get(token,actor);
        RequireReal();
        var inventory=await Run<GpoInventory>("gpoInventory",c,new{},ct);
        connections.TryUpdate(token,c with{Inventory=inventory},c);
        return inventory;
    }
    public async Task<GpoWorkflowPlan> PreviewAsync(string token,string actor,GpoSelection selection,CancellationToken ct)
    {
        RequireReal();
        var c=Get(token,actor);ProductionGpoMappings.Validate(selection);
        var mapping=ProductionGpoMappings.Require(selection.Setting);
        var gpo=c.Inventory.Gpos.SingleOrDefault(g=>string.Equals(g.Id,selection.GpoId,StringComparison.OrdinalIgnoreCase));
        var scope=c.Inventory.Scopes.SingleOrDefault(s=>string.Equals(s.Dn,selection.ScopeDn,StringComparison.OrdinalIgnoreCase));
        if(gpo is null||!gpo.Selectable||scope is null)throw new PolicyException("GPO_SELECTION_REQUIRED","Select an available GPO and scope from the discovered list.");
        if(mapping.DomainPolicySensitive && scope.Kind!="Domain") throw new PolicyException("PASSWORD_SCOPE_MISMATCH","Domain password and lockout policies require the domain root.");
        var preview=await Run<GpoPreview>("gpoPreview",c,new{selection,mapping},ct);
        var plan=new GpoWorkflowPlan(Guid.NewGuid().ToString("N"),actor,c.Inventory.ExecutionUser,Mode,Domain,Dc,selection,preview,PolicyValues.Now(),PolicyValues.Hash(mapping));
        store.Put("gpo_plans",plan.Id,plan);store.Audit("GPO_PLAN_PREPARED",actor,details:plan);
        return plan;
    }
    public GpoWorkflowRun[] History(string actor)=>store.List<GpoWorkflowRun>("gpo_runs")
        .Where(x=>string.Equals(x.Plan.Actor,actor,StringComparison.OrdinalIgnoreCase))
        .OrderByDescending(x=>DateTimeOffset.TryParse(x.UpdatedAt,out var updated)?updated:DateTimeOffset.MinValue)
        .ToArray();
    private void AssertContext(GpoWorkflowPlan p,Connection c,string actor)
    {
        if(!string.Equals(p.Actor,actor,StringComparison.OrdinalIgnoreCase)||p.Mode!=Mode||p.Domain!=Domain||p.DomainController!=Dc||!string.Equals(p.ExecutionUser,c.Inventory.ExecutionUser,StringComparison.OrdinalIgnoreCase))throw new PolicyException("GPO_PLAN_CONTEXT","Reconnect with the same execution account and environment or prepare a new plan.");
    }
    public async Task<GpoWorkflowRun> ExecuteAsync(string id,string operation,GpoConsent consent,string token,string actor)
    {
        RequireReal();
        var c=Get(token,actor);
        var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);AssertContext(plan,c,actor);
        var mapping=ProductionGpoMappings.Require(plan.Selection.Setting);
        if(!string.IsNullOrEmpty(plan.MappingHash) && !string.Equals(plan.MappingHash,PolicyValues.Hash(mapping),StringComparison.Ordinal)) throw new PolicyException("GPO_MAPPING_CHANGED","The production mapping changed after this plan was prepared. Generate a fresh preview.");
        var previous=store.Get<GpoWorkflowRun>("gpo_runs",id);
        if(operation=="apply"){
            ProductionGpoMappings.Validate(plan.Selection);
            GpoWorkflowRules.ValidateConsent(plan,consent);
            if(previous is not null)return previous;
            if(DateTimeOffset.UtcNow-DateTimeOffset.Parse(plan.CreatedAt)>TimeSpan.FromMinutes(10))throw new PolicyException("GPO_PLAN_EXPIRED","Prepare a fresh GPO plan.");
        }else if(operation=="rollback"){
            if(consent.Confirmation!="ROLLBACK")throw new PolicyException("CONFIRMATION_REQUIRED","Type ROLLBACK.");
            if(previous is null)throw new PolicyException("NOT_FOUND","No execution exists for this plan.");
            if(previous.Result.State=="ROLLED_BACK")return previous;
            if(previous.Result.State=="NO_CHANGE")throw new PolicyException("ROLLBACK_NOT_AVAILABLE","No backup exists because this operation required no change.");
        }else if(operation is not ("verify" or "refresh"))throw new PolicyException("OPERATION_DENIED","Unknown GPO operation.");
        if(operation!="apply"&&previous is null)throw new PolicyException("NOT_FOUND","Apply has not been started.");
        if(operation=="refresh" && previous is not null)
        {
            // Do not trust the previous stored status before a disruptive endpoint refresh.
            // Re-read the live GPO/link state first; this catches external GPMC edits between Verify and Refresh.
            var live=await Run<GpoWorkflowResult>("gpoVerify",c,new{plan,mapping,previous=previous.Result,consent=previous.Approval},CancellationToken.None);
            if(live.RefreshResults.Length==0 && previous.Result.RefreshResults.Length>0) live=live with{RefreshResults=previous.Result.RefreshResults};
            previous=previous with{Result=live,UpdatedAt=PolicyValues.Now()};
            store.Put("gpo_runs",id,previous,live.State);
            if(!live.GpoPublished || !live.LinkVerified || live.State.Contains("DRIFT",StringComparison.OrdinalIgnoreCase) || live.State.Contains("MISMATCH",StringComparison.OrdinalIgnoreCase))
                throw new PolicyException("GPO_DRIFT_DETECTED","Live GPO or link state no longer matches the requested state. Refresh was blocked; prepare a fresh remediation plan.");
        }
        if(Real&&operation!="verify"&&!config.GetValue<bool>("Windows:EnableWrites"))throw new PolicyException("WRITES_DISABLED","Enable writes in Settings first.");
        gate.BeginOperation(()=>{if(operation=="apply"&&store.Get<GpoWorkflowRun>("gpo_runs",id)is not null)throw new PolicyException("GPO_ALREADY_STARTED","This operation already exists. Refresh history.");});
        var result=previous?.Result??new("APPLYING","Execution started; inspect backup after an interruption.",null,null,null,false,false,[],"PENDING");
        var correlationId=previous?.CorrelationId??Guid.NewGuid().ToString("N");
        var startedAt=previous?.StartedAt??PolicyValues.Now();
        var run=new GpoWorkflowRun(id,plan,result with{State=operation.ToUpperInvariant()+"ING"},PolicyValues.Now(),operation=="apply"?consent:previous?.Approval,correlationId,startedAt);
        try{
            store.Put("gpo_runs",id,run,run.Result.State);store.Audit("GPO_"+operation.ToUpperInvariant()+"_STARTED",actor,jobId:id,controlId:plan.Selection.Setting,gpoId:plan.Selection.GpoId,details:new{id,correlationId,plan.ExecutionUser});
            result=await Run<GpoWorkflowResult>("gpo"+char.ToUpperInvariant(operation[0])+operation[1..],c,new{plan,mapping,previous=previous?.Result,consent=operation=="apply"?consent:previous?.Approval},CancellationToken.None);
            if(operation=="verify" && previous is not null && result.RefreshResults.Length==0 && previous.Result.RefreshResults.Length>0)
                result=result with{RefreshResults=previous.Result.RefreshResults};
            run=run with{Result=result,UpdatedAt=PolicyValues.Now()};
            if(operation=="apply" && plan.Selection.RunGpUpdate && result.GpoPublished && result.LinkVerified && (result.State is "PUBLISHED" or "NO_CHANGE"))
            {
                // Persist publication before refresh and retain the same operation gate throughout.
                store.Put("gpo_runs",id,run,run.Result.State);
                store.Audit("GPO_AUTO_REFRESH_STARTED",actor,jobId:id,details:new{id,correlationId});
                try
                {
                    result=await Run<GpoWorkflowResult>("gpoRefresh",c,new{plan,mapping,previous=result,consent},CancellationToken.None);
                    run=run with{Result=result,UpdatedAt=PolicyValues.Now()};
                }
                catch(Exception)
                {
                    run=run with{Result=result with{State="REFRESH_PARTIAL",Message="GPO publication completed, but automatic gpupdate could not complete. Inspect endpoint state before retrying Refresh."},UpdatedAt=PolicyValues.Now()};
                }
            }
        }catch(Exception ex){
            // A transport/timeout failure can occur after a remote write began.
            // Never label an unknown outcome as a safe failure.
            var safe=ex is PolicyException pex && new[]{"GPO_BUSY","GPO_ALREADY_STARTED","GPO_PLAN_STALE","GPO_PLAN_EXPIRED","ROLLBACK_CONFLICT","ROLLBACK_NOT_AVAILABLE","PREFLIGHT_FAILED"}.Contains(pex.Code);
            run=run with{Result=result with{State=safe?"FAILED_SAFE":"REVIEW_REQUIRED",Message=ex is PolicyException p?p.Code+": "+p.Message:"Execution interrupted. Inspect the DC backup/manifest before recovery."},UpdatedAt=PolicyValues.Now()};
        }
        finally{store.Put("gpo_runs",id,run,run.Result.State);gate.EndOperation();}
        store.Audit("GPO_EXECUTION_RESULT",actor,jobId:id,controlId:plan.Selection.Setting,gpoId:plan.Selection.GpoId,details:new{run,correlationId=run.CorrelationId});
        return run;
    }
    public GpoEvidence Evidence(string id,string actor)
    {
        var run=store.Require<GpoWorkflowRun>("gpo_runs",id);
        if(!string.Equals(run.Plan.Actor,actor,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("NOT_FOUND","Operation not found.");
        var body=new {
            schemaVersion="1.0",
            product="GPO Remediator",
            benchmark="CIS v4.0.0",
            operationId=run.Id,
            generatedAt=PolicyValues.Now(),
            actor=run.Plan.Actor,
            executionUser=run.Plan.ExecutionUser,
            domain=run.Plan.Domain,
            domainController=run.Plan.DomainController,
            controlId=ProductionGpoMappings.Require(run.Plan.Selection.Setting).ControlId,
            setting=run.Plan.Selection.Setting,
            gpoId=run.Plan.Selection.GpoId,
            gpoName=run.Plan.Preview.Gpo.Name,
            scopeDn=run.Plan.Selection.ScopeDn,
            beforeValue=run.Plan.Preview.PreviousValue,
            desiredValue=ProductionGpoMappings.Require(run.Plan.Selection.Setting).DesiredDisplay(run.Plan.Selection),
            state=run.Result.State,
            backupId=run.Result.BackupId,
            backupDirectory=run.Result.BackupDirectory,
            effectiveStatus=run.Result.EffectiveStatus,
            currentValue=run.Result.CurrentValue,
            verification=run.Result.Verification,
            endpointChecks=run.Result.EndpointChecks,
            warnings=run.Plan.Preview.Warnings,
            changeReference=run.Approval?.ChangeReference,
            approvedBy=run.Approval?.ApprovedBy,
            handler=ProductionGpoMappings.Require(run.Plan.Selection.Setting).Handler,
            mappingSource=ProductionGpoMappings.Require(run.Plan.Selection.Setting).Source
        };
        var hash=PolicyValues.Hash(body);
        return new("1.0","GPO Remediator","CIS v4.0.0",run.Id,(string)body.generatedAt,run.Plan.Actor,
            run.Plan.ExecutionUser,run.Plan.Domain,run.Plan.DomainController,(string)body.controlId,run.Plan.Selection.Setting,
            run.Plan.Selection.GpoId,run.Plan.Preview.Gpo.Name,run.Plan.Selection.ScopeDn,run.Plan.Preview.PreviousValue,
            ProductionGpoMappings.Require(run.Plan.Selection.Setting).DesiredDisplay(run.Plan.Selection),run.Result.State,run.Result.BackupId,run.Result.BackupDirectory,run.Result.EffectiveStatus,
            run.Result.Verification,run.Plan.Preview.Warnings,hash,run.Approval?.ChangeReference,run.Approval?.ApprovedBy,ProductionGpoMappings.Require(run.Plan.Selection.Setting).Handler,ProductionGpoMappings.Require(run.Plan.Selection.Setting).Source,run.Result.EndpointChecks,run.CorrelationId);
    }
    public void Dispose(){cleanup?.Dispose();foreach(var key in connections.Keys)Disconnect(key);}
}
