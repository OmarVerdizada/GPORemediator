using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using Microsoft.AspNetCore.DataProtection;

namespace GpoRemediator.Services;

public sealed class GpoWorkflowService(IConfiguration config,Store store,OperationGate gate,IDataProtectionProvider protection,WindowsPowerShellExecutor executor) : IDisposable, IWorkflowOperations
{
    private static readonly TimeSpan ConnectionIdleTimeout=TimeSpan.FromMinutes(15);
    private static readonly TimeSpan AbsoluteConnectionLifetime=TimeSpan.FromHours(2);
    private sealed record Connection(string Actor,string UserName,byte[] Password,GpoInventory Inventory,DateTimeOffset Expires,DateTimeOffset Created);
    private readonly SemaphoreSlim loginSlots=new(4,4);
    private readonly ConcurrentDictionary<string,Connection> connections=new();
    private readonly IDataProtector protector=protection.CreateProtector("GpoWorkflow.EphemeralLogin.v1");
    private bool Real=>!config.GetValue<bool>("LocalSetup")&&string.Equals(config["Mode"],"Windows",StringComparison.OrdinalIgnoreCase);
    private string Mode=>"WINDOWS";
    private void RequireReal(){if(!Real)throw new PolicyException("WINDOWS_MODE_REQUIRED","GPO discovery and remediation require Windows / AD mode. Setup mode is configuration-only.");}
    private string Domain=>config["Windows:Domain"]??"";
    private string Dc=>config["Windows:DomainController"]??"";
    private object Configuration { get { if(Targeting=="ExplicitHosts")OperatorSecurity.ValidateHosts(AllowedHosts,Domain);return new{domain=Domain,domainController=Dc,backupPath=config["Windows:BackupPath"],allowedHosts=AllowedHosts,endpointTargeting=Targeting,emitProgress=true}; } }
    private string[] ApprovedGpos=>config.GetSection("Windows:ApprovedGpoIds").Get<string[]>()??[];
    private string[] AuthorizedOus=>config.GetSection("Windows:AuthorizedOus").Get<string[]>()??[];
    private string[] AllowedHosts=>config.GetSection("Windows:AllowedHosts").Get<string[]>()??[];
    private string Targeting=>EndpointTargeting.Resolve(config["Windows:EndpointTargeting"],AllowedHosts);
    private string ConfigHash=>PolicyValues.Hash(new{domain=Domain,dc=Dc,backupPath=config["Windows:BackupPath"],approvedGpos=ApprovedGpos,authorizedOus=AuthorizedOus,allowedHosts=AllowedHosts,endpointTargeting=Targeting});
    private GpoInventory Authorize(GpoInventory source)
    {
        // Discovery/preview are read-only under the delegated account. A saved
        // write boundary must not hide the rest of the domain inventory.
        return source;
    }
    private Timer? cleanup;
    private void Expire()
    {
        foreach(var pair in connections.Where(x=>x.Value.Expires<=DateTimeOffset.UtcNow||x.Value.Created.Add(AbsoluteConnectionLifetime)<=DateTimeOffset.UtcNow)) Disconnect(pair.Key);
    }
    public async Task<(string Token,GpoInventory Inventory)> ConnectAsync(GpoLoginRequest request,string actor,CancellationToken ct)
    {
        Expire();
        RequireReal();
        request.UserName=WindowsAccount.Normalize(request.UserName);
        if(connections.Count>=32) throw new PolicyException("GPO_CONNECTION_LIMIT","Too many active GPO sessions. Disconnect unused sessions or wait for the 30-minute idle timeout.");
        if(request.Password is null||request.UserName.Length>256||request.Password.Length>1024||request.UserName.IndexOfAny(['\r','\n','\0'])>=0) throw new PolicyException("CREDENTIAL_FORMAT","Invalid login fields.");
        if(string.IsNullOrWhiteSpace(request.UserName)||string.IsNullOrEmpty(request.Password)) throw new PolicyException("DELEGATED_CREDENTIAL_REQUIRED","Supply an explicit delegated DOMAIN\\user credential. The backend service identity is never used for GPO execution.");
        if(!await loginSlots.WaitAsync(0,ct))throw new PolicyException("GPO_CONNECTION_LIMIT","Too many concurrent connection attempts. Retry later.");
        GpoInventory inventory;
        try {
            inventory=Authorize(await executor.RunAsync<GpoInventory>("gpoInventory",Configuration,new{credential=new{userName=request.UserName,password=request.Password}},ct));
            GpoScriptWorkspaces.SyncInventory(inventory);
            var bytes=Encoding.UTF8.GetBytes(request.Password);
            byte[] encrypted;
            try{encrypted=protector.Protect(bytes);}finally{CryptographicOperations.ZeroMemory(bytes);}
            var token=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            lock(connections){
                if(connections.Count>=32){CryptographicOperations.ZeroMemory(encrypted);throw new PolicyException("GPO_CONNECTION_LIMIT","Too many active GPO sessions.");}
                connections[token]=new(actor,request.UserName,encrypted,inventory,DateTimeOffset.UtcNow.Add(ConnectionIdleTimeout),DateTimeOffset.UtcNow);
            }
            lock(connections) cleanup??=new Timer(_=>Expire(),null,TimeSpan.FromMinutes(1),TimeSpan.FromMinutes(1));
            store.Audit("GPO_CONNECTED",actor,details:new{inventory.ExecutionUser,mode=Mode,gpoCount=inventory.Gpos.Length});
            return(token,inventory);
        } finally {request.Password="";loginSlots.Release();}
    }
    // Called by a periodic callback installed at first use; secrets are also removed on access and disconnect.
    public void CleanupExpired()=>Expire();
    public void Disconnect(string token){if(connections.TryRemove(token,out var c))CryptographicOperations.ZeroMemory(c.Password);}
    private Connection Get(string token,string actor)
    {
        Expire();
        if(!connections.TryGetValue(token,out var c)||!string.Equals(c.Actor,actor,StringComparison.OrdinalIgnoreCase))throw new PolicyException("GPO_LOGIN_REQUIRED","Connect again. The temporary GPO connection expired or the service restarted.");
        var idleExpiry=DateTimeOffset.UtcNow.Add(ConnectionIdleTimeout);
        var absoluteExpiry=c.Created.Add(AbsoluteConnectionLifetime);
        var refreshed=c with{Expires=idleExpiry<absoluteExpiry?idleExpiry:absoluteExpiry};
        connections.TryUpdate(token,refreshed,c);
        return refreshed;
    }
    private async Task<T> Run<T>(string op,Connection c,object data,CancellationToken ct,Action<string>? progress=null)
    {
        // Decryption exists only for this subprocess invocation. No request/payload logging.
        var bytes=protector.Unprotect(c.Password);
        try{return await executor.RunAsync<T>(op,Configuration,new{credential=new{userName=c.UserName,password=Encoding.UTF8.GetString(bytes)},data},ct,progress);}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    public GpoInventory Inventory(string token,string actor)=>Get(token,actor).Inventory;
    public Task<T> RunDirectoryOperation<T>(string operation,string token,string actor,object data,CancellationToken ct)
    {
        RequireReal();
        if(operation is not ("fgppPreview" or "fgppApply" or "fgppVerify" or "fgppRollback"))throw new PolicyException("OPERATION_DENIED","Unsupported password policy operation.");
        return Run<T>(operation,Get(token,actor),data,ct);
    }
    public void ValidateConnection(string token,string actor){RequireReal();Get(token,actor);}
    public async Task<object> AccessReportAsync(GpoSelection selection,string token,string actor,CancellationToken ct){
        RequireReal();var c=Get(token,actor);
        if(!c.Inventory.Gpos.Any(x=>x.Id.Equals(selection.GpoId,StringComparison.OrdinalIgnoreCase))||!c.Inventory.Scopes.Any(x=>x.Dn.Equals(selection.ScopeDn,StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("GPO_SELECTION_REQUIRED","Choose a discovered GPO and OU/domain.");
        var mapping=ProductionGpoMappings.Effective(selection with{ItemValues=null,ReviewContext=null});
        if(mapping.Handler=="Manual")mapping=mapping with{Handler="SecurityTemplate"};
        var report=await Run<System.Text.Json.JsonElement>("gpoPreview",c,new{selection,mapping,accessReport=true},ct);
        store.Audit("GPO_ACCESS_REPORT",actor,gpoId:selection.GpoId,details:new{c.Inventory.ExecutionUser,selection.ScopeDn});
        return report;
    }
    public async Task<object> ExplainAsync(string id,GpoExplainRequest request,string token,string actor,CancellationToken ct){
        RequireReal();var c=Get(token,actor);var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);AssertContext(plan,c,actor);
        var mapping=ProductionGpoMappings.Effective(plan.Selection);
        var hosts=plan.Preview.VerificationComputers??plan.Preview.RefreshComputers;
        var hostname=(request.Hostname??"").Trim();
        if(!mapping.DomainPolicySensitive&&!hosts.Any(x=>x.Equals(hostname,StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("ENDPOINT_OUTSIDE_SCOPE","Choose an endpoint pinned in this preview; generate a new preview for a different target.");
        var result=await Run<System.Text.Json.JsonElement>("gpoExplain",c,new{plan,mapping,hostname},ct);
        store.Put("gpo_diagnostics",id,new{actor,result});store.Audit("GPO_APPLICATION_EXPLAINED",actor,jobId:id,gpoId:plan.Selection.GpoId,details:new{hostname,c.Inventory.ExecutionUser});
        return result;
    }

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
        var inventory=Authorize(await Run<GpoInventory>("gpoInventory",c,new{},ct));
        GpoScriptWorkspaces.SyncInventory(inventory);
        connections.TryUpdate(token,c with{Inventory=inventory},c);
        return inventory;
    }
    public async Task<object> CheckTargetAccessAsync(string token,string actor,GpoSelection selection,CancellationToken ct)
    {
        // Access depends on the selected object/scope, not unfinished policy
        // input fields. Value validation belongs to the explicit Preview call.
        RequireReal();var c=Get(token,actor);var mapping=ProductionGpoMappings.Effective(selection with{ItemValues=null,ReviewContext=null});
        if(!mapping.Writable&&selection.ReviewContext is not null)mapping=mapping with{Automation="Automated",Handler=mapping.Handler=="Manual"?"SecurityTemplate":mapping.Handler};
        if(!mapping.Writable)throw new PolicyException("GPO_MANUAL_ONLY","This control requires manual review.");
        var gpo=c.Inventory.Gpos.SingleOrDefault(x=>string.Equals(x.Id,selection.GpoId,StringComparison.OrdinalIgnoreCase));
        var scope=c.Inventory.Scopes.SingleOrDefault(x=>string.Equals(x.Dn,selection.ScopeDn,StringComparison.OrdinalIgnoreCase));
        if(gpo is null||!gpo.Selectable||scope is null)throw new PolicyException("GPO_SELECTION_REQUIRED","Select a discovered GPO and target.");
        ProductionGpoMappings.ValidateTarget(mapping,scope,selection);
        try{return await Run<System.Text.Json.JsonElement>("gpoPreview",c,new{selection,mapping,accessOnly=true},ct);}
        catch(PolicyException error) when(error.Code.EndsWith("ACCESS_DENIED",StringComparison.Ordinal)||error.Code=="GPO_ACCESS_UNVERIFIED"){
            store.Audit("GPO_TARGET_ACCESS_BLOCKED",actor,controlId:selection.Setting,gpoId:selection.GpoId,details:new{selection.ScopeDn,c.Inventory.ExecutionUser,error.Code});
            throw;
        }
    }
    public async Task<GpoWorkflowPlan> PreviewAsync(string token,string actor,GpoSelection selection,CancellationToken ct,bool requireWriteAccess=true)
    {
        RequireReal();
        var c=Get(token,actor);ProductionGpoMappings.Validate(selection);
        var mapping=ProductionGpoMappings.Effective(selection);
        var gpo=c.Inventory.Gpos.SingleOrDefault(g=>string.Equals(g.Id,selection.GpoId,StringComparison.OrdinalIgnoreCase));
        var scope=c.Inventory.Scopes.SingleOrDefault(s=>string.Equals(s.Dn,selection.ScopeDn,StringComparison.OrdinalIgnoreCase));
        if(gpo is null||!gpo.Selectable||scope is null)throw new PolicyException("GPO_SELECTION_REQUIRED","Select an available GPO and scope from the discovered list.");
        if(mapping.Scope=="User" && selection.Refresh=="Scope" &&
           !c.Inventory.Scopes.Any(s=>s.Kind=="OU"&&string.Equals(s.Dn,selection.EndpointScopeDn,StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("ENDPOINT_SCOPE_REQUIRED","Select a discovered computer OU for user-session refresh.");
        ProductionGpoMappings.ValidateTarget(mapping,scope,selection);
        GpoPreview preview;
        try{preview=await Run<GpoPreview>("gpoPreview",c,new{selection,mapping,requireWriteAccess},ct);}
        catch(PolicyException error) when(error.Code.EndsWith("ACCESS_DENIED",StringComparison.Ordinal)||error.Code=="GPO_ACCESS_UNVERIFIED"){
            store.Audit("GPO_PREVIEW_ACCESS_BLOCKED",actor,controlId:selection.Setting,gpoId:selection.GpoId,details:new{selection.ScopeDn,c.Inventory.ExecutionUser,error.Code});
            throw;
        }
        var plan=new GpoWorkflowPlan(Guid.NewGuid().ToString("N"),actor,c.Inventory.ExecutionUser,Mode,Domain,Dc,selection,preview,PolicyValues.Now(),PolicyValues.Hash(mapping),ConfigHash,GpoWorkflowRules.IsWriteAuthorized(ApprovedGpos,AuthorizedOus,selection));
        store.Put("gpo_plans",plan.Id,plan);store.Audit("GPO_PLAN_PREPARED",actor,details:plan);
        return plan;
    }
    public GpoWorkflowRun[] History(string actor)=>store.GpoRunsForActor(actor);
    private void AssertContext(GpoWorkflowPlan p,Connection c,string actor)
    {
        if(!string.Equals(p.Actor,actor,StringComparison.OrdinalIgnoreCase)||p.Mode!=Mode||p.Domain!=Domain||p.DomainController!=Dc||!string.Equals(p.ExecutionUser,c.Inventory.ExecutionUser,StringComparison.OrdinalIgnoreCase)||!string.Equals(p.ConfigHash,ConfigHash,StringComparison.Ordinal))throw new PolicyException("GPO_PLAN_CONTEXT","Reconnect with the same execution account and unchanged authorization configuration, then prepare a new plan.");
    }
    public GpoWorkflowPlan ValidateSubmission(string id,string operation,GpoConsent consent,string token,string actor)
    {
        RequireReal();var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);AssertContext(plan,Get(token,actor),actor);
        if(operation!="verify"){
            if(!config.GetValue<bool>("Windows:EnableWrites"))throw new PolicyException("WRITES_DISABLED","Enable the production change gate first.");
            GpoWorkflowRules.ValidateWriteScope(ApprovedGpos,AuthorizedOus);GpoWorkflowRules.ValidateWriteSelection(ApprovedGpos,AuthorizedOus,plan.Selection);
        }
        if(operation=="apply"){
            GpoWorkflowRules.ValidateConsent(plan,consent);ProductionGpoMappings.Validate(plan.Selection);
            if(DateTimeOffset.UtcNow-DateTimeOffset.Parse(plan.CreatedAt)>TimeSpan.FromMinutes(10))throw new PolicyException("GPO_PLAN_EXPIRED","Prepare a fresh plan.");
            if(store.Get<GpoWorkflowRun>("gpo_runs",id) is not null)throw new PolicyException("GPO_ALREADY_STARTED","This plan already has an execution; inspect it instead of replaying Apply.");
        }else{
            var run=store.Require<GpoWorkflowRun>("gpo_runs",id);
            if(operation=="rollback"&&(consent.Confirmation!="ROLLBACK"||string.IsNullOrEmpty(run.Result.BackupId)))throw new PolicyException("ROLLBACK_NOT_AVAILABLE","Type ROLLBACK and select an operation with a completed backup.");
        }
        return plan;
    }
    public async Task<GpoWorkflowRun> ExecuteAsync(string id,string operation,GpoConsent consent,string token,string actor,string? workflowId=null,GpoRollbackAnchor? rollbackAnchor=null)
    {
        RequireReal();
        if(operation=="rollback"&&rollbackAnchor is null&&store.List<WorkflowJob>("workflow_jobs").Any(job=>job.Action=="apply"&&job.PlanIds.Length>1&&job.CompletedIds.Contains(id)))
            throw new PolicyException("BATCH_RECOVERY_REQUIRED","Use the Workflow center batch recovery action to restore the first full-GPO snapshot safely.");
        var c=Get(token,actor);
        var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);AssertContext(plan,c,actor);
        var mapping=ProductionGpoMappings.Effective(plan.Selection);
        if(operation is not ("apply" or "rollback" or "verify" or "refresh"))
            throw new PolicyException("OPERATION_DENIED","Unknown GPO operation.");
        if(operation=="refresh" && consent.Refresh is not ("Pdc" or "Scope"))
            throw new PolicyException("GPO_OPTIONS_INVALID","Choose PDC or scope computers for policy refresh.");
        if(operation=="refresh" && mapping.Scope=="User" && consent.Refresh=="Pdc")
            throw new PolicyException("USER_REFRESH_TARGET_INVALID","User policy refresh requires the endpoint OU recorded in the plan; the PDC is not a user-session target.");
        if(operation=="refresh" && mapping.Scope=="User" && consent.Refresh=="Scope" && string.IsNullOrWhiteSpace(plan.Selection.EndpointScopeDn))
            throw new PolicyException("ENDPOINT_SCOPE_REQUIRED","This user-policy plan does not contain an endpoint OU. Prepare a fresh plan with a user-session endpoint OU.");
        if(operation!="verify")
        {
            if(!config.GetValue<bool>("Windows:EnableWrites"))throw new PolicyException("WRITES_DISABLED","Enable the production change gate first.");
            GpoWorkflowRules.ValidateWriteScope(ApprovedGpos,AuthorizedOus);
            GpoWorkflowRules.ValidateWriteSelection(ApprovedGpos,AuthorizedOus,plan.Selection);
        }
        // Read and validate the latest execution record only after claiming the GPO.
        // Verification and refresh must not overwrite another operation's result.
        var resourceKey=Guid.Parse(plan.Selection.GpoId).ToString("D");
        gate.BeginOperation(resourceKey,()=>{},workflowId);
        try
        {
            var previous=store.Get<GpoWorkflowRun>("gpo_runs",id);
            GpoWorkflowRules.ValidateMappingVersion(plan.MappingHash,PolicyValues.Hash(mapping),operation,previous?.Result.State);
            if(operation=="apply"){
                ProductionGpoMappings.Validate(plan.Selection);
                GpoWorkflowRules.ValidateConsent(plan,consent);
                if(previous is not null)return previous;
                if(DateTimeOffset.UtcNow-DateTimeOffset.Parse(plan.CreatedAt)>TimeSpan.FromMinutes(10))throw new PolicyException("GPO_PLAN_EXPIRED","Prepare a fresh GPO plan.");
            }else if(operation=="rollback"){
                if(consent.Confirmation!="ROLLBACK")throw new PolicyException("CONFIRMATION_REQUIRED","Type ROLLBACK.");
                if(previous is null)throw new PolicyException("NOT_FOUND","No execution exists for this plan.");
                if(previous.Result.State=="NO_CHANGE")throw new PolicyException("ROLLBACK_NOT_AVAILABLE","No backup exists because this operation required no change.");
            }
            if(operation!="apply"&&previous is null)throw new PolicyException("NOT_FOUND","Apply has not been started.");
            if(operation=="refresh" && previous is not null)
            {
                // Do not trust the previous stored status before a disruptive endpoint refresh.
                // Re-read the live GPO/link state first; this catches external GPMC edits between Verify and Refresh.
                var live=await Run<GpoWorkflowResult>("gpoVerify",c,new{plan,mapping,previous=previous.Result,consent=previous.Approval},CancellationToken.None);
                if(live.RefreshResults.Length==0 && previous.Result.RefreshResults.Length>0) live=live with{RefreshResults=previous.Result.RefreshResults};
                previous=previous with{Result=live,UpdatedAt=PolicyValues.Now()};
                store.Put("gpo_runs",id,previous,live.State);
                if(live.State != "ROLLED_BACK" && (!live.GpoPublished || !live.LinkVerified || live.State is not ("PUBLISHED" or "NO_CHANGE")))
                    throw new PolicyException("GPO_DRIFT_DETECTED","Live GPO or link state no longer matches the requested state. Refresh was blocked; prepare a fresh remediation plan.");
            }
            var result=previous?.Result??new("APPLYING","Execution started; inspect backup after an interruption.",null,null,null,false,false,[],"PENDING");
            var correlationId=previous?.CorrelationId??Guid.NewGuid().ToString("N");
            var startedAt=previous?.StartedAt??PolicyValues.Now();
            var run=new GpoWorkflowRun(id,plan,result with{State=operation.ToUpperInvariant()+"ING"},PolicyValues.Now(),operation=="apply"?consent:previous?.Approval,correlationId,startedAt);
            try{
                store.Put("gpo_runs",id,run,run.Result.State);store.Audit("GPO_"+operation.ToUpperInvariant()+"_STARTED",actor,jobId:id,controlId:plan.Selection.Setting,gpoId:plan.Selection.GpoId,details:new{id,correlationId,plan.ExecutionUser});
                var stages=(previous?.Stages??[]).ToList();
                var initialStageCount=stages.Count;
                void Progress(string phase){
                    var now=PolicyValues.Now();if(stages.Count>initialStageCount&&stages[^1].FinishedAt is null)stages[^1]=stages[^1] with{FinishedAt=now};
                    stages.Add(new(phase,now));run=run with{Stages=stages.ToArray(),UpdatedAt=now};store.Put("gpo_runs",id,run,run.Result.State);
                }
                Progress(operation.ToUpperInvariant()+"_STARTED");
                result=await Run<GpoWorkflowResult>("gpo"+char.ToUpperInvariant(operation[0])+operation[1..],c,new{plan,mapping,previous=previous?.Result,refresh=operation=="refresh"?consent.Refresh:null,consent=operation=="apply"?consent:previous?.Approval,rollbackAnchor},CancellationToken.None,Progress);
                if(operation=="verify" && result.EndpointCoverage is not null)
                {
                    var checks=(result.EndpointChecks??[]).ToList();
                    while(result.EndpointCoverage is {Complete:false} coverage && result.GpoPublished && result.LinkVerified)
                    {
                        var offset=coverage.Checked;
                        Progress("ENDPOINT_PAGE");
                        result=result with{EndpointChecks=checks.ToArray()};
                        run=run with{Result=result with{State="VERIFYING"},UpdatedAt=PolicyValues.Now()};
                        store.Put("gpo_runs",id,run,"VERIFYING");
                        result=await Run<GpoWorkflowResult>("gpoVerify",c,new{plan,mapping,verificationOffset=offset},CancellationToken.None,Progress);
                        checks.AddRange(result.EndpointChecks??[]);
                        if(result.EndpointCoverage is null || result.EndpointCoverage.Checked<=offset)
                            throw new PolicyException("ENDPOINT_VERIFICATION_STALLED","Endpoint verification did not advance; partial evidence was retained.");
                    }
                    var unique=checks.GroupBy(x=>x.Hostname,StringComparer.OrdinalIgnoreCase).Select(g=>g.Last()).ToArray();
                    var complete=result.EndpointCoverage is {Complete:true} finished && finished.Total>0 && unique.Length==finished.Total;
                    var status=unique.Any(x=>x.State=="MISMATCH")?"ENDPOINT_MISMATCH":complete&&unique.All(x=>x.State=="VERIFIED")?"VERIFIED_ON_ALL_TARGETS":"ENDPOINT_VERIFICATION_PENDING";
                    result=result with{EndpointChecks=unique,EffectiveStatus=result.GpoPublished&&result.LinkVerified&&result.Verification?.ReplicationConverged==true?status:result.EffectiveStatus};
                }
                if(operation=="refresh" && result.RefreshCoverage is not null)
                {
                    var refreshResults=result.RefreshResults.ToList();
                    while(result.RefreshCoverage is {Complete:false} coverage && (result.GpoPublished&&result.LinkVerified||result.State=="ROLLED_BACK"))
                    {
                        var offset=coverage.Checked;result=result with{RefreshResults=refreshResults.ToArray()};
                        run=run with{Result=result with{State="REFRESHING"},UpdatedAt=PolicyValues.Now()};store.Put("gpo_runs",id,run,"REFRESHING");
                        Progress("REFRESH_PAGE");
                        result=await Run<GpoWorkflowResult>("gpoRefresh",c,new{plan,mapping,previous=previous?.Result,refresh=consent.Refresh,refreshOffset=offset},CancellationToken.None,Progress);
                        refreshResults.AddRange(result.RefreshResults);
                        if(result.RefreshCoverage is null || result.RefreshCoverage.Checked<=offset)throw new PolicyException("ENDPOINT_REFRESH_STALLED","Refresh did not advance. Partial evidence was retained.");
                    }
                    var unique=refreshResults.GroupBy(x=>x.Computer,StringComparer.OrdinalIgnoreCase).Select(g=>g.Last()).ToArray();
                    var completed=result.RefreshCoverage is {Complete:true} finished && finished.Total>0 && unique.Length==finished.Total && unique.All(x=>x.State=="COMPLETED");
                    result=result with{RefreshResults=unique,State=result.GpoPublished&&result.LinkVerified?(completed?"REFRESH_COMPLETED":"REFRESH_PARTIAL"):result.State,
                        Message=completed?"Computer policy processing completed on every pinned refresh target. Verify resultant values and winning GPO separately.":"Refresh did not complete on every pinned target. Review per-host results."};
                }
                if(stages.Count>0){stages[^1]=stages[^1] with{FinishedAt=PolicyValues.Now()};run=run with{Stages=stages.ToArray()};}
                if(operation=="verify" && previous is not null && result.RefreshResults.Length==0 && previous.Result.RefreshResults.Length>0)
                    result=result with{RefreshResults=previous.Result.RefreshResults};
                run=run with{Result=result,UpdatedAt=PolicyValues.Now()};
            }catch(Exception ex){
                // A transport/timeout failure can occur after a remote write began.
                // Never label an unknown outcome as a safe failure.
                var safe=ex is PolicyException pex && new[]{"GPO_BUSY","GPO_CHANGED","ENVIRONMENT_NOT_READY","ROLLBACK_CONFLICT","ROLLBACK_NOT_AVAILABLE"}.Contains(pex.Code);
                run=run with{Result=result with{State=safe?"FAILED_SAFE":"REVIEW_REQUIRED",Message=ex is PolicyException p?p.Code+": "+p.Message:"Execution interrupted. Inspect the DC backup/manifest before recovery."},UpdatedAt=PolicyValues.Now()};
            }
            finally{store.Put("gpo_runs",id,run,run.Result.State);}
            store.Audit("GPO_EXECUTION_RESULT",actor,jobId:id,controlId:plan.Selection.Setting,gpoId:plan.Selection.GpoId,details:new{run,correlationId=run.CorrelationId});
            return run;
        }
        finally{gate.EndOperation(resourceKey);}
    }
    // Read-only rollback preflight: returns a live before/after report without modifying AD.
    // The worker rechecks drift under an exclusive lock during the actual Restore-GPO.
    public async Task<object> RollbackPreviewAsync(string id,string token,string actor,CancellationToken ct)
    {
        RequireReal();
        var c=Get(token,actor);
        var run=store.Require<GpoWorkflowRun>("gpo_runs",id);
        AssertContext(run.Plan,c,actor);
        if(store.List<WorkflowJob>("workflow_jobs").Any(job=>job.Action=="apply"&&job.PlanIds.Length>1&&job.CompletedIds.Contains(id)))
            throw new PolicyException("BATCH_RECOVERY_REQUIRED","Use Workflow center batch recovery for operations in a multi-control batch.");
        return await Run<object>("gpoRollbackInspect",c,new{plan=run.Plan},ct);
    }
    public GpoEvidence Evidence(string id,string actor)
    {
        var run=store.Require<GpoWorkflowRun>("gpo_runs",id);
        if(!string.Equals(run.Plan.Actor,actor,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("NOT_FOUND","Operation not found.");
        // Each export represents the latest recorded run; preserve earlier snapshots by hash.
        var evidence=new GpoEvidence("1.1","GPO Remediator","CIS v4.0.0",run.Id,run.UpdatedAt,run.Plan.Actor,
            run.Plan.ExecutionUser,run.Plan.Domain,run.Plan.DomainController,ProductionGpoMappings.Require(run.Plan.Selection.Setting).ControlId,run.Plan.Selection.Setting,
            run.Plan.Selection.GpoId,run.Plan.Preview.Gpo.Name,run.Plan.Selection.ScopeDn,run.Plan.Preview.PreviousValue,
            ProductionGpoMappings.Effective(run.Plan.Selection).DesiredDisplay(run.Plan.Selection),run.Result.State,run.Result.BackupId,run.Result.BackupDirectory,run.Result.EffectiveStatus,
            run.Result.Verification,run.Plan.Preview.Warnings,"",run.Approval?.ChangeReference,run.Approval?.ApprovedBy,ProductionGpoMappings.Require(run.Plan.Selection.Setting).Handler,ProductionGpoMappings.Effective(run.Plan.Selection).Source,run.Result.EndpointChecks,run.CorrelationId,run.Result.CurrentValue);
        evidence=evidence with{IntegrityHash=GpoWorkflowRules.EvidenceHash(evidence)};
        store.Put("gpo_evidence",id+"-"+evidence.IntegrityHash,evidence,"IMMUTABLE");
        return evidence;
    }
    public void Dispose(){cleanup?.Dispose();foreach(var key in connections.Keys)Disconnect(key);}
}
