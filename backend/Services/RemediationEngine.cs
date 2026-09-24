using System.Threading.Channels;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;

namespace GpoRemediator.Services;

public sealed class RemediationEngine(Store store, IWindowsPolicyProvider provider, AdapterRegistry adapters, ILogger<RemediationEngine> logger) : BackgroundService
{
    private readonly Channel<(string Id,string Operation)> queue=Channel.CreateUnbounded<(string,string)>(new(){SingleReader=true});
    private readonly object submissionGate=new();
    private bool maintenance;
    public bool Maintenance { get { lock(submissionGate) return maintenance; } }
    public void EndMaintenance() { lock(submissionGate) maintenance=false; }
    public void BeginMaintenance(Action action)
    {
        lock(submissionGate)
        {
            if(maintenance) throw new PolicyException("SERVICE_STOPPING","The service is already stopping or restarting.");
            if(store.List<RemediationJob>("jobs").Any(j=>IsActive(j.State)))
                throw new PolicyException("JOB_BUSY","An operation is active. Wait for it to finish before stopping or restarting the service.");
            maintenance=true;
            try { action(); } catch { maintenance=false; throw; }
        }
    }
    public static readonly HashSet<string> ActiveStates=["CREATED","PREFLIGHT","IMPACT_ANALYZED","BACKING_UP","APPLYING","GPO_WRITE_VERIFIED","GPO_SCOPE_VERIFIED","POLICY_REFRESH_PENDING","POLICY_REFRESHED","RSOP_VERIFYING","ENDPOINT_VERIFYING","RESTARTING","ROLLING_BACK","ROLLBACK_GPO_VERIFIED","VERIFY_QUEUED","ROLLBACK_QUEUED"];
    public static bool IsActive(string state)=>ActiveStates.Contains(state);
    public (Finding Finding,BenchmarkControl Control,TargetResource Target) Context(string findingId)
    {
        var finding=store.Require<Finding>("findings",findingId);
        return(finding,store.Require<BenchmarkControl>("controls",finding.ControlId),store.Require<TargetResource>("targets",finding.TargetId));
    }
    public async Task<PolicySourceAnalysis> AnalyzeAsync(string findingId,string operatorName,CancellationToken ct)
    {
        var (finding,control,target)=Context(findingId);
        var result=await provider.AnalyzeAsync(target,control,ct);
        store.Put("analyses",findingId,result); store.Put("targets",target.Id,result.Target);
        // Source analysis is read-only with respect to the domain. The local audit and observed finding are durable.
        store.Audit("SOURCE_ANALYZED",operatorName,controlId:control.Id,gpoId:result.WinningGpoId,details:new{finding.Id,result.Status,result.Confidence});
        return result;
    }
    public Task<EnvironmentReadiness> ReadinessAsync(CancellationToken ct) => provider.ReadinessAsync(ct);

    public async Task<TargetScanResult> ScanTargetAsync(TargetResource seed,string operatorName,CancellationToken ct)
    {
        var target=await provider.ResolveTargetAsync(seed,ct);
        store.Put("targets",target.Id,target);
        var results=new List<ScanControlResult>();
        var created=0;
        foreach(var control in Catalog.Controls.Where(c=>c.Automated&&c.SupportedByGpo&&c.Profiles.Contains(target.Profile,StringComparer.OrdinalIgnoreCase)))
        {
            try
            {
                adapters.Get(control,target);
                var verification=await provider.VerifyEndpointAsync(target,control,control.ExpectedValue,ct);
                var equal=PolicyValues.Equal(verification.ActualValue,control.ExpectedValue,control.PolicyType);
                var existing=store.List<Finding>("findings").FirstOrDefault(f=>f.TargetId==target.Id&&f.ControlId==control.Id);
                if(verification.Success&&equal)
                {
                    if(existing is not null) store.Put("findings",existing.Id,existing with{CurrentValue=verification.ActualValue,Status="PASS"},"PASS");
                    results.Add(new(control.Id,control.ControlId,control.Title,"PASS",verification.ActualValue,control.ExpectedValue,verification.Code,verification.Message,existing?.Id));
                    continue;
                }
                if(verification.ActualValue.Length==0)
                {
                    results.Add(new(control.Id,control.ControlId,control.Title,"UNAVAILABLE",[],control.ExpectedValue,verification.Code,verification.Message,existing?.Id));
                    continue;
                }
                Finding finding;
                if(existing is null)
                {
                    finding=new Finding(Guid.NewGuid().ToString(),control.Id,target.Id,verification.ActualValue,"FAIL",PolicyValues.Now());
                    created++;
                }
                else finding=existing with{CurrentValue=verification.ActualValue,Status="FAIL"};
                store.Put("findings",finding.Id,finding,"FAIL");
                results.Add(new(control.Id,control.ControlId,control.Title,"FAIL",verification.ActualValue,control.ExpectedValue,verification.Code,verification.Message,finding.Id));
            }
            catch(PolicyException ex)
            {
                results.Add(new(control.Id,control.ControlId,control.Title,"UNAVAILABLE",[],control.ExpectedValue,ex.Code,Redactor.Clean(ex.Message)));
            }
        }
        var output=new TargetScanResult(target,results.ToArray(),results.Count(x=>x.Status=="PASS"),results.Count(x=>x.Status=="FAIL"),results.Count(x=>x.Status=="UNAVAILABLE"),created,PolicyValues.Now());
        store.Audit("TARGET_SCANNED",operatorName,details:new{target=target.Hostname,output.Compliant,output.NonCompliant,output.Unavailable,output.FindingsCreated});
        return output;
    }

    public async Task<SafePlanResult> PrepareSafePlanAsync(string findingId,string operatorName,CancellationToken ct)
    {
        var analysis=await AnalyzeAsync(findingId,operatorName,ct);
        var dedicated=analysis.ApplicableGpos.Where(g=>g.Approved&&g.Dedicated&&!g.Protected).ToArray();
        TargetSelection selection;
        if(dedicated.Length==1) selection=new("EXISTING",dedicated[0].Id);
        else if(dedicated.Length>1) throw new PolicyException("GPO_SELECTION_AMBIGUOUS","More than one approved dedicated GPO is applied to the target. Choose the intended GUID manually.");
        else
        {
            var winner=analysis.WinningGpoId is null?null:analysis.ApplicableGpos.FirstOrDefault(g=>string.Equals(g.Id,analysis.WinningGpoId,StringComparison.OrdinalIgnoreCase));
            if(analysis.Status!="DETECTED"||winner is null||!winner.Approved||winner.Protected)
                throw new PolicyException("SAFE_PLAN_NEEDS_SELECTION","No single safe approved GPO can be selected automatically. Review source analysis and choose an approved dedicated GPO.");
            selection=new("DETECTED");
        }
        var preview=await PreviewAsync(findingId,selection,operatorName,ct);
        _=await DryRunAsync(findingId,preview.Impact.Id,operatorName,ct);
        store.Audit("SAFE_PLAN_PREPARED",operatorName,controlId:preview.Impact.ControlId,gpoId:preview.Impact.Gpo.Id,details:new{findingId,previewId=preview.Impact.Id,writes=0,selection});
        return new SafePlanResult(analysis,preview.Impact,preview.Preflight,true,0,selection);
    }
    public async Task<(ImpactAnalysis Impact,PreflightResult Preflight)> PreviewAsync(string findingId,TargetSelection selection,string operatorName,CancellationToken ct)
    {
        var (_,control,target)=Context(findingId); adapters.Get(control,target);
        var plan=await provider.PreviewAsync(findingId,target,control,selection,ct);
        adapters.Get(control,plan.Target);
        ValidatePlan(plan,control);
        var preflight=await provider.PreflightAsync(plan.Target,plan.Gpo,ct);
        store.Put("previews",plan.Id,plan); store.Put("targets",plan.Target.Id,plan.Target);
        store.Audit("IMPACT_PREVIEWED",operatorName,controlId:control.Id,gpoId:plan.Gpo.Id,details:new{plan.Id,plan.OldValue,plan.ProposedValue,plan.BroadImpact});
        return(plan,preflight);
    }
    private static void ValidatePlan(ImpactAnalysis plan,BenchmarkControl control)
    {
        if(!plan.Gpo.Approved||plan.Gpo.Protected) throw new PolicyException("GPO_NOT_APPROVED","The selected GPO is not approved or is a protected default policy.");
        if(!plan.RollbackAvailable||!control.SupportsRollback) throw new PolicyException("ROLLBACK_UNAVAILABLE","A verified rollback point is required before writing this policy.");
    }
    private ImpactAnalysis Plan(string findingId,string previewId)
    {
        var plan=store.Require<ImpactAnalysis>("previews",previewId);
        if(plan.FindingId!=findingId||plan.ExecutionMode!=provider.Mode) throw new PolicyException("PREVIEW_MISMATCH","Preview belongs to another finding or execution mode.");
        if(DateTimeOffset.UtcNow-DateTimeOffset.Parse(plan.CreatedAt)>TimeSpan.FromMinutes(15)) throw new PolicyException("PREVIEW_EXPIRED","Preview is older than 15 minutes. Analyze impact again.");
        return plan;
    }
    private async Task<PreflightResult> RevalidateAsync(ImpactAnalysis plan,BenchmarkControl control,CancellationToken ct)
    {
        var fresh=await provider.PreviewAsync(plan.FindingId,plan.Target,control,plan.Selection,ct);
        adapters.Get(control,fresh.Target);
        if(fresh.Fingerprint!=plan.Fingerprint) throw new PolicyException("STALE_PREVIEW","GPO, scope, value, or target changed after preview. Generate a new impact preview.");
        ValidatePlan(fresh,control);
        var preflight=await provider.PreflightAsync(plan.Target,plan.Gpo,ct);
        if(!preflight.CanRead||!preflight.CanEdit||!preflight.CanVerify||(plan.Selection.Strategy=="CREATE"&&!preflight.CanLink)||preflight.Errors.Length>0)
            throw new PolicyException("PREFLIGHT_DENIED",string.Join(" ",preflight.Errors.Prepend("Identity cannot safely read, edit, scope, or verify this operation.")));
        return preflight;
    }
    public async Task<object> DryRunAsync(string findingId,string previewId,string operatorName,CancellationToken ct)
    {
        var plan=Plan(findingId,previewId); var (_,control,target)=Context(findingId); adapters.Get(control,target);
        var preflight=await RevalidateAsync(plan,control,ct);
        store.Audit("DRY_RUN",operatorName,controlId:control.Id,gpoId:plan.Gpo.Id,details:new{previewId,writes=0,oldValue=plan.OldValue,newValue=plan.ProposedValue,mode=provider.Mode});
        return new{dryRun=true,writes=0,impact=plan,preflight};
    }
    public RemediationJob Submit(string findingId,ApplyRequest request,string operatorName)
    {
        lock(submissionGate)
        {
            if(maintenance) throw new PolicyException("SERVICE_STOPPING","The service is stopping. Start it again before submitting a job.");
            var plan=Plan(findingId,request.PreviewId); var (_,control,target)=Context(findingId); adapters.Get(control,target); ValidatePlan(plan,control);
            if(plan.BroadImpact&&!request.Options.AcknowledgeBroadImpact) throw new PolicyException("IMPACT_ACK_REQUIRED","Explicitly acknowledge the affected GPO scope before applying.");
            if(store.List<RemediationJob>("jobs").Any(j=>IsActive(j.State))) throw new PolicyException("JOB_BUSY","Another privileged operation is running. Wait until it finishes.");
            var now=PolicyValues.Now(); var job=new RemediationJob(Guid.NewGuid().ToString(),findingId,control.Id,target.Id,plan.Gpo.Id,"CREATED",operatorName,provider.Mode,now,now,null,request.Options,plan.Id);
            store.Put("jobs",job.Id,job,job.State); store.Step(job.Id,job.State,"Remediation requested; no domain write yet.");
            store.Audit("REMEDIATION_REQUESTED",operatorName,job.Id,control.Id,job.GpoId,new{job.Options,previewId=plan.Id});
            queue.Writer.TryWrite((job.Id,"APPLY")); return job;
        }
    }
    public RemediationJob SubmitFollowup(string id,string operation,string operatorName,bool acknowledged=false)
    {
        lock(submissionGate)
        {
            if(maintenance) throw new PolicyException("SERVICE_STOPPING","The service is stopping. Start it again before submitting a job.");
            var job=store.Require<RemediationJob>("jobs",id);
            if(store.List<RemediationJob>("jobs").Any(j=>IsActive(j.State))) throw new PolicyException("JOB_BUSY","Another operation is running.");
            if(job.BackupId is null) throw new PolicyException("NO_BACKUP","This job has no recorded rollback point or completed write.");
            if(job.Mode!=provider.Mode) throw new PolicyException("MODE_MISMATCH","The job belongs to another execution mode.");
            if(operation=="ROLLBACK"&&!acknowledged) throw new PolicyException("ROLLBACK_ACK_REQUIRED","Acknowledge that rollback restores the complete GPO backup.");
            if(job.State=="ROLLED_BACK" || (operation=="VERIFY"&&job.State.Contains("ROLLBACK"))) throw new PolicyException("INVALID_JOB_STATE","This job cannot enter the requested workflow.");
            if(operation=="ROLLBACK"&&job.State=="ROLLBACK_VERIFICATION_PENDING") operation="VERIFY_ROLLBACK";
            job=Transition(job with{Operator=operatorName},operation=="VERIFY"?"VERIFY_QUEUED":"ROLLBACK_QUEUED",$"{operation} requested by {operatorName}.");
            store.Audit(operation+"_REQUESTED",operatorName,job.Id,job.ControlId,job.GpoId);
            queue.Writer.TryWrite((job.Id,operation)); return job;
        }
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Never replay uncertain writes after a crash. An operator must inspect and explicitly verify/recover.
        foreach(var interrupted in store.List<RemediationJob>("jobs").Where(j=>IsActive(j.State)))
            Transition(interrupted,"INTERRUPTED_REVIEW_REQUIRED","Service restarted during an operation. No write has been replayed; inspect backup and current GPO before continuing.");
        await foreach(var item in queue.Reader.ReadAllAsync(stoppingToken))
        {
            var job=store.Require<RemediationJob>("jobs",item.Id);
            try
            {
                if(item.Operation=="APPLY") await ApplyAsync(job,stoppingToken);
                else if(item.Operation is "ROLLBACK" or "VERIFY_ROLLBACK") await RollbackAsync(job,item.Operation=="VERIFY_ROLLBACK",stoppingToken);
                else await VerifyAsync(job,false,stoppingToken);
            }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested)
            { Transition(store.Require<RemediationJob>("jobs",job.Id),"INTERRUPTED_REVIEW_REQUIRED","Service stopped. Review the recorded operation before continuing."); }
            catch(Exception ex)
            {
                var current=store.Require<RemediationJob>("jobs",job.Id);
                var code=ex is PolicyException pe?pe.Code:"OPERATION_ERROR";
                var safe=Redactor.Clean(ex.Message);
                logger.LogWarning("Remediation {JobId} stopped at {State}: {Code}",job.Id,current.State,code);
                var state=item.Operation.Contains("ROLLBACK")?"FAILED_ROLLBACK":current.State switch
                {
                    "CREATED" or "PREFLIGHT"=>"FAILED_PREFLIGHT","IMPACT_ANALYZED" or "BACKING_UP"=>"FAILED_BACKUP",
                    "APPLYING"=>"FAILED_APPLY","GPO_WRITE_VERIFIED"=>"FAILED_SCOPE_VERIFY",
                    "POLICY_REFRESH_PENDING"=>"FAILED_GPUPDATE","RSOP_VERIFYING"=>"FAILED_RSOP_VERIFY",
                    "ENDPOINT_VERIFYING"=>"FAILED_ENDPOINT_VERIFY",_=>"FAILED_VERIFICATION"
                };
                Transition(current,state,$"{code}: {safe}",true);
            }
        }
    }
    private RemediationJob Transition(RemediationJob job,string state,string message,bool error=false)
    {
        var next=job with{State=state,UpdatedAt=PolicyValues.Now(),Error=error?Redactor.Clean(message):null};
        store.Put("jobs",job.Id,next,state); store.Step(job.Id,state,message);
        store.Audit(state,job.Operator,job.Id,job.ControlId,job.GpoId,new{message=Redactor.Clean(message)}); return next;
    }
    private async Task ApplyAsync(RemediationJob job,CancellationToken ct)
    {
        var plan=Plan(job.FindingId,job.PreviewId); var (_,control,target)=Context(job.FindingId);
        var adapter=adapters.Get(control,target);
        job=Transition(job,"PREFLIGHT","Validating modules, identity, approval, scope, and preview freshness.");
        var permission=await RevalidateAsync(plan,control,ct);
        store.Audit("PERMISSION_VALIDATED",job.Operator,job.Id,control.Id,job.GpoId,permission);
        job=Transition(job,"IMPACT_ANALYZED","Impact rechecked against the current GPO; operator acknowledgement recorded.");
        var gpo=await provider.EnsureGpoAsync(plan,ct);
        if(plan.Selection.Strategy=="CREATE") store.Audit("DEDICATED_GPO_CREATED",job.Operator,job.Id,control.Id,gpo.Id,new{gpo.Name,scope=plan.Target.Ou});
        job=Transition(job,"BACKING_UP","Creating a complete rollback snapshot before policy modification.");
        var backup=await provider.BackupAsync(job.Id,plan.Target,control,gpo,job.Operator,ct);
        if(string.IsNullOrEmpty(backup.ProviderData)) throw new PolicyException("BACKUP_FAILED","Provider returned no restorable backup information.");
        store.Put("backups",backup.Id,backup); job=job with{BackupId=backup.Id}; store.Put("jobs",job.Id,job,job.State);
        store.Audit("GPO_BACKUP_CREATED",job.Operator,job.Id,control.Id,gpo.Id,new{backup.Id,backup.CreatedAt,backup.PreviousValue});
        job=Transition(job,"APPLYING","Applying the selected policy adapter using the approved execution identity.");
        MarkUnknown(job);
        await adapter.ApplyAsync(provider,gpo,control,ct);
        store.Audit("GPO_MODIFIED",job.Operator,job.Id,control.Id,gpo.Id,new{control.PolicyType,value=control.ExpectedValue});
        var post=await provider.PreviewAsync(job.FindingId,plan.Target,control,new("EXISTING",gpo.Id),ct);
        backup=backup with{PostWriteVersion=post.Gpo.Version}; store.Put("backups",backup.Id,backup);
        await VerifyAsync(job,true,ct);
    }
    private async Task<VerificationResult> CheckAsync(RemediationJob job,string stage,Func<Task<VerificationResult>> check,CancellationToken ct,int maxAttempts=3)
    {
        VerificationResult result=new(false,"UNAVAILABLE","No verification result.",[]);
        for(var attempt=1;attempt<=maxAttempts;attempt++)
        {
            result=await check(); store.Verification(job.Id,stage,result);
            store.Audit(stage,job.Operator,job.Id,job.ControlId,job.GpoId,new{attempt,result});
            if(result.Success||!result.Retryable) break;
            if(attempt<maxAttempts) await Task.Delay(provider.Mode=="MOCK"?50:3000,ct);
        }
        return result;
    }
    private bool VerifiedOrStop(ref RemediationJob job,VerificationResult result,string failedState)
    {
        if(result.Success) return true;
        job=Transition(job,result.Retryable?"CHANGE_APPLIED_VERIFICATION_PENDING":failedState,$"{result.Code}: {result.Message}",!result.Retryable); return false;
    }
    private async Task VerifyAsync(RemediationJob job,bool initial,CancellationToken ct)
    {
        var plan=store.Require<ImpactAnalysis>("previews",job.PreviewId); var (_,control,target)=Context(job.FindingId); var gpo=plan.Gpo;
        var result=await CheckAsync(job,"GPO_VERIFICATION",()=>provider.VerifyGpoAsync(gpo,control,control.ExpectedValue,ct),ct);
        if(!VerifiedOrStop(ref job,result,"FAILED_GPO_VERIFY")) return;
        job=Transition(job,"GPO_WRITE_VERIFIED","GPO read-back contains the exact intended value.");
        result=await CheckAsync(job,"SCOPE_VERIFICATION",()=>provider.VerifyScopeAsync(gpo,target,ct),ct);
        if(!VerifiedOrStop(ref job,result,"FAILED_SCOPE_VERIFY")) return;
        job=Transition(job,"GPO_SCOPE_VERIFIED","Selected GPO link and filtering remain valid for the reviewed scope.");
        if(initial&&!job.Options.RunGpUpdate)
        { Transition(job,"CHANGE_APPLIED_VERIFICATION_PENDING","Policy refresh was deferred by the operator. Use Verify to refresh and check effective policy later."); return; }
        job=Transition(job,"POLICY_REFRESH_PENDING","Requesting bounded computer policy refresh.");
        result=await CheckAsync(job,"POLICY_REFRESH",()=>provider.RefreshAsync(target,ct),ct);
        if(!VerifiedOrStop(ref job,result,"FAILED_GPUPDATE")) return;
        job=Transition(job,"POLICY_REFRESHED","Computer policy refresh completed; effective values still require verification.");
        if(control.RequiresRestart==RestartRequirement.REQUIRED)
        {
            if(initial&&!job.Options.AuthorizeRestart)
            { Transition(job,"CHANGE_APPLIED_RESTART_REQUIRED","A restart is required. No reboot was authorized. Restart through your change process, then Verify."); return; }
            if(initial&&job.Options.AuthorizeRestart)
            {
                job=Transition(job,"RESTARTING","Operator explicitly authorized an endpoint restart.");
                result=await CheckAsync(job,"RESTART_REQUEST",()=>provider.RestartAsync(target,ct),ct,maxAttempts:1);
                if(!VerifiedOrStop(ref job,result,"FAILED_RESTART")) return;
            }
        }
        job=Transition(job,"RSOP_VERIFYING","Reading effective Group Policy and checking the intended result.");
        result=await CheckAsync(job,"RSOP_VERIFICATION",()=>provider.VerifyRsopAsync(target,gpo,control,control.ExpectedValue,ct),ct);
        if(!VerifiedOrStop(ref job,result,"FAILED_RSOP_VERIFY")) return;
        job=Transition(job,"ENDPOINT_VERIFYING","Independently reading the endpoint policy and evaluating the benchmark.");
        result=await CheckAsync(job,"ENDPOINT_VERIFICATION",()=>provider.VerifyEndpointAsync(target,control,control.ExpectedValue,ct),ct);
        if(!VerifiedOrStop(ref job,result,"FAILED_ENDPOINT_VERIFY")) return;
        if(!PolicyValues.Equal(result.ActualValue,control.ExpectedValue,control.PolicyType))
        { Transition(job,"FAILED_ENDPOINT_VERIFY","Benchmark evaluator rejected the observed value despite provider success.",true); return; }
        var finding=store.Require<Finding>("findings",job.FindingId);
        store.Put("findings",finding.Id,finding with{CurrentValue=result.ActualValue,Status="PASS"},"PASS");
        Transition(job,"COMPLIANT","GPO, scope, policy refresh, RSoP, endpoint, and benchmark evaluation all passed.");
    }
    private async Task RollbackAsync(RemediationJob job,bool verificationOnly,CancellationToken ct)
    {
        var backup=store.Require<GpoBackup>("backups",job.BackupId!); var (_,control,target)=Context(job.FindingId);
        var plan=store.Require<ImpactAnalysis>("previews",job.PreviewId);
        if(!verificationOnly)
        {
            job=Transition(job,"ROLLING_BACK","Checking for concurrent changes before restoring the complete recorded GPO snapshot.");
            var preflight=await provider.PreflightAsync(target,plan.Gpo,ct);
            if(!preflight.CanRead||!preflight.CanEdit||!preflight.CanVerify) throw new PolicyException("PREFLIGHT_DENIED","Rollback identity lacks read, edit, or verification capability.");
            var scopeBefore=await provider.VerifyScopeAsync(plan.Gpo,target,ct);
            if(!scopeBefore.Success) throw new PolicyException("ROLLBACK_SCOPE_CHANGED","The reviewed GPO scope or filtering changed. Generate and approve a separate recovery plan before restoring this backup.");
            var current=await provider.PreviewAsync(job.FindingId,target,control,new("EXISTING",plan.Gpo.Id),ct);
            var recovery=await provider.BackupAsync(job.Id,target,control,current.Gpo,job.Operator,ct);
            store.Put("backups",recovery.Id,recovery); store.Audit("ROLLBACK_SAFETY_BACKUP",job.Operator,job.Id,job.ControlId,job.GpoId,new{recovery.Id});
            MarkUnknown(job);
            await provider.RestoreAsync(backup,control,ct);
        }
        var result=await CheckAsync(job,"ROLLBACK_GPO_VERIFICATION",()=>provider.VerifyRollbackAsync(backup,control,ct),ct);
        if(!result.Success) { Transition(job,"FAILED_ROLLBACK",result.Message,true); return; }
        job=Transition(job,"ROLLBACK_GPO_VERIFIED","Restored GPO independently matches the recorded backup.");
        result=await CheckAsync(job,"ROLLBACK_SCOPE_VERIFICATION",()=>provider.VerifyScopeAsync(plan.Gpo,target,ct),ct);
        if(!result.Success) { Transition(job,"ROLLBACK_VERIFICATION_PENDING",result.Message); return; }
        result=await CheckAsync(job,"ROLLBACK_REFRESH",()=>provider.RefreshAsync(target,ct),ct);
        if(!result.Success) { Transition(job,"ROLLBACK_VERIFICATION_PENDING",result.Message); return; }
        if(control.RequiresRestart==RestartRequirement.REQUIRED&&!verificationOnly)
        { MarkUnknown(job); Transition(job,"ROLLBACK_VERIFICATION_PENDING","GPO restored. Restart may be required; restart through change management, then retry rollback verification. No automatic reboot."); return; }
        var expected=backup.EndpointPreviousValue??backup.PreviousValue;
        result=await CheckAsync(job,"ROLLBACK_ENDPOINT_VERIFICATION",()=>provider.VerifyEndpointAsync(target,control,expected,ct),ct);
        if(!result.Success||!PolicyValues.Equal(result.ActualValue,expected,control.PolicyType))
        { MarkUnknown(job); Transition(job,"ROLLBACK_VERIFICATION_PENDING","GPO restored, but original effective endpoint state has not been verified."); return; }
        var finding=store.Require<Finding>("findings",job.FindingId);
        var status=PolicyValues.Equal(result.ActualValue,control.ExpectedValue,control.PolicyType)?"PASS":"FAIL";
        store.Put("findings",finding.Id,finding with{CurrentValue=result.ActualValue,Status=status},status);
        Transition(job,"ROLLED_BACK","GPO backup restored, scope checked, policy refreshed, and previous endpoint state independently verified.");
    }
    private void MarkUnknown(RemediationJob job)
    { var finding=store.Require<Finding>("findings",job.FindingId); store.Put("findings",finding.Id,finding with{Status="UNKNOWN"},"UNKNOWN"); }
}
