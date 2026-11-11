using System.Collections.Concurrent;
using System.Threading.Channels;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;

namespace GpoRemediator.Services;

// Durable records contain approvals and results, never session cookies or passwords.
// Process termination recovers writes for review; no privileged work is replayed.
public sealed class WorkspaceWorkflows(Store store,IWorkflowOperations service,OperationGate gate,ILogger<WorkspaceWorkflows> logger,TimeProvider clock) : BackgroundService
{
    private sealed record Work(string Id,string Token,string? Resource);
    private const int QueueCapacity=16;
    private readonly Channel<Work> queue=Channel.CreateBounded<Work>(new BoundedChannelOptions(QueueCapacity){SingleReader=true,FullMode=BoundedChannelFullMode.Wait});
    private readonly object sync=new();
    private readonly ConcurrentDictionary<string,Task> schedules=new();
    private CancellationToken stopping;
    public WorkflowJob[] List(string actor)=>store.List<WorkflowJob>("workflow_jobs").Where(x=>x.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase)).Take(200).ToArray();
    public BatchPlan[] Batches(string actor)=>store.List<BatchPlan>("batch_plans").Where(x=>x.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase)).Take(100).ToArray();
    public WorkflowJob Get(string id,string actor){var job=store.Require<WorkflowJob>("workflow_jobs",id);if(!job.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase))throw new PolicyException("NOT_FOUND","Workflow not found.");return job;}
    private GpoWorkflowPlan Plan(string id,string actor){var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);if(!plan.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase))throw new PolicyException("NOT_FOUND","Plan not found.");return plan;}
    private void Save(WorkflowJob job)=>store.Put("workflow_jobs",job.Id,job,job.State);
    private WorkflowJob Update(string id,Func<WorkflowJob,WorkflowJob> change){lock(sync){var job=change(store.Require<WorkflowJob>("workflow_jobs",id)) with{UpdatedAt=PolicyValues.Now()};Save(job);return job;}}
    private WorkflowJob Enqueue(WorkflowJob job,string token,string? resource){
        lock(sync){
            var existing=store.Get<WorkflowJob>("workflow_jobs",job.Id);
            if(existing is not null){if(existing.Actor!=job.Actor||existing.RequestHash!=job.RequestHash)throw new PolicyException("IDEMPOTENCY_CONFLICT","Request ID was already used with a different payload.");return existing;}
            if(stopping.IsCancellationRequested||List(job.Actor).Count(x=>WorkspaceRules.Active(x.State)||x.State=="VERIFY_SCHEDULED")>=4)throw new PolicyException("GPO_CONNECTION_LIMIT","At most four unfinished workflows per operator are permitted.");
            if(queue.Reader.Count>=QueueCapacity)throw new PolicyException("GPO_CONNECTION_LIMIT","The workflow queue is full.");
            if(resource is not null)gate.Reserve(resource,job.Id);
            try{
                // Producers hold sync and the reader can only free slots.
                // Commit the receipt and its audit event before releasing work.
                store.AcceptWorkflow(job);
                if(!queue.Writer.TryWrite(new Work(job.Id,token,resource)))
                    throw new InvalidOperationException("The workflow queue unexpectedly closed.");
            }catch{if(resource is not null)gate.Release(resource,job.Id);throw;}
            return job;
        }
    }
    private static string JobId(string requestId,string actor){if(!Guid.TryParse(requestId,out var guid))throw new PolicyException("INVALID_REQUEST","Request ID must be a GUID.");return PolicyValues.Hash(actor.ToUpperInvariant()+":"+guid.ToString("D"))[..32];}
    private WorkflowJob New(string requestId,string actor,string action,object payload)=>new(JobId(requestId,actor),actor,action,"QUEUED",PolicyValues.Now(),PolicyValues.Now(),[],[],"None",[],new(""),PolicyValues.Hash(payload),"Accepted by the server; inspect this workflow after reconnecting.");
    public WorkflowJob Preview(string requestId,BatchPreviewRequest request,string token,string actor){
        service.ValidateConnection(token,actor);
        var selections=request.Selections??[];
        if(selections.Length is <1 or >20||selections.Select(x=>x.Setting).Distinct().Count()!=selections.Length)throw new PolicyException("INVALID_REQUEST","Select 1–20 distinct controls per batch.");
        if(selections.Any(x=>!Guid.TryParse(x.GpoId,out _)||!x.GpoId.Equals(selections[0].GpoId,StringComparison.OrdinalIgnoreCase)||!x.ScopeDn.Equals(selections[0].ScopeDn,StringComparison.OrdinalIgnoreCase)))throw new PolicyException("INVALID_REQUEST","A batch uses one GPO and one scope.");
        if(request.PilotSourceId is not null){
            var pilot=Get(request.PilotSourceId,actor);var source=store.Require<BatchPlan>("batch_plans",pilot.BatchId??"");
            var runs=pilot.CompletedIds.Select(id=>store.Require<GpoWorkflowRun>("gpo_runs",id)).ToArray();
            if(!source.Pilot||pilot.Action!="apply"||pilot.State!="COMPLETED"||runs.Length==0||runs.Any(run=>!WorkspaceRules.Published(run)||!GpoAssurance.EffectiveVerified(run.Result)||run.Result.EffectiveStatus is not ("VERIFIED_ON_SAMPLE" or "VERIFIED_ON_ALL_TARGETS")||
                !DateTimeOffset.TryParse(run.Result.Verification?.CheckedAt,out var checkedAt)||DateTimeOffset.UtcNow-checkedAt>TimeSpan.FromMinutes(30)))
                throw new PolicyException("PILOT_NOT_VERIFIED","Promotion requires a completed pilot with replication convergence and effective sample verification for every applied control.");
            if(!selections.Select(x=>x.Setting).Order().SequenceEqual(runs.Select(x=>x.Plan.Selection.Setting).Order()))throw new PolicyException("PILOT_CONTROL_MISMATCH","Promotion must preview the same control set as the verified pilot.");
            if(selections.Any(selection=>{
                var mapping=ProductionGpoMappings.Effective(selection);var original=runs.Single(run=>run.Plan.Selection.Setting==selection.Setting).Plan;
                return mapping.DesiredDisplay(selection)!=ProductionGpoMappings.Effective(original.Selection).DesiredDisplay(original.Selection)||original.MappingHash is not null&&original.MappingHash!=PolicyValues.Hash(mapping);
            }))throw new PolicyException("PILOT_VALUE_MISMATCH","Promotion must use the same policy values and mapping as the verified pilot; different values require a new pilot.");
        }
        var job=New(requestId,actor,"preview",new{requestId,request}) with{Selections=selections,BatchId=Guid.NewGuid().ToString("N"),Pilot=request.Pilot,PilotLimit=request.PilotLimit,PilotSourceId=request.PilotSourceId};
        return Enqueue(job,token,null);
    }
    public WorkflowJob Scan(ScanRequest request,string token,string actor){
        service.ValidateConnection(token,actor);
        var controls=request.Controls??[];
        if(controls.Length is <1 or >405||controls.Distinct().Count()!=controls.Length||controls.Any(id=>!ProductionGpoMappings.Settings.Any(x=>x.Id==id)))throw new PolicyException("INVALID_REQUEST","Select 1–405 distinct known controls.");
        return Enqueue(New(request.RequestId,actor,"scan",request) with{ScanTarget=request.Target,ScanControls=controls,ScanRows=[]},token,null);
    }
    public WorkflowJob Start(string action,WorkflowRequest request,string token,string actor){
        if(action is not ("apply" or "rollback" or "verify" or "refresh"))throw new PolicyException("INVALID_REQUEST","Unknown workflow action.");
        var automatic=request.Refresh=="Auto"&&(action=="apply"&&request.BatchId is not null||action=="rollback"&&request.SourceWorkflowId is not null);
        if(!automatic&&request.Refresh is not ("None" or "Pdc" or "Scope")||action=="refresh"&&request.Refresh=="None")throw new PolicyException("INVALID_REQUEST","Choose None, Pdc or Scope; Auto is reserved for a reviewed batch.");
        var schedule=request.VerificationDelays??[];WorkspaceRules.ValidateSchedule(schedule);
        var id=JobId(request.RequestId,actor);var hash=PolicyValues.Hash(new{action,request});
        lock(sync){var existing=store.Get<WorkflowJob>("workflow_jobs",id);if(existing is not null){if(existing.Actor!=actor||existing.RequestHash!=hash)throw new PolicyException("IDEMPOTENCY_CONFLICT","Request ID was already used.");return existing;}}
        var ids=request.PlanIds??[];
        if(action=="rollback"&&request.SourceWorkflowId is not null){
            var source=Get(request.SourceWorkflowId,actor);
            if(source.Action!="apply"||WorkspaceRules.Active(source.State)||source.State=="VERIFY_SCHEDULED"||source.CompletedIds.Length==0)throw new PolicyException("ROLLBACK_NOT_AVAILABLE","Select a finished apply workflow with completed backups.");
            if(List(actor).Any(x=>x.Action=="rollback"&&x.SourceWorkflowId==source.Id&&x.State is "QUEUED" or "RUNNING" or "VERIFY_SCHEDULED"))throw new PolicyException("ROLLBACK_NOT_AVAILABLE","This batch recovery is still active; wait for it to finish before submitting another restore.");
            ids=[BatchRecovery.Resolve(store,source,null).Target];
        }
        if(ids.Length is <1 or >20||ids.Distinct().Count()!=ids.Length)throw new PolicyException("INVALID_REQUEST","Select 1–20 distinct plans.");
        if(request.SourceWorkflowId is not null&&action!="rollback")throw new PolicyException("INVALID_REQUEST","A recovery source is only valid for rollback.");
        if(ids.Length>1&&action is not ("apply" or "verify"))throw new PolicyException("INVALID_REQUEST","Use the batch recovery source for full-GPO rollback.");
        // The workflow refresh field is authoritative at both submission and execution.
        var executionConsent=request.Consent with{Refresh=request.Refresh};
        var plans=ids.Select(op=>service.ValidateSubmission(op,action,executionConsent with{Refresh=BatchWorkflowRules.Refresh(Plan(op,actor),request.Refresh)},token,actor)).ToArray();
        if(action=="rollback"&&request.SourceWorkflowId is null&&BatchRecovery.Source(store,actor,ids[0]) is {} member)
            BatchRecovery.Resolve(store,member,ids[0]);
        if(action=="apply")foreach(var plan in plans)BatchWorkflowRules.ValidateConflicts(plan);
        if(action=="apply"&&request.Refresh!="None")foreach(var plan in plans){
            var strategy=BatchWorkflowRules.Refresh(plan,request.Refresh);var mapping=ProductionGpoMappings.Effective(plan.Selection);
            ProductionGpoMappings.ValidateRefresh(mapping,strategy);
            if(mapping.Scope=="User"&&strategy=="Scope"&&string.IsNullOrWhiteSpace(plan.Selection.EndpointScopeDn))throw new PolicyException("ENDPOINT_SCOPE_REQUIRED","Select a computer OU for user-session refresh before approving this batch.");
        }
        if(plans.Any(p=>p.Selection.GpoId!=plans[0].Selection.GpoId||p.Selection.ScopeDn!=plans[0].Selection.ScopeDn))throw new PolicyException("INVALID_REQUEST","One workflow must use one GPO/scope.");
        if(action=="apply"&&ids.Length>1&&request.BatchId is null)throw new PolicyException("BATCH_REQUIRED","Apply the reviewed batch preview.");
        if(request.BatchId is not null){
            var batch=store.Require<BatchPlan>("batch_plans",request.BatchId);
            if(batch.Actor!=actor||!batch.PlanIds.SequenceEqual(ids)||action!="apply")throw new PolicyException("BATCH_REQUIRED","The approved plans must match the complete reviewed batch in order.");
            if(batch.Pilot)foreach(var plan in plans)WorkspaceRules.ValidatePilot(plan,batch.PilotLimit);
            if(batch.Pilot&&request.Refresh=="Pdc")throw new PolicyException("PILOT_SCOPE_UNSAFE","Pilot refresh must remain within the authorized pilot OU; PDC refresh is not permitted.");
        }
        var job=New(request.RequestId,actor,action,new{action,request}) with{PlanIds=ids,Consent=executionConsent,Refresh=request.Refresh,VerificationDelays=schedule,BatchId=request.BatchId,SourceWorkflowId=request.SourceWorkflowId};
        return Enqueue(job,token,action=="verify"?null:Guid.Parse(plans[0].Selection.GpoId).ToString("D"));
    }
    public override Task StartAsync(CancellationToken cancellationToken){
        foreach(var job in store.List<WorkflowJob>("workflow_jobs").Where(x=>WorkspaceRules.Active(x.State)||x.State=="VERIFY_SCHEDULED")){
            Save(job with{State=job.Action is "scan" or "preview"||job.State=="VERIFY_SCHEDULED"?"WAITING_CONNECTION":"NEEDS_REVIEW",NextCheckAt=null,UpdatedAt=PolicyValues.Now(),Message="Service restarted. No write was replayed. Reconnect and verify recorded results before starting a new approved workflow."});
        }
        return base.StartAsync(cancellationToken);
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken){
        stopping=stoppingToken;
        try{await foreach(var work in queue.Reader.ReadAllAsync(stoppingToken)){
            // Synchronize with submission so the durable record exists before processing.
            lock(sync){}
            await Process(work,stoppingToken);
        }}catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){}
    }
    private async Task Process(Work work,CancellationToken ct){
        var job=Update(work.Id,j=>j with{State="RUNNING",StartedAt=PolicyValues.Now(),Message="Server workflow started."});
        try{
            if(job.Action=="preview"){
                await ProcessPreview(work,job,ct);return;
            }
            if(job.Action=="scan"){await ProcessScan(work,job,ct);return;}
            string? expected=null;
            var publishedFields=new Dictionary<string,GpoPolicyField>(StringComparer.OrdinalIgnoreCase);
            var refreshIncomplete=false;
            GpoRollbackAnchor? anchor=null;
            if(job.Action=="rollback"){
                var full=job.SourceWorkflowId is not null;
                var source=full?Get(job.SourceWorkflowId!,job.Actor):BatchRecovery.Source(store,job.Actor,job.PlanIds[0]);
                if(source is not null){
                    var recovery=BatchRecovery.Resolve(store,source,full?null:job.PlanIds[0]);
                    if(recovery.Target!=job.PlanIds[0])throw new PolicyException("BATCH_ROLLBACK_ORDER","The next recoverable snapshot changed. Review the batch again.");
                    anchor=recovery.Anchor;
                }
            }
            foreach(var originalId in job.PlanIds){
                ct.ThrowIfCancellationRequested();var plan=Plan(originalId,job.Actor);
                if(job.Action=="apply"&&expected is not null){
                    var fresh=await service.PreviewAsync(work.Token,job.Actor,plan.Selection,ct);
                    if(fresh.Preview.Fingerprint!=expected||!BatchWorkflowRules.CanRebase(plan.Preview,fresh.Preview,publishedFields))
                        throw new PolicyException("BATCH_DRIFT","The live GPO or a reviewed value changed outside the preceding batch step. Remaining writes were stopped.");
                    plan=fresh with{Preview=fresh.Preview with{RelatedConflicts=plan.Preview.RelatedConflicts}};
                    store.Put("gpo_plans",plan.Id,plan);
                }
                if(job.BatchId is not null){var batch=store.Require<BatchPlan>("batch_plans",job.BatchId);if(batch.Pilot)WorkspaceRules.ValidatePilot(plan,batch.PilotLimit);}
                job=Update(job.Id,j=>j with{CurrentOperationId=plan.Id});
                var result=await service.ExecuteAsync(plan.Id,job.Action,job.Consent with{Refresh=BatchWorkflowRules.Refresh(plan,job.Refresh)},work.Token,job.Actor,job.Id,anchor);
                job=Update(job.Id,j=>j with{CompletedIds=[..j.CompletedIds,plan.Id],Message=result.Result.Message});
                if(job.Action=="apply"&&!WorkspaceRules.Published(result)||job.Action=="rollback"&&result.Result.State!="ROLLED_BACK"||job.Action=="verify"&&result.Result.State is "REVIEW_REQUIRED" or "DRIFT_DETECTED" or "ROLLBACK_DRIFT_DETECTED")
                    throw new PolicyException("WORKFLOW_RESULT_REVIEW","A step requires review. Remaining writes and refresh were stopped.");
                if(job.Action=="refresh")refreshIncomplete|=InspectRefresh(result.Result);
                if(job.Action=="apply")foreach(var field in plan.Preview.Fields??[])publishedFields[field.Address]=field;
                expected=result.Result.PostFingerprint??plan.Preview.Fingerprint;
            }
            if(job.SourceWorkflowId is not null){
                var source=Get(job.SourceWorkflowId,job.Actor);
                foreach(var op in source.CompletedIds.Where(id=>id!=job.CompletedIds[0])){
                    var run=store.Require<GpoWorkflowRun>("gpo_runs",op);
                    if(run.BatchStepRestored||run.Result.State is "ROLLED_BACK" or "BATCH_ROLLED_BACK")continue;
                    store.Put("gpo_runs",op,run with{UpdatedAt=PolicyValues.Now(),Result=run.Result with{State="BATCH_ROLLED_BACK",Message="Restored through the batch's first full-GPO snapshot. Inspect recovery workflow "+job.Id,EffectiveStatus="ROLLBACK_ENDPOINT_PENDING",
                        GpoPublished=false,LinkVerified=false,CurrentValue=null,CurrentValueSource=null,CurrentLink=null,DomainPolicy=null,Verification=null,EndpointChecks=[],RefreshResults=[],RestoreChecks=null}},"BATCH_ROLLED_BACK");
                }
            }
            // Refresh follows only the explicit approval and a verified successful mutation.
            if(job.Refresh!="None"&&job.Action is "apply" or "rollback"){
                var candidates=job.Action=="rollback"&&anchor?.BatchPlans is {} saved?saved:job.CompletedIds.Select(op=>Plan(op,job.Actor)).ToArray();
                var groups=job.Refresh=="Auto"||candidates.Length>1?BatchWorkflowRules.RefreshGroups(candidates,job.Refresh):[candidates[^1]];
                var combined=new List<GpoRefreshResult>();
                foreach(var target in groups){
                    var refreshId=job.Action=="rollback"?job.CompletedIds[0]:target.Id;
                    var refreshAnchor=job.Action=="rollback"&&(job.Refresh=="Auto"||groups.Length>1)?anchor! with{RefreshPlan=target}:null;
                    var refreshed=await service.ExecuteAsync(refreshId,"refresh",new("",Refresh:BatchWorkflowRules.Refresh(target,job.Refresh)),work.Token,job.Actor,job.Id,refreshAnchor);
                    combined.AddRange(refreshed.Result.RefreshResults);
                    if(job.Action=="rollback"&&groups.Length>1){
                        static string State(IEnumerable<string> states)=>states.Contains("FAILED")?"FAILED":states.All(s=>s=="COMPLETED")?"COMPLETED":"SCHEDULED";
                        static string? Half(IEnumerable<string?> states){var known=states.OfType<string>().ToArray();return known.Length==0?null:State(known);}
                        var merged=combined.GroupBy(r=>r.Computer,StringComparer.OrdinalIgnoreCase).Select(g=>new GpoRefreshResult(g.Key,State(g.Select(r=>r.State)),string.Join(" | ",g.Select(r=>r.Message)),Half(g.Select(r=>r.ComputerState)),Half(g.Select(r=>r.UserState)))).ToArray();
                        store.Put("gpo_runs",refreshId,refreshed with{Result=refreshed.Result with{RefreshResults=merged,RefreshCoverage=new(merged.Length,merged.Length,target.Id==groups[^1].Id)}},refreshed.Result.State);
                    }
                    refreshIncomplete|=InspectRefresh(refreshed.Result);
                }
            }
            var effectivePending=false;
            var restoredSnapshot=false;
            var endpointMismatches=new List<string>();
            if(job.Action is "apply" or "refresh" or "verify" or "rollback"){
                foreach(var id in job.CompletedIds){
                    var measured=job.Action=="verify"?store.Require<GpoWorkflowRun>("gpo_runs",id):
                        await service.ExecuteAsync(id,"verify",new(""),work.Token,job.Actor,job.Id);
                    if(measured.Result.State=="ROLLED_BACK"){
                        restoredSnapshot=true;
                        if((measured.Result.EndpointChecks??[]).Any(x=>x.State=="RESTORE_MISMATCH"))
                            endpointMismatches.Add(measured.Plan.Selection.Setting);
                        effectivePending|=job.SourceWorkflowId is not null || !GpoAssurance.RestoredValuesVerified(measured.Result);
                        continue;
                    }
                    if(job.Action=="rollback")
                        throw new PolicyException("ROLLBACK_REVIEW_REQUIRED","The saved snapshot could not be confirmed on re-verification.");
                    if(HasEndpointMismatch(measured))endpointMismatches.Add(measured.Plan.Selection.Setting);
                    effectivePending|=!GpoAssurance.EffectiveVerified(measured.Result);
                }
            }
            if(refreshIncomplete)
            {
                var mismatches=endpointMismatches.Count==0?"":$" Endpoint values differ for controls {string.Join(", ",endpointMismatches)}.";
                throw new PolicyException("REFRESH_REVIEW_REQUIRED","Refresh did not finish or schedule on every target. Inspect the per-host refresh and verification results."+mismatches);
            }
            if(job.VerificationDelays.Length==0){
                RequireMatchingEndpoints(endpointMismatches,restoredSnapshot);
            }
            if(job.VerificationDelays.Length>0){
                job=Update(job.Id,j=>j with{State="VERIFY_SCHEDULED",NextCheckAt=DateTimeOffset.UtcNow.AddSeconds(j.VerificationDelays[0]).ToString("O"),Message="Publication/restore completed. Read-only follow-up verification is scheduled."});
                var scheduleTask=VerifyLater(work,job,ct);schedules[job.Id]=scheduleTask;
                _=scheduleTask.ContinueWith(_=>schedules.TryRemove(job.Id,out var removed),TaskScheduler.Default);
            }else Finish(job.Id,effectivePending?"CHECKS_INCOMPLETE":"COMPLETED",effectivePending?
                restoredSnapshot?"GPO snapshot restored. Endpoint rollback verification is incomplete. Inspect the per-host readings and replication.":"GPO operation recorded, but effective endpoint application is not verified. Inspect endpoint values and replication; refresh or re-verify after policy processing.":
                restoredSnapshot?"GPO snapshot and the recorded restore values match. Inspect the verification scope and readings.":"Server workflow finished. Inspect publication, replication and endpoint evidence separately.");
        }catch(OperationCanceledException)when(ct.IsCancellationRequested){Finish(job.Id,"WAITING_CONNECTION","Service stopping. No remaining step will be replayed automatically.");}
        catch(Exception error){FailJob(job.Id,error);}
        finally{if(work.Resource is not null)gate.Release(work.Resource,job.Id);}
    }
    private async Task ProcessPreview(Work work,WorkflowJob job,CancellationToken ct){
        var plans=new List<GpoWorkflowPlan>();
        foreach(var selection in job.Selections??[]){
             var plan=await service.PreviewAsync(work.Token,job.Actor,selection,ct);
            if(job.Pilot)WorkspaceRules.ValidatePilot(plan,job.PilotLimit);
            if(plans.Count>0&&plans[0].Preview.Fingerprint!=plan.Preview.Fingerprint)throw new PolicyException("BATCH_DRIFT","The GPO changed during preview; generate a new batch.");
            plans.Add(plan);job=Update(job.Id,j=>j with{CompletedIds=plans.Select(x=>x.Id).ToArray(),Message=$"Read-only preview: {plans.Count}/{job.Selections!.Length}"});
        }
        var ordered=BatchWorkflowRules.CheckSharedFields(BatchWorkflowRules.Order(plans.ToArray()));
        foreach(var plan in ordered){store.Put("gpo_plans",plan.Id,plan);}
        Update(job.Id,j=>j with{CompletedIds=ordered.Select(plan=>plan.Id).ToArray()});
        var batch=new BatchPlan(job.BatchId!,job.Actor,PolicyValues.Now(),ordered.Select(x=>x.Id).ToArray(),job.Pilot,job.PilotLimit,job.PilotSourceId);store.Put("batch_plans",batch.Id,batch,"READY");
        Finish(job.Id,"COMPLETED","Batch preview ready. Review every value, link and scope before separately approving Apply.");
    }
    private async Task ProcessScan(Work work,WorkflowJob job,CancellationToken ct){
        var rows=new List<ScanRow>();
        foreach(var control in job.ScanControls??[]){
            ct.ThrowIfCancellationRequested();var original=ProductionGpoMappings.Require(control);
            var domainAccount=original.DomainPolicySensitive&&job.ScanTarget!.AccountScope=="Domain";
            var selection=job.ScanTarget! with{Setting=control,Value=original.Suggested??0,Refresh="None",AccountScope=domainAccount?"Domain":original.Scope=="User"?"Users":"LocalComputers",FirstLink=domainAccount,CustomValue=null,ItemValues=null,ReviewContext=null};
            var mapping=ProductionGpoMappings.Effective(selection);
            try{
                if(!mapping.Writable||mapping.RequiresInput||mapping.Scope=="User")rows.Add(new(control,"NOT_CHECKED",null,null,"Manual, user-session targeting or organization-specific input requires individual review; no compliance claim was made.",PolicyValues.Now()));
                else{
                    var plan=await service.PreviewAsync(work.Token,job.Actor,selection,ct,requireWriteAccess:false);
                    rows.Add(new(control,plan.Preview.NoChange?"GPO_MATCH":"DIFFERENT",plan.Preview.PreviousValue,plan.Preview.DesiredValue,"Read-only GPO content/link comparison; effective endpoint compliance is not inferred.",PolicyValues.Now(),plan.Id,plan.Preview.PreviousValueSource));
                }
            }catch(PolicyException error){if(error.Code=="GPO_LOGIN_REQUIRED")throw;rows.Add(new(control,"NOT_CHECKED",null,null,error.Code,PolicyValues.Now()));}
            Update(job.Id,j=>j with{ScanRows=rows.ToArray(),Message=$"Read-only scan: {rows.Count}/{job.ScanControls!.Length}"});
        }
        Finish(job.Id,"COMPLETED","Read-only scan completed. NOT_CHECKED controls are not compliant results.");
    }
    private async Task VerifyLater(Work work,WorkflowJob job,CancellationToken ct){
        try{
            var start=clock.GetUtcNow();
            var skipped=false;var effectivePending=false;var restoredSnapshot=false;
            foreach(var seconds in job.VerificationDelays){
                effectivePending=false;
                restoredSnapshot=false;
                var endpointMismatches=new List<string>();
                var due=start.AddSeconds(seconds);Update(job.Id,j=>j with{NextCheckAt=due.ToString("O")});
                var delay=due-clock.GetUtcNow();if(delay>TimeSpan.Zero)await Task.Delay(delay,clock,ct);
                foreach(var id in job.CompletedIds){
                    ct.ThrowIfCancellationRequested();
                    Update(job.Id,j=>j with{CurrentOperationId=id});
                    GpoWorkflowRun run;
                    try{run=await service.ExecuteAsync(id,"verify",new(""),work.Token,job.Actor);}
                    catch(PolicyException error)when(error.Code is "GPO_OPERATION_BUSY" or "SERVICE_STOPPING"){
                        skipped=true;Update(job.Id,j=>j with{Message="A read-only check was skipped while the GPO/service was busy. The remaining scheduled checks are retained."});continue;
                    }
                    if(run.Result.State is "REVIEW_REQUIRED" or "DRIFT_DETECTED" or "ROLLBACK_DRIFT_DETECTED")throw new PolicyException("FOLLOWUP_DRIFT","Follow-up detected drift or an ambiguous result; inspect recovery.");
                    if(run.Result.State=="ROLLED_BACK"){
                        restoredSnapshot=true;
                        if((run.Result.EndpointChecks??[]).Any(x=>x.State=="RESTORE_MISMATCH"))
                            endpointMismatches.Add(run.Plan.Selection.Setting);
                        effectivePending|=job.SourceWorkflowId is not null || !GpoAssurance.RestoredValuesVerified(run.Result);
                        continue;
                    }
                    if(HasEndpointMismatch(run))endpointMismatches.Add(run.Plan.Selection.Setting);
                    effectivePending|=!GpoAssurance.EffectiveVerified(run.Result);
                }
                if(seconds==job.VerificationDelays[^1])RequireMatchingEndpoints(endpointMismatches,restoredSnapshot);
                Update(job.Id,j=>j with{Message="Read-only follow-up completed at "+PolicyValues.Now()});
            }
            Finish(job.Id,skipped||effectivePending?"CHECKS_INCOMPLETE":"COMPLETED",skipped?"One or more scheduled checks were skipped while busy. Submit read-only Verify after the current GPO operation finishes.":effectivePending?restoredSnapshot?"GPO snapshot restored. Scheduled checks did not establish endpoint rollback.":"Scheduled checks ended without verified endpoint application. Inspect the pending endpoint/replication evidence.":"Scheduled checks completed with verified effective values.");
        }catch(OperationCanceledException)when(ct.IsCancellationRequested){Finish(job.Id,"WAITING_CONNECTION","Follow-up interrupted by service shutdown. Reconnect and submit read-only verification.");}
        catch(Exception error){FailJob(job.Id,error);}
    }
    private static bool HasEndpointMismatch(GpoWorkflowRun run){
        if(run.Result.State is "REVIEW_REQUIRED" or "DRIFT_DETECTED" or "ROLLBACK_DRIFT_DETECTED")
            throw new PolicyException("WORKFLOW_RESULT_REVIEW","Verification found GPO drift or an uncertain outcome. Inspect the recorded evidence before retrying.");
        return run.Result.EffectiveStatus=="ENDPOINT_MISMATCH" || (run.Result.EndpointChecks??[]).Any(x=>x.State=="MISMATCH");
    }
    private static bool InspectRefresh(GpoWorkflowResult result)
    {
        if(result.State!="ROLLED_BACK" && (!result.GpoPublished || !result.LinkVerified ||
            result.State is "DRIFT_DETECTED" or "ROLLBACK_DRIFT_DETECTED" or "REVIEW_REQUIRED" or "FAILED_SAFE"))
            throw new PolicyException("REFRESH_REVIEW_REQUIRED","The live policy or restore state requires review. Remaining refresh steps were stopped.");
        return result.State=="REFRESH_PARTIAL" || result.RefreshResults.Length==0 || result.RefreshCoverage is {Complete:false} ||
            result.RefreshResults.Any(x=>x.State is not ("COMPLETED" or "SCHEDULED"));
    }
    private static void RequireMatchingEndpoints(List<string> controls,bool restoredSnapshot){
        if(restoredSnapshot&&controls.Count>0)
            throw new PolicyException("ROLLBACK_ENDPOINT_MISMATCH","The GPO snapshot was restored. Some endpoint values still differ from their recorded pre-change readings.");
        if(controls.Count>0)
            throw new PolicyException("ENDPOINT_POLICY_MISMATCH",$"Endpoint values differ from the request for controls {string.Join(", ",controls)}. Open each control's verification details for measured values and processing evidence.");
    }
    private void Finish(string id,string state,string message){var job=Update(id,j=>j with{State=state,Message=message,NextCheckAt=null,CurrentOperationId=null,FinishedAt=PolicyValues.Now()});store.Audit("WORKFLOW_"+state,job.Actor,jobId:id,details:new{job.Action,job.CompletedIds,job.Message});}
    private void FailJob(string id,Exception error){logger.LogWarning("Workflow {WorkflowId} failed with {Type}",id,error.GetType().Name);Finish(id,error is PolicyException {Code:"GPO_LOGIN_REQUIRED"}?"WAITING_CONNECTION":"NEEDS_REVIEW",error is PolicyException policy?policy.Code+": "+policy.Message:"Workflow interrupted. Inspect recorded results before retrying any write.");}
    public override async Task StopAsync(CancellationToken cancellationToken){await base.StopAsync(cancellationToken);try{await Task.WhenAll(schedules.Values).WaitAsync(cancellationToken);}catch(OperationCanceledException){}}
}
