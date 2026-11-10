using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

static void Check(bool value,string message){if(!value)throw new Exception(message);}
static void Reject(Action action,string code){try{action();throw new Exception("Expected "+code);}catch(PolicyException error){Check(error.Code==code,error.Code+" != "+code);}}
static async Task<WorkflowJob> Done(WorkspaceWorkflows jobs,string id){for(var i=0;i<600;i++){var job=jobs.Get(id,"TEST\\Admin");if(!WorkspaceRules.Active(job.State)&&job.State!="VERIFY_SCHEDULED")return job;await Task.Delay(10);}throw new Exception("Workflow did not finish");}
var phases=new List<string>();
var liveChecks=new List<GpoLiveCheck>();
var liveFrame=JsonSerializer.Serialize(new GpoLiveCheck("ENDPOINT","CHECKING","ws.example.test",null,"Reading effective policy.","untrusted-time"));
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("GPO_CHECK:"+liveFrame+"\nGPO_CHECK:{invalid}\nGPO_CHECK:"+liveFrame.Replace("CHECKING","FAKE_SUCCESS")+"\n{\"ok\":true}")))){
 var output=await WindowsPowerShellExecutor.ReadOutputAsync(reader,8192,CancellationToken.None,null,liveChecks.Add);
 Check(output=="{\"ok\":true}"&&liveChecks.Count==1&&liveChecks[0].State=="CHECKING"&&liveChecks[0].CheckedAt!="untrusted-time","Live evidence frames must be bounded, validated, timestamped and separate from the final response");
}
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("GPO_STAGE:BACKUP\r\nGPO_STAGE:WRITING\n{\"ok\":true}")))){
 var output=await WindowsPowerShellExecutor.ReadOutputAsync(reader,1024,CancellationToken.None,phases.Add);
 Check(output=="{\"ok\":true}"&&phases.SequenceEqual(new[]{"BACKUP","WRITING"}),"Streaming protocol mixed stages and result");
}
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("module banner\nGPO_STAGE:REPLICATION_ENDPOINT_CHECK\nGPO_RESULT:{\"ok\":true,\"data\":{\"state\":\"PUBLISHED\"}}\nmodule cleanup output")))){
 var output=await WindowsPowerShellExecutor.ReadOutputAsync(reader,8192,CancellationToken.None);
 using var response=JsonDocument.Parse(output);
 Check(response.RootElement.GetProperty("data").GetProperty("state").GetString()=="PUBLISHED","Module stdout corrupted the framed operation response");
}
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("GPO_RESULT:{\"ok\":false,\"code\":\"TEST_DENIED\"}\n")))){
 var output=await WindowsPowerShellExecutor.ReadOutputAsync(reader,8192,CancellationToken.None);
 Check(!JsonDocument.Parse(output).RootElement.GetProperty("ok").GetBoolean(),"A framed failure became success");
}
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("GPO_RESULT:{\"ok\":true}\nGPO_RESULT:{\"ok\":false}")))){
 try{await WindowsPowerShellExecutor.ReadOutputAsync(reader,8192,CancellationToken.None);throw new Exception("Duplicate response accepted");}catch(PolicyException error){Check(error.Code=="POWERSHELL_PROTOCOL","Duplicate response must fail closed");}
}
foreach(var pair in new[]{("PSSecurityException private secret","SCRIPT_POLICY_BLOCKED","POWERSHELL_POLICY_BLOCKED"),("ParserError private secret","SCRIPT_PARSE_ERROR","POWERSHELL_SCRIPT_PARSE"),("private secret","UNCLASSIFIED_STDERR","POWERSHELL_TRANSPORT"),("","NO_STDERR","POWERSHELL_TRANSPORT")}){
 using var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(pair.Item1)));
 var hint=await WindowsPowerShellExecutor.ReadErrorSummaryAsync(reader,CancellationToken.None);
 var error=WindowsPowerShellExecutor.TransportError(1,"REPLICATION_ENDPOINT_CHECK",0,hint);
 Check(hint==pair.Item2&&error.Code==pair.Item3&&!error.Message.Contains("private secret")&&error.Message.Contains("REPLICATION_ENDPOINT_CHECK"),"Stderr diagnosis leaked output, hid the stage or misclassified failure");
}
Console.WriteLine("PASS framed PowerShell responses tolerate module stdout, preserve failures, reject duplicate results and expose safe policy/parse/exit/stage diagnostics without stderr contents");
var refreshChecks=new List<GpoLiveCheck>();
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("GPO_CHECK:"+liveFrame.Replace("ENDPOINT","REFRESH")+"\nGPO_RESULT:{\"ok\":true}")))){
 await WindowsPowerShellExecutor.ReadOutputAsync(reader,8192,CancellationToken.None,null,refreshChecks.Add);
 Check(refreshChecks.Count==1&&refreshChecks[0].Phase=="REFRESH","Refresh progress was discarded or converted to endpoint-value evidence");
}
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(new string('x',10000))))){
 try{await WindowsPowerShellExecutor.ReadOutputAsync(reader,100,CancellationToken.None);throw new Exception("Unbounded output accepted");}catch(PolicyException error){Check(error.Code=="RESPONSE_TOO_LARGE","Output cap");}
}
using var store=new Store(":memory:");var gate=new OperationGate(store);var fake=new FakeOperations(store,gate);
using var jobs=new WorkspaceWorkflows(store,fake,gate,NullLogger<WorkspaceWorkflows>.Instance,new FastClock());await jobs.StartAsync(CancellationToken.None);
var selection=new GpoSelection("11111111-1111-1111-1111-111111111111","OU=Pilot,DC=test,DC=local","2.3.1.1",1);
var first=await fake.PreviewAsync("secret-session","TEST\\Admin",selection,CancellationToken.None);
using(var maintenanceStore=new Store(":memory:")){
 var maintenanceGate=new OperationGate(maintenanceStore);
 foreach(var runState in new[]{"APPLYING","VERIFYING","REFRESHING","ROLLBACKING","ROLLING_BACK","applying"}){
  var result=new GpoWorkflowResult(runState,"Recorded",null,null,null,false,false,[],"NOT_VERIFIED");
  var record=new GpoWorkflowRun("maintenance-test",first,result,PolicyValues.Now());
  maintenanceStore.Put("gpo_runs",record.Id,record,runState);
  Check(maintenanceStore.CountActiveGpoRuns()==1,"Active operation count: "+runState);
  Reject(()=>maintenanceGate.BeginMaintenance(()=>{}),"GPO_OPERATION_BUSY");
 }
 maintenanceStore.Put("gpo_runs","maintenance-test",new GpoWorkflowRun("maintenance-test",first,new("PUBLISHED","Recorded",null,null,null,true,true,[],"NOT_VERIFIED"),PolicyValues.Now()),"PUBLISHED");
 Check(maintenanceStore.CountActiveGpoRuns()==0,"Completed operations do not block maintenance");
 maintenanceGate.BeginMaintenance(()=>{});maintenanceGate.EndMaintenance();
}
var consent=new GpoConsent("APPLY",true,true,"CHANGE-1");
WorkspaceRules.ValidatePilot(first,10);
Reject(()=>WorkspaceRules.ValidatePilot(first with{Selection=first.Selection with{ScopeDn="DC=test,DC=local"}},10),"PILOT_SCOPE_UNSAFE");
Reject(()=>WorkspaceRules.ValidatePilot(first with{Preview=first.Preview with{Impact=first.Preview.Impact! with{ExistingLinkScopes=["OU=Other,DC=test,DC=local"]}}},10),"PILOT_SCOPE_UNSAFE");
Reject(()=>WorkspaceRules.ValidateSchedule([300,60]),"INVALID_REQUEST");
Reject(()=>WorkspaceRules.ValidateSchedule([1]),"INVALID_REQUEST");
// HTTP tests use production route registration, authorization and antiforgery helpers.
var builder=WebApplication.CreateBuilder();builder.WebHost.UseTestServer();builder.Logging.ClearProviders();
builder.Services.AddSingleton(store);builder.Services.AddSingleton(jobs);builder.Services.AddAntiforgery(o=>o.HeaderName="X-CSRF-Token");
await using var app=builder.Build();app.UseRouting();
app.Use(async(ctx,next)=>{
 var actor=ctx.Request.Headers["Test-Identity"].ToString();if(actor.Length>0)ctx.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name,actor),new Claim(ClaimTypes.NameIdentifier,actor)],"Test"));
 try{OperatorSecurity.RequireIdentity(ctx);await RequestSecurity.ValidateMutationAsync(ctx);await next(ctx);}
 catch(PolicyException error){ctx.Response.StatusCode=error.Code=="AUTHENTICATION_REQUIRED"?401:error.Code=="NOT_FOUND"?404:409;await ctx.Response.WriteAsJsonAsync(new{error.Code});}
});
app.MapGet("/api/session",(HttpContext ctx,IAntiforgery anti)=>new{token=anti.GetAndStoreTokens(ctx).RequestToken});WorkspaceEndpoints.MapWorkspace(app);await app.StartAsync();
using var http=app.GetTestClient();http.BaseAddress=new Uri("http://localhost");
async Task<(string,string)> Session(string actor){using var req=new HttpRequestMessage(HttpMethod.Get,"/api/session");req.Headers.Add("Test-Identity",actor);using var response=await http.SendAsync(req);return((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!,response.Headers.GetValues("Set-Cookie").First().Split(';')[0]);}
var admin=await Session("TEST\\Admin");var viewer=await Session("TEST\\Viewer");
async Task<HttpResponseMessage> Post(string action,object body,string actor="TEST\\Admin"){
 var session=actor=="TEST\\Admin"?admin:viewer;using var req=new HttpRequestMessage(HttpMethod.Post,"/api/workflows/"+action){Content=JsonContent.Create(body)};
 req.Headers.Add("Test-Identity",actor);req.Headers.Add("Origin","http://localhost");req.Headers.Add("Cookie",session.Item2+"; GpoRemediator.GpoConnection=secret-session");req.Headers.Add("X-CSRF-Token",session.Item1);return await http.SendAsync(req);
}
var request=new WorkflowRequest(Guid.NewGuid().ToString(),[first.Id],consent,"Scope");
store.Execute("CREATE TRIGGER fixture_reject_acceptance BEFORE INSERT ON audit_macs BEGIN SELECT RAISE(ABORT,'Fixture audit write failure'); END;");
try{
    jobs.Start("apply",request,"secret-session","TEST\\Admin");
    throw new Exception("An unaudited workflow was accepted");
}
catch(Microsoft.Data.Sqlite.SqliteException){}
finally{store.Execute("DROP TRIGGER fixture_reject_acceptance");}
Check(jobs.List("TEST\\Admin").Length==0&&store.AuditEvents().Length==0&&fake.Actions.Count==0,"Audit failure left a queued write or a partial acceptance");
fake.Block=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
using(var response=await Post("apply",request)){Check(response.StatusCode==HttpStatusCode.Accepted,"Production API did not accept async work");}
var jobId=jobs.List("TEST\\Admin").Single().Id;
Check(WorkspaceRules.Active(jobs.Get(jobId,"TEST\\Admin").State),"Work completed while worker was blocked");
Reject(()=>gate.BeginMaintenance(()=>{}),"GPO_OPERATION_BUSY");
Reject(()=>gate.BeginOperation(Guid.Parse(selection.GpoId).ToString("D"),()=>{}),"GPO_OPERATION_BUSY");
Check(!JsonDefaults.Serialize(jobs.Get(jobId,"TEST\\Admin")).Contains("secret-session"),"Session token was persisted");
using(var response=await Post("apply",request)){Check(response.StatusCode==HttpStatusCode.Accepted,"Idempotent retry failed");}
using(var response=await Post("apply",request with{Refresh="Pdc"})){Check(response.StatusCode==HttpStatusCode.Conflict,"Changed idempotency payload accepted");}
using(var response=await Post("apply",request,"TEST\\Viewer")){Check(response.StatusCode==HttpStatusCode.NotFound,"Another Windows identity accessed an existing plan");}
Reject(()=>jobs.Get(jobId,"TEST\\Viewer"),"NOT_FOUND");
fake.Block.SetResult();var finished=await Done(jobs,jobId);Check(finished.State=="COMPLETED","Single workflow failed");
Check(fake.Actions.SequenceEqual(new[]{"apply:2.3.1.1","refresh:Scope","verify:2.3.1.1"}),"Server did not own the approved apply/refresh chain");
fake.RefreshFails=true;
var failedRefresh=jobs.Start("refresh",new(Guid.NewGuid().ToString(),[first.Id],new(""),"Scope"),"secret-session","TEST\\Admin");
failedRefresh=await Done(jobs,failedRefresh.Id);Check(failedRefresh.State=="NEEDS_REVIEW","Standalone failed refresh reported a completed workflow");
Check(fake.Actions[^1]=="verify:2.3.1.1"&&store.Require<GpoWorkflowRun>("gpo_runs",first.Id).Result.RefreshResults.Single().State=="FAILED",
    "An endpoint refresh failure suppressed read-back or discarded refresh evidence");
fake.RefreshFails=false;
var rollbackTarget=await fake.PreviewAsync("secret-session","TEST\\Admin",selection with{Setting="2.3.10.4"},CancellationToken.None);
await fake.ExecuteAsync(rollbackTarget.Id,"apply",consent,"secret-session","TEST\\Admin");
fake.RestoreEndpointDiff=true;
var stickyRollback=jobs.Start("rollback",new(Guid.NewGuid().ToString(),[rollbackTarget.Id],new("ROLLBACK"),"Scope"),"secret-session","TEST\\Admin");
stickyRollback=await Done(jobs,stickyRollback.Id);
Check(stickyRollback.State=="NEEDS_REVIEW"&&stickyRollback.Message.Contains("ROLLBACK_ENDPOINT_MISMATCH")&&
    store.Require<GpoWorkflowRun>("gpo_runs",rollbackTarget.Id).Result.State=="ROLLED_BACK",
    "Snapshot restore with a sticky endpoint value was reported as complete");
fake.RestoreEndpointDiff=false;
var restoredPending=jobs.Start("verify",new(Guid.NewGuid().ToString(),[rollbackTarget.Id],new("")),"secret-session","TEST\\Admin");
restoredPending=await Done(jobs,restoredPending.Id);
Check(restoredPending.State=="CHECKS_INCOMPLETE"&&restoredPending.Message.Contains("Endpoint rollback verification is incomplete"),"Restored snapshot without a baseline was reported as complete");
fake.RestoreEndpointMatch=true;
var restoredMatch=jobs.Start("verify",new(Guid.NewGuid().ToString(),[rollbackTarget.Id],new("")),"secret-session","TEST\\Admin");
restoredMatch=await Done(jobs,restoredMatch.Id);
Check(restoredMatch.State=="COMPLETED","Matching restore evidence was not recognized: "+restoredMatch.Message);
fake.RestoreEndpointMatch=false;
// A published audit CSV or scheduled refresh is not evidence of effective change.
var auditPlan=await fake.PreviewAsync("secret-session","TEST\\Admin",selection with{Setting="17.1.1"},CancellationToken.None);
fake.EndpointMismatch=true;
var unchangedAudit=jobs.Start("apply",new(Guid.NewGuid().ToString(),[auditPlan.Id],consent,"Scope"),"secret-session","TEST\\Admin");
unchangedAudit=await Done(jobs,unchangedAudit.Id);
Check(unchangedAudit.State=="NEEDS_REVIEW"&&unchangedAudit.Message.Contains("ENDPOINT_POLICY_MISMATCH"),"Unchanged effective audit policy was reported as successful");
Check(store.Require<GpoWorkflowRun>("gpo_runs",auditPlan.Id).Result.EndpointChecks![0].State=="MISMATCH","Effective audit mismatch evidence was lost");
fake.EndpointMismatch=false;fake.EndpointUnavailable=true;
var unavailableAudit=jobs.Start("refresh",new(Guid.NewGuid().ToString(),[auditPlan.Id],new(""),"Scope"),"secret-session","TEST\\Admin");
unavailableAudit=await Done(jobs,unavailableAudit.Id);Check(unavailableAudit.State=="CHECKS_INCOMPLETE","Unreachable audit endpoint was reported as verified success");
fake.EndpointUnavailable=false;
fake.EndpointMismatch=true;fake.Actions.Clear();
var pendingConvergence=jobs.Start("apply",new(Guid.NewGuid().ToString(),[auditPlan.Id],consent,"Scope",[60,300,900]),"secret-session","TEST\\Admin");
pendingConvergence=await Done(jobs,pendingConvergence.Id);
Check(pendingConvergence.State=="NEEDS_REVIEW"&&fake.Actions.Count(x=>x=="verify:17.1.1")==4,"Audit mismatch canceled convergence checks early or falsely passed the final check");
fake.EndpointMismatch=false;
// Batch preview and rebasing preserve reviewed per-control values while fingerprints advance.
fake.Actions.Clear();
var preview=jobs.Preview(Guid.NewGuid().ToString(),new([selection with{Setting="2.3.1.2"},selection with{Setting="2.3.1.3"}],true),"secret-session","TEST\\Admin");
preview=await Done(jobs,preview.Id);Check(preview.State=="COMPLETED","Batch preview failed: "+preview.Message);
var batch=jobs.Batches("TEST\\Admin").Single();
var bulk=jobs.Start("apply",new(Guid.NewGuid().ToString(),batch.PlanIds,consent,"Scope",[60,300,900],batch.Id),"secret-session","TEST\\Admin");
bulk=await Done(jobs,bulk.Id);Check(bulk.State=="COMPLETED",bulk.Message);
Check(fake.Actions.Count(x=>x.StartsWith("apply:"))==2&&fake.Actions.Count(x=>x=="refresh:Scope")==1&&fake.Actions.Count(x=>x.StartsWith("verify:"))==8,"Bulk execution or scheduled verification count incorrect");
Check(bulk.CompletedIds[1]!=batch.PlanIds[1],"Second batch control was not re-previewed after first write");
var promotionRequest=new BatchPreviewRequest([selection with{Setting="2.3.1.2",ScopeDn="OU=Production,DC=test,DC=local"},selection with{Setting="2.3.1.3",ScopeDn="OU=Production,DC=test,DC=local"}],PilotSourceId:bulk.Id);
var pilotRun=store.Require<GpoWorkflowRun>("gpo_runs",bulk.CompletedIds[0]);
store.Put("gpo_runs",pilotRun.Id,pilotRun with{Result=pilotRun.Result with{EndpointChecks=[]}});
Reject(()=>jobs.Preview(Guid.NewGuid().ToString(),promotionRequest,"secret-session","TEST\\Admin"),"PILOT_NOT_VERIFIED");
store.Put("gpo_runs",pilotRun.Id,pilotRun);
var promotion=jobs.Preview(Guid.NewGuid().ToString(),promotionRequest,"secret-session","TEST\\Admin");
promotion=await Done(jobs,promotion.Id);Check(promotion.State=="COMPLETED"&&promotion.CompletedIds.All(id=>store.Get<GpoWorkflowRun>("gpo_runs",id) is null),"Pilot promotion bypassed separate preview and approval");
Reject(()=>jobs.Preview(Guid.NewGuid().ToString(),new([selection],PilotSourceId:bulk.Id),"secret-session","TEST\\Admin"),"PILOT_CONTROL_MISMATCH");
var recovery=jobs.Start("rollback",new(Guid.NewGuid().ToString(),[],new("ROLLBACK"),"Scope",SourceWorkflowId:bulk.Id),"secret-session","TEST\\Admin");
recovery=await Done(jobs,recovery.Id);Check(recovery.State=="CHECKS_INCOMPLETE",recovery.Message);
Check(fake.LastAnchor is not null&&fake.LastRestore==bulk.CompletedIds[0],"Batch rollback did not use first snapshot plus final publication anchor");
Check(store.Require<GpoWorkflowRun>("gpo_runs",bulk.CompletedIds[1]).Result.State=="BATCH_ROLLED_BACK","Batch restore left later controls marked as applied");
var restoredChild=store.Require<GpoWorkflowRun>("gpo_runs",bulk.CompletedIds[1]).Result;
Check(!restoredChild.GpoPublished&&!restoredChild.LinkVerified&&restoredChild.EndpointChecks?.Length==0&&restoredChild.CurrentValue is null,"Restored batch member retained stale forward publication or endpoint claims");
var repeatRecovery=jobs.Start("rollback",new(Guid.NewGuid().ToString(),[],new("ROLLBACK"),SourceWorkflowId:bulk.Id),"secret-session","TEST\\Admin");
repeatRecovery=await Done(jobs,repeatRecovery.Id);Check(repeatRecovery.State=="CHECKS_INCOMPLETE","Completed batch could not be restored again: "+repeatRecovery.Message);
Check(repeatRecovery.Id!=recovery.Id&&fake.LastRestore==bulk.CompletedIds[0],"Repeat batch recovery did not retain the first snapshot");
// An uncertain write blocks later writes and refresh.
var p=await fake.PreviewAsync("secret-session","TEST\\Admin",selection with{Setting="2.3.1.5"},CancellationToken.None);
fake.FailNext=true;fake.Actions.Clear();var failure=jobs.Start("apply",new(Guid.NewGuid().ToString(),[p.Id],consent,"Scope"),"secret-session","TEST\\Admin");
failure=await Done(jobs,failure.Id);Check(failure.State=="NEEDS_REVIEW"&&fake.Actions.Count==1,"Failed apply continued to refresh");
var driftPreview=jobs.Preview(Guid.NewGuid().ToString(),new([selection with{Setting="2.3.1.2"},selection with{Setting="2.3.1.3"}]),"secret-session","TEST\\Admin");
driftPreview=await Done(jobs,driftPreview.Id);var driftBatch=jobs.Batches("TEST\\Admin").Single(x=>x.Id==driftPreview.BatchId);
fake.Actions.Clear();fake.DriftAfterApply=true;
var drift=jobs.Start("apply",new(Guid.NewGuid().ToString(),driftBatch.PlanIds,consent,"Scope",BatchId:driftBatch.Id),"secret-session","TEST\\Admin");
drift=await Done(jobs,drift.Id);Check(drift.State=="NEEDS_REVIEW"&&fake.Actions.Count==1,"External drift did not stop later batch writes");
fake.Actions.Clear();fake.FailNext=true;
var restoreFailure=jobs.Start("rollback",new(Guid.NewGuid().ToString(),[first.Id],new("ROLLBACK"),"Scope"),"secret-session","TEST\\Admin");
restoreFailure=await Done(jobs,restoreFailure.Id);Check(restoreFailure.State=="NEEDS_REVIEW"&&fake.Actions.Count==1,"Uncertain restore continued to refresh");
// Read-only scan keeps manual/unsupported controls distinct and never calls ExecuteAsync.
fake.Actions.Clear();fake.PreviewAccessRequirements.Clear();var scan=jobs.Scan(new(Guid.NewGuid().ToString(),selection,["2.3.1.1","1.2.3"]),"secret-session","TEST\\Admin");scan=await Done(jobs,scan.Id);
Check(scan.State=="COMPLETED"&&scan.ScanRows!.Length==2&&scan.ScanRows.Any(x=>x.State=="NOT_CHECKED")&&fake.Actions.Count==0,"Read-only scan wrote or hid a manual control");
Check(fake.PreviewAccessRequirements.Count>0&&fake.PreviewAccessRequirements.All(x=>!x),"Read-only scan required write permissions");
fake.PreviewSelections.Clear();var domainScan=jobs.Scan(new(Guid.NewGuid().ToString(),selection with{ScopeDn="DC=test,DC=local",AccountScope="Domain"},["1.2.1"]),"secret-session","TEST\\Admin");domainScan=await Done(jobs,domainScan.Id);
Check(domainScan.State=="COMPLETED"&&fake.PreviewSelections.Single().AccountScope=="Domain"&&fake.PreviewSelections.Single().FirstLink&&fake.Actions.Count==0,"Domain scan lost scope intent or performed a write");
Console.WriteLine("PASS domain scan preserves account scope and first-link intent without native writes");
// The opt-in batch UI uses the same durable queue for every policy half.
fake.Actions.Clear();fake.FailNext=false;fake.DriftAfterApply=false;
var userMapping=ProductionGpoMappings.Settings.First(x=>x.Scope=="User"&&x.Automation=="Automated");
var mixedPreview=jobs.Preview(Guid.NewGuid().ToString(),new([selection with{Setting="2.3.1.2",AccountScope="LocalComputers"},selection with{Setting=userMapping.Id,AccountScope="Users",EndpointScopeDn="OU=Endpoints,DC=test,DC=local",VerificationUser="TEST\\user"}]),"secret-session","TEST\\Admin");
mixedPreview=await Done(jobs,mixedPreview.Id);Check(mixedPreview.State=="COMPLETED","User/computer batch preview: "+mixedPreview.Message);
var mixedBatch=jobs.Batches("TEST\\Admin").Single(x=>x.Id==mixedPreview.BatchId);
fake.RefreshFails=true;
var mixedApply=jobs.Start("apply",new(Guid.NewGuid().ToString(),mixedBatch.PlanIds,consent,"Auto",BatchId:mixedBatch.Id),"secret-session","TEST\\Admin");
mixedApply=await Done(jobs,mixedApply.Id);
Check(mixedApply.State=="NEEDS_REVIEW"&&fake.Actions.Count(x=>x=="refresh:Scope")==2&&fake.Actions.Count(x=>x.StartsWith("verify:"))==2,
    "A refresh failure stopped the other policy context or skipped endpoint verification");
fake.RefreshFails=false;
fake.Actions.Clear();var mixedVerify=jobs.Start("verify",new(Guid.NewGuid().ToString(),mixedApply.CompletedIds,new("")),"secret-session","TEST\\Admin");mixedVerify=await Done(jobs,mixedVerify.Id);
Check(mixedVerify.State=="COMPLETED"&&fake.Actions.Count==2&&fake.Actions.All(x=>x.StartsWith("verify:")),"Read-only multi-control verification must not write or refresh");
Reject(()=>jobs.Start("apply",new(Guid.NewGuid().ToString(),[mixedBatch.PlanIds[0]],consent,"Auto"),"secret-session","TEST\\Admin"),"INVALID_REQUEST");
fake.Actions.Clear();fake.EndpointMismatch=true;
var mismatchBatch=jobs.Start("verify",new(Guid.NewGuid().ToString(),mixedApply.CompletedIds,new("")),"secret-session","TEST\\Admin");
mismatchBatch=await Done(jobs,mismatchBatch.Id);
Check(mismatchBatch.State=="NEEDS_REVIEW"&&mismatchBatch.Message.Contains("2.3.1.2")&&mismatchBatch.Message.Contains(userMapping.Id)&&
    fake.Actions.Count==2&&fake.Actions.All(x=>x.StartsWith("verify:")),"A mismatch stopped read-only verification of the other batch controls");
fake.EndpointMismatch=false;
Console.WriteLine("PASS user/computer batch preview, separate automatic refresh contexts, bounded single-plan Auto rejection and read-only batch re-verification");
fake.Actions.Clear();fake.ConfigurePreview=(s,v)=>s.Setting is "1.2.1" or "1.2.4"?v with{DesiredValue=s.Value.ToString(),DomainPolicy=new(s.Setting=="1.2.1"?"LockoutDuration":"LockoutObservationWindow","30",s.Value.ToString(),"dc.test.local"),Dependency=s.Setting=="1.2.1"&&!fake.Actions.Contains("apply:1.2.4")?new("DOMAIN_LOCKOUT_DEPENDENCY","Window must change first","1.2.4",15,"LockoutObservationWindow","30"):null}:v;
var domainTarget=selection with{ScopeDn="DC=test,DC=local",AccountScope="Domain",Value=15};
var accountPreview=jobs.Preview(Guid.NewGuid().ToString(),new([domainTarget with{Setting="1.2.1"},domainTarget with{Setting="1.2.4"}]),"secret-session","TEST\\Admin");accountPreview=await Done(jobs,accountPreview.Id);
Check(accountPreview.State=="COMPLETED","Related account batch: "+accountPreview.Message);var accountBatch=jobs.Batches("TEST\\Admin").Single(x=>x.Id==accountPreview.BatchId);
Check(store.Require<GpoWorkflowPlan>("gpo_plans",accountBatch.PlanIds[0]).Selection.Setting=="1.2.4","Related control was not ordered before the dependent control");
var accountApply=jobs.Start("apply",new(Guid.NewGuid().ToString(),accountBatch.PlanIds,consent,"Auto",BatchId:accountBatch.Id),"secret-session","TEST\\Admin");accountApply=await Done(jobs,accountApply.Id);
Check(accountApply.State=="COMPLETED"&&fake.Actions.Where(x=>x.StartsWith("apply:")).SequenceEqual(["apply:1.2.4","apply:1.2.1"])&&fake.Actions.Count(x=>x=="refresh:Pdc")==1,"Account batch did not use approved dependency order and PDC refresh");
fake.ConfigurePreview=null;
var dependencyPlan=store.Require<GpoWorkflowPlan>("gpo_plans",accountBatch.PlanIds[1]);var invalidWindow=store.Require<GpoWorkflowPlan>("gpo_plans",accountBatch.PlanIds[0]);
Reject(()=>BatchWorkflowRules.Order([dependencyPlan with{Preview=dependencyPlan.Preview with{Dependency=new("DOMAIN_LOCKOUT_DEPENDENCY","Window missing","1.2.4",15,"LockoutObservationWindow","30")}}]),"DOMAIN_LOCKOUT_DEPENDENCY");
Reject(()=>BatchWorkflowRules.Order([dependencyPlan,invalidWindow with{Preview=invalidWindow.Preview with{DomainPolicy=invalidWindow.Preview.DomainPolicy! with{DesiredValue="60"}}}]),"DOMAIN_LOCKOUT_DEPENDENCY");
var threshold=dependencyPlan with{Selection=dependencyPlan.Selection with{Setting="1.2.2"},Preview=dependencyPlan.Preview with{Dependency=null,DomainPolicy=new("LockoutThreshold","0","5","dc.test.local")}};
Check(BatchWorkflowRules.Order([threshold,dependencyPlan,invalidWindow])[^1].Selection.Setting=="1.2.2","Account lockout was enabled before the explicitly selected duration/window prerequisites");
Console.WriteLine("PASS domain account batch dependency order, exact approved values, single PDC refresh and invalid/incomplete dependency rejection");
using(var req=new HttpRequestMessage(HttpMethod.Get,"/api/workflows/"+jobId+"/report")){req.Headers.Add("Test-Identity","TEST\\Admin");using var response=await http.SendAsync(req);var html=await response.Content.ReadAsStringAsync();Check(response.IsSuccessStatusCode&&html.Contains("&lt;unsafe&gt;")&&!html.Contains("<unsafe>"),"Report escaping failed");}
var reportSource=store.Require<WorkflowJob>("workflow_jobs",jobId).CompletedIds[0];var reportRun=store.Require<GpoWorkflowRun>("gpo_runs",reportSource);
store.Put("gpo_runs",reportSource,reportRun with{Result=reportRun.Result with{CurrentLink=new(reportRun.Plan.Selection.ScopeDn,2,false,false)}});
using(var req=new HttpRequestMessage(HttpMethod.Get,"/api/workflows/"+jobId+"/report")){req.Headers.Add("Test-Identity","TEST\\Admin");using var response=await http.SendAsync(req);var html=await response.Content.ReadAsStringAsync();Check(html.Contains("Intent: enable;")&&html.Contains("Observed: Enabled=False, order=2"),"HTML report confused link intent and measured disabled state");}
store.Put("gpo_runs",reportSource,reportRun with{Result=reportRun.Result with{State="ROLLED_BACK",CurrentLink=null,RestoreChecks=[new("SCOPE_LINKS","MATCH","","","Restored original absence")]}});
using(var req=new HttpRequestMessage(HttpMethod.Get,"/api/workflows/"+jobId+"/report")){req.Headers.Add("Test-Identity","TEST\\Admin");using var response=await http.SendAsync(req);var html=await response.Content.ReadAsStringAsync();Check(html.Contains("Restore saved link: Absent")&&html.Contains("Observed: Absent (verified)")&&!html.Contains("Intent: enable;"),"Rollback report reused forward link intent");}
store.Put("gpo_runs",reportSource,reportRun);
using(var req=new HttpRequestMessage(HttpMethod.Get,"/api/workflows/"+jobId+"/report?format=json")){req.Headers.Add("Test-Identity","TEST\\Admin");using var response=await http.SendAsync(req);var report=await response.Content.ReadFromJsonAsync<JsonElement>();Check(report.GetProperty("integrityHash").GetString()==PolicyValues.Hash(report.GetProperty("payload")),"Report payload integrity hash does not match exported JSON");}
await app.StopAsync();await jobs.StopAsync(CancellationToken.None);
// Simulate service death: stored queued writes must become review records, not replay.
var interrupted=finished with{Id="interrupted",State="RUNNING"};store.Put("workflow_jobs",interrupted.Id,interrupted,"RUNNING");
using(var restarted=new WorkspaceWorkflows(store,fake,gate,NullLogger<WorkspaceWorkflows>.Instance,TimeProvider.System)){
 await restarted.StartAsync(CancellationToken.None);for(var i=0;i<100&&restarted.Get(interrupted.Id,"TEST\\Admin").State=="RUNNING";i++)await Task.Delay(10);
 Check(restarted.Get(interrupted.Id,"TEST\\Admin").State=="NEEDS_REVIEW","Restart replayed or lost an interrupted write");await restarted.StopAsync(CancellationToken.None);
}
Console.WriteLine("PASS workspace: production async HTTP/identity isolation/idempotency, server refresh chain, serialized batch/rebase/first-snapshot rollback, scheduled checks, read-only scan, pilot boundaries, report escaping, streaming limits and restart recovery.");

sealed class FakeOperations(Store store,OperationGate gate):IWorkflowOperations
{
 public readonly List<bool> PreviewAccessRequirements=[];
 public readonly List<GpoSelection> PreviewSelections=[];
 public Func<GpoSelection,GpoPreview,GpoPreview>? ConfigurePreview;
 public readonly List<string> Actions=[];public TaskCompletionSource? Block;public bool FailNext;public bool DriftAfterApply;public bool RefreshFails;public bool EndpointMismatch;public bool EndpointUnavailable;public GpoRollbackAnchor? LastAnchor;public string? LastRestore;private string fingerprint="initial";
 public bool RestoreEndpointDiff;public bool RestoreEndpointMatch;
 public void ValidateConnection(string token,string actor){if(token!="secret-session")throw new PolicyException("GPO_LOGIN_REQUIRED","Reconnect.");}
 public Task<GpoWorkflowPlan> PreviewAsync(string token,string actor,GpoSelection selection,CancellationToken ct,bool requireWriteAccess=true){
  PreviewAccessRequirements.Add(requireWriteAccess);
  PreviewSelections.Add(selection);
  ValidateConnection(token,actor);var preview=new GpoPreview(new(selection.GpoId,"<unsafe>",false,true),new(selection.ScopeDn,"Pilot","OU"),"0",fingerprint,"links",null,[],[],new("",false,[],new(2,0,2,0,["ws.test.local"],false),[],[],null),DesiredValue:"1");
  if(ConfigurePreview is not null)preview=ConfigurePreview(selection,preview);
  var plan=new GpoWorkflowPlan(Guid.NewGuid().ToString("N"),actor,"TEST\\Executor","WINDOWS","test.local","dc.test.local",selection,preview,PolicyValues.Now());store.Put("gpo_plans",plan.Id,plan);return Task.FromResult(plan);
 }
 public GpoWorkflowPlan ValidateSubmission(string id,string operation,GpoConsent consent,string token,string actor){ValidateConnection(token,actor);var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);if(plan.Actor!=actor)throw new PolicyException("NOT_FOUND","Plan");return plan;}
 public async Task<GpoWorkflowRun> ExecuteAsync(string id,string operation,GpoConsent consent,string token,string actor,string? workflowId=null,GpoRollbackAnchor? rollbackAnchor=null){
  ValidateConnection(token,actor);var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);var key=Guid.Parse(plan.Selection.GpoId).ToString("D");gate.BeginOperation(key,()=>{},workflowId);
  try{
   Actions.Add(operation+":"+(operation=="refresh"?consent.Refresh:plan.Selection.Setting));if(Block is not null){await Block.Task;Block=null;}
   var saved=store.Get<GpoWorkflowRun>("gpo_runs",id);
   var state=FailNext?"REVIEW_REQUIRED":operation=="rollback"||((operation is "refresh" or "verify")&&saved?.Result.State=="ROLLED_BACK")?"ROLLED_BACK":"PUBLISHED";FailNext=false;
   if(operation=="apply")fingerprint=Guid.NewGuid().ToString("N");if(operation=="rollback"){LastAnchor=rollbackAnchor;LastRestore=id;}
   var result=new GpoWorkflowResult(state,"Recorded",operation=="apply"?"backup-"+id:store.Get<GpoWorkflowRun>("gpo_runs",id)?.Result.BackupId,"backup",fingerprint,operation!="rollback",operation!="rollback",operation=="refresh"?[new("ws.test.local","SCHEDULED","scheduled")]:[],"VERIFIED_ON_SAMPLE",new("1","1",true,[],[],PolicyValues.Now(),true),[new("ws.test.local","VERIFIED","fixture effective value")]);
   if(operation=="verify"&&EndpointMismatch)result=result with{EffectiveStatus="ENDPOINT_MISMATCH",EndpointChecks=[new("ws.test.local","MISMATCH","Audit policy remained unchanged","0")]};
   if(operation=="verify"&&EndpointUnavailable)result=result with{EffectiveStatus="ENDPOINT_VERIFICATION_PENDING",EndpointChecks=[new("ws.test.local","UNAVAILABLE","Endpoint unreachable")]};
   if(operation=="verify"&&state=="ROLLED_BACK"&&RestoreEndpointDiff)
    result=result with{EffectiveStatus="ROLLBACK_ENDPOINT_MISMATCH",EndpointChecks=[new("ws.test.local","RESTORE_MISMATCH","Saved DWORD differs","DisableDomainCreds=1")]};
   if(operation=="verify"&&state=="ROLLED_BACK"&&RestoreEndpointMatch)
    result=result with{EffectiveStatus="ROLLBACK_ENDPOINT_SAMPLE_MATCH",EndpointChecks=[new("ws.test.local","RESTORE_MATCH","Saved DWORD matches","DisableDomainCreds=0")],RestoreChecks=[new("CONTENT","MATCH","same","same","Matches")]};
   if(operation=="refresh"&&RefreshFails)result=result with{RefreshResults=[new("ws.test.local","FAILED","RPC unavailable")]};
   if(operation=="verify"&&store.Get<GpoWorkflowRun>("gpo_runs",id) is {} previous)
    result=result with{RefreshResults=previous.Result.RefreshResults,RefreshCoverage=previous.Result.RefreshCoverage};
   var run=new GpoWorkflowRun(id,plan,result,PolicyValues.Now(),consent);store.Put("gpo_runs",id,run,state);if(operation=="apply"&&DriftAfterApply){fingerprint="external-edit";DriftAfterApply=false;}return run;
  }finally{gate.EndOperation(key);}
 }
}
sealed class FastClock:TimeProvider
{
 public override ITimer CreateTimer(TimerCallback callback,object? state,TimeSpan dueTime,TimeSpan period)=>new ShortTimer(callback,state);
 private sealed class ShortTimer:ITimer{private readonly Timer timer;public ShortTimer(TimerCallback callback,object? state){timer=new Timer(callback,state,5,Timeout.Infinite);}public bool Change(TimeSpan dueTime,TimeSpan period)=>timer.Change(5,Timeout.Infinite);public void Dispose()=>timer.Dispose();public ValueTask DisposeAsync()=>timer.DisposeAsync();}
}
