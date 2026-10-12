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
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("GPO_STAGE:BACKUP\r\nGPO_STAGE:WRITING\n{\"ok\":true}")))){
 var output=await WindowsPowerShellExecutor.ReadOutputAsync(reader,1024,CancellationToken.None,phases.Add);
 Check(output=="{\"ok\":true}"&&phases.SequenceEqual(new[]{"BACKUP","WRITING"}),"Streaming protocol mixed stages and result");
}
using(var reader=new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(new string('x',10000))))){
 try{await WindowsPowerShellExecutor.ReadOutputAsync(reader,100,CancellationToken.None);throw new Exception("Unbounded output accepted");}catch(PolicyException error){Check(error.Code=="RESPONSE_TOO_LARGE","Output cap");}
}
using var store=new Store(":memory:");var gate=new OperationGate(store);var fake=new FakeOperations(store,gate);
using var jobs=new WorkspaceWorkflows(store,fake,gate,NullLogger<WorkspaceWorkflows>.Instance,new FastClock());await jobs.StartAsync(CancellationToken.None);
var selection=new GpoSelection("11111111-1111-1111-1111-111111111111","OU=Pilot,DC=test,DC=local","2.3.1.1",1);
var first=await fake.PreviewAsync("secret-session","TEST\\Admin",selection,CancellationToken.None);
var consent=new GpoConsent("APPLY",true,true,"CHANGE-1");
WorkspaceRules.ValidatePilot(first,10);
Reject(()=>WorkspaceRules.ValidatePilot(first with{Selection=first.Selection with{ScopeDn="DC=test,DC=local"}},10),"PILOT_SCOPE_UNSAFE");
Reject(()=>WorkspaceRules.ValidatePilot(first with{Preview=first.Preview with{Impact=first.Preview.Impact! with{ExistingLinkScopes=["OU=Other,DC=test,DC=local"]}}},10),"PILOT_SCOPE_UNSAFE");
Reject(()=>WorkspaceRules.ValidateSchedule([300,60]),"INVALID_REQUEST");
Reject(()=>WorkspaceRules.ValidateSchedule([1]),"INVALID_REQUEST");
// HTTP tests use production route registration, authorization and antiforgery helpers.
var builder=WebApplication.CreateBuilder();builder.WebHost.UseTestServer();builder.Logging.ClearProviders();
builder.Services.AddSingleton(store);builder.Services.AddSingleton(jobs);builder.Services.AddAntiforgery(o=>o.HeaderName="X-CSRF-Token");
var configuration=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["Windows:Roles:Administrators:0"]="TEST\\Admin",["Windows:Roles:Viewers:0"]="TEST\\Viewer"}).Build();
await using var app=builder.Build();app.UseRouting();
app.Use(async(ctx,next)=>{
 var actor=ctx.Request.Headers["Test-Identity"].ToString();if(actor.Length>0)ctx.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name,actor),new Claim(ClaimTypes.NameIdentifier,actor)],"Test"));
 try{OperatorSecurity.Authorize(ctx,configuration,true,"TEST\\Admin");await RequestSecurity.ValidateMutationAsync(ctx);await next(ctx);}
 catch(PolicyException error){ctx.Response.StatusCode=error.Code is "ROLE_DENIED" or "OPERATOR_DENIED"?403:error.Code=="NOT_FOUND"?404:409;await ctx.Response.WriteAsJsonAsync(new{error.Code});}
});
app.MapGet("/api/session",(HttpContext ctx,IAntiforgery anti)=>new{token=anti.GetAndStoreTokens(ctx).RequestToken});WorkspaceEndpoints.MapWorkspace(app);await app.StartAsync();
using var http=app.GetTestClient();http.BaseAddress=new Uri("http://localhost");
async Task<(string,string)> Session(string actor){using var req=new HttpRequestMessage(HttpMethod.Get,"/api/session");req.Headers.Add("Test-Identity",actor);using var response=await http.SendAsync(req);return((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!,response.Headers.GetValues("Set-Cookie").First().Split(';')[0]);}
var admin=await Session("TEST\\Admin");var viewer=await Session("TEST\\Viewer");
async Task<HttpResponseMessage> Post(string action,object body,string actor="TEST\\Admin"){
 var session=actor=="TEST\\Admin"?admin:viewer;using var req=new HttpRequestMessage(HttpMethod.Post,"/api/workflows/"+action){Content=JsonContent.Create(body)};
 req.Headers.Add("Test-Identity",actor);req.Headers.Add("Origin","http://localhost");req.Headers.Add("Cookie",session.Item2+"; GpoRemediator.GpoConnection=secret-session");req.Headers.Add("X-CSRF-Token",session.Item1);return await http.SendAsync(req);
}
fake.Block=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var request=new WorkflowRequest(Guid.NewGuid().ToString(),[first.Id],consent,"Scope");
using(var response=await Post("apply",request)){Check(response.StatusCode==HttpStatusCode.Accepted,"Production API did not accept async work");}
var jobId=jobs.List("TEST\\Admin").Single().Id;
Check(WorkspaceRules.Active(jobs.Get(jobId,"TEST\\Admin").State),"Work completed while worker was blocked");
Reject(()=>gate.BeginMaintenance(()=>{}),"GPO_OPERATION_BUSY");
Reject(()=>gate.BeginOperation(Guid.Parse(selection.GpoId).ToString("D"),()=>{}),"GPO_OPERATION_BUSY");
Check(!JsonDefaults.Serialize(jobs.Get(jobId,"TEST\\Admin")).Contains("secret-session"),"Session token was persisted");
using(var response=await Post("apply",request)){Check(response.StatusCode==HttpStatusCode.Accepted,"Idempotent retry failed");}
using(var response=await Post("apply",request with{Refresh="Pdc"})){Check(response.StatusCode==HttpStatusCode.Conflict,"Changed idempotency payload accepted");}
using(var response=await Post("apply",request,"TEST\\Viewer")){Check(response.StatusCode==HttpStatusCode.Forbidden,"Viewer submitted a write");}
Reject(()=>jobs.Get(jobId,"TEST\\Viewer"),"NOT_FOUND");
fake.Block.SetResult();var finished=await Done(jobs,jobId);Check(finished.State=="COMPLETED","Single workflow failed");
Check(fake.Actions.SequenceEqual(new[]{"apply:2.3.1.1","refresh:Scope"}),"Server did not own the approved apply/refresh chain");
// Batch preview and rebasing preserve reviewed per-control values while fingerprints advance.
fake.Actions.Clear();
var preview=jobs.Preview(Guid.NewGuid().ToString(),new([selection with{Setting="2.3.1.2"},selection with{Setting="2.3.1.3"}],true),"secret-session","TEST\\Admin");
preview=await Done(jobs,preview.Id);Check(preview.State=="COMPLETED","Batch preview failed: "+preview.Message);
var batch=jobs.Batches("TEST\\Admin").Single();
var bulk=jobs.Start("apply",new(Guid.NewGuid().ToString(),batch.PlanIds,consent,"Scope",[60,300,900],batch.Id),"secret-session","TEST\\Admin");
bulk=await Done(jobs,bulk.Id);Check(bulk.State=="COMPLETED",bulk.Message);
Check(fake.Actions.Count(x=>x.StartsWith("apply:"))==2&&fake.Actions.Count(x=>x=="refresh:Scope")==1&&fake.Actions.Count(x=>x.StartsWith("verify:"))==6,"Bulk execution or scheduled verification count incorrect");
Check(bulk.CompletedIds[1]!=batch.PlanIds[1],"Second batch control was not re-previewed after first write");
var promotion=jobs.Preview(Guid.NewGuid().ToString(),new([selection with{Setting="2.3.1.2",ScopeDn="OU=Production,DC=test,DC=local"},selection with{Setting="2.3.1.3",ScopeDn="OU=Production,DC=test,DC=local"}],PilotSourceId:bulk.Id),"secret-session","TEST\\Admin");
promotion=await Done(jobs,promotion.Id);Check(promotion.State=="COMPLETED"&&promotion.CompletedIds.All(id=>store.Get<GpoWorkflowRun>("gpo_runs",id) is null),"Pilot promotion bypassed separate preview and approval");
Reject(()=>jobs.Preview(Guid.NewGuid().ToString(),new([selection],PilotSourceId:bulk.Id),"secret-session","TEST\\Admin"),"PILOT_CONTROL_MISMATCH");
var recovery=jobs.Start("rollback",new(Guid.NewGuid().ToString(),[],new("ROLLBACK"),"Scope",SourceWorkflowId:bulk.Id),"secret-session","TEST\\Admin");
recovery=await Done(jobs,recovery.Id);Check(recovery.State=="COMPLETED",recovery.Message);
Check(fake.LastAnchor is not null&&fake.LastRestore==bulk.CompletedIds[0],"Batch rollback did not use first snapshot plus final publication anchor");
Check(store.Require<GpoWorkflowRun>("gpo_runs",bulk.CompletedIds[1]).Result.State=="BATCH_ROLLED_BACK","Batch restore left later controls marked as applied");
Reject(()=>jobs.Start("rollback",new(Guid.NewGuid().ToString(),[],new("ROLLBACK"),SourceWorkflowId:bulk.Id),"secret-session","TEST\\Admin"),"ROLLBACK_NOT_AVAILABLE");
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
fake.Actions.Clear();var scan=jobs.Scan(new(Guid.NewGuid().ToString(),selection,["2.3.1.1","1.2.3"]),"secret-session","TEST\\Admin");scan=await Done(jobs,scan.Id);
Check(scan.State=="COMPLETED"&&scan.ScanRows!.Length==2&&scan.ScanRows.Any(x=>x.State=="NOT_CHECKED")&&fake.Actions.Count==0,"Read-only scan wrote or hid a manual control");
using(var req=new HttpRequestMessage(HttpMethod.Get,"/api/workflows/"+jobId+"/report")){req.Headers.Add("Test-Identity","TEST\\Admin");using var response=await http.SendAsync(req);var html=await response.Content.ReadAsStringAsync();Check(response.IsSuccessStatusCode&&html.Contains("&lt;unsafe&gt;")&&!html.Contains("<unsafe>"),"Report escaping failed");}
using(var req=new HttpRequestMessage(HttpMethod.Get,"/api/workflows/"+jobId+"/report?format=json")){req.Headers.Add("Test-Identity","TEST\\Admin");using var response=await http.SendAsync(req);var report=await response.Content.ReadFromJsonAsync<JsonElement>();Check(report.GetProperty("integrityHash").GetString()==PolicyValues.Hash(report.GetProperty("payload")),"Report payload integrity hash does not match exported JSON");}
await app.StopAsync();await jobs.StopAsync(CancellationToken.None);
// Simulate service death: stored queued writes must become review records, not replay.
var interrupted=finished with{Id="interrupted",State="RUNNING"};store.Put("workflow_jobs",interrupted.Id,interrupted,"RUNNING");
using(var restarted=new WorkspaceWorkflows(store,fake,gate,NullLogger<WorkspaceWorkflows>.Instance,TimeProvider.System)){
 await restarted.StartAsync(CancellationToken.None);for(var i=0;i<100&&restarted.Get(interrupted.Id,"TEST\\Admin").State=="RUNNING";i++)await Task.Delay(10);
 Check(restarted.Get(interrupted.Id,"TEST\\Admin").State=="NEEDS_REVIEW","Restart replayed or lost an interrupted write");await restarted.StopAsync(CancellationToken.None);
}
Console.WriteLine("PASS workspace: production async HTTP/roles/idempotency, server refresh chain, serialized batch/rebase/first-snapshot rollback, scheduled checks, read-only scan, pilot boundaries, report escaping, streaming limits and restart recovery.");

sealed class FakeOperations(Store store,OperationGate gate):IWorkflowOperations
{
 public readonly List<string> Actions=[];public TaskCompletionSource? Block;public bool FailNext;public bool DriftAfterApply;public GpoRollbackAnchor? LastAnchor;public string? LastRestore;private string fingerprint="initial";
 public void ValidateConnection(string token,string actor){if(token!="secret-session")throw new PolicyException("GPO_LOGIN_REQUIRED","Reconnect.");}
 public Task<GpoWorkflowPlan> PreviewAsync(string token,string actor,GpoSelection selection,CancellationToken ct){
  ValidateConnection(token,actor);var preview=new GpoPreview(new(selection.GpoId,"<unsafe>",false,true),new(selection.ScopeDn,"Pilot","OU"),"0",fingerprint,"links",null,[],[],new("",false,[],new(2,0,2,0,["ws.test.local"],false),[],[],null),DesiredValue:"1");
  var plan=new GpoWorkflowPlan(Guid.NewGuid().ToString("N"),actor,"TEST\\Executor","WINDOWS","test.local","dc.test.local",selection,preview,PolicyValues.Now());store.Put("gpo_plans",plan.Id,plan);return Task.FromResult(plan);
 }
 public GpoWorkflowPlan ValidateSubmission(string id,string operation,GpoConsent consent,string token,string actor){ValidateConnection(token,actor);var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);if(plan.Actor!=actor)throw new PolicyException("NOT_FOUND","Plan");return plan;}
 public async Task<GpoWorkflowRun> ExecuteAsync(string id,string operation,GpoConsent consent,string token,string actor,string? workflowId=null,GpoRollbackAnchor? rollbackAnchor=null){
  ValidateConnection(token,actor);var plan=store.Require<GpoWorkflowPlan>("gpo_plans",id);var key=Guid.Parse(plan.Selection.GpoId).ToString("D");gate.BeginOperation(key,()=>{},workflowId);
  try{
   Actions.Add(operation+":"+(operation=="refresh"?consent.Refresh:plan.Selection.Setting));if(Block is not null){await Block.Task;Block=null;}
   var state=FailNext?"REVIEW_REQUIRED":operation=="rollback"?"ROLLED_BACK":"PUBLISHED";FailNext=false;
   if(operation=="apply")fingerprint=Guid.NewGuid().ToString("N");if(operation=="rollback"){LastAnchor=rollbackAnchor;LastRestore=id;}
   var result=new GpoWorkflowResult(state,"Recorded",operation=="apply"?"backup-"+id:store.Get<GpoWorkflowRun>("gpo_runs",id)?.Result.BackupId,"backup",fingerprint,operation!="rollback",operation!="rollback",operation=="refresh"?[new("ws.test.local","SCHEDULED","scheduled")]:[],"VERIFIED_ON_SAMPLE",new("1","1",true,[],[],PolicyValues.Now(),true),[]);
   var run=new GpoWorkflowRun(id,plan,result,PolicyValues.Now(),consent);store.Put("gpo_runs",id,run,state);if(operation=="apply"&&DriftAfterApply){fingerprint="external-edit";DriftAfterApply=false;}return run;
  }finally{gate.EndOperation(key);}
 }
}
sealed class FastClock:TimeProvider
{
 public override ITimer CreateTimer(TimerCallback callback,object? state,TimeSpan dueTime,TimeSpan period)=>new ShortTimer(callback,state);
 private sealed class ShortTimer:ITimer{private readonly Timer timer;public ShortTimer(TimerCallback callback,object? state){timer=new Timer(callback,state,5,Timeout.Infinite);}public bool Change(TimeSpan dueTime,TimeSpan period)=>timer.Change(5,Timeout.Infinite);public void Dispose()=>timer.Dispose();public ValueTask DisposeAsync()=>timer.DisposeAsync();}
}
