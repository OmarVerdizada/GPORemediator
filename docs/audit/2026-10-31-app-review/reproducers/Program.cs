using System.Reflection;
using System.Text.Json;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.DataProtection;

Directory.CreateDirectory("work/review3174");
const string actor="EXAMPLE\\Operator",gpo="11111111-1111-1111-1111-111111111111",dn="DC=example,DC=test";
using var store=new Store(":memory:");
var cfg=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Mode","Windows"},{"Windows:Domain","example.test"},{"Windows:DomainController","dc.example.test"}}).Build();
using var service=new GpoWorkflowService(cfg,store,new OperationGate(store),new EphemeralDataProtectionProvider(),new WindowsPowerShellExecutor(NullLogger<WindowsPowerShellExecutor>.Instance));
var selection=new GpoSelection(gpo,"OU=Pilot,"+dn,"9.1.5",0,"LocalComputers",ItemValues:[["16384"]]);
var plan=new GpoWorkflowPlan("audit-0",actor,actor,"WINDOWS","example.test","dc.example.test",selection,new(new(gpo,"Example GPO",false,true),new(selection.ScopeDn,"Pilot","OU"),"0","fp","",null,[],[],DesiredValue:"16384"),PolicyValues.Now());
var result=new GpoWorkflowResult("PUBLISHED","Fixture",null,null,null,true,true,[new("ws.example.test","FAILED","Fixture refresh failed")],"VERIFIED_ON_ALL_TARGETS",new("1","1",true,[],[],PolicyValues.Now(),true),[new("ws.example.test","VERIFIED","Fixture value","16384")],"16384",EndpointCoverage:new(1,1,true),RefreshCoverage:new(1,1,true),CurrentLink:new(selection.ScopeDn,1,false,true));
for(int i=0;i<201;i++){var p=plan with{Id="audit-"+i};store.Put("gpo_plans",p.Id,p);store.Put("gpo_runs",p.Id,new GpoWorkflowRun(p.Id,p,result,PolicyValues.Now()));}
var findings=new List<object>();
var authorizedOu="OU=Servers,"+dn;var outsideOu="OU=Outside\\,OU=Servers,"+dn;
findings.Add(new{test="escaped-comma DN suffix treated as descendant",authorizedOu,outsideOu,authorized=GpoWorkflowRules.IsWriteAuthorized([gpo],[authorizedOu],selection with{ScopeDn=outsideOu})});
findings.Add(new{test="history hard cap",stored=store.List<GpoWorkflowRun>("gpo_runs").Length,apiReturned=service.History(actor).Length});
var evidence=JsonSerializer.SerializeToElement(service.Evidence("audit-0",actor),JsonDefaults.Options);
findings.Add(new{test="evidence omissions",liveRefreshResults=result.RefreshResults.Length,exportHasRefreshResults=evidence.TryGetProperty("refreshResults",out _),exportHasEndpointCoverage=evidence.TryGetProperty("endpointCoverage",out _),exportHasRefreshCoverage=evidence.TryGetProperty("refreshCoverage",out _)});
var rolled=new GpoWorkflowRun(plan.Id,plan,result with{State="ROLLED_BACK",GpoPublished=false,LinkVerified=false,CurrentLink=new(selection.ScopeDn,1,false,false)},PolicyValues.Now());
var reportJob=new WorkflowJob("report",actor,"rollback","COMPLETED",PolicyValues.Now(),PolicyValues.Now(),[plan.Id],[plan.Id],"None",[],new(""),"hash","Fixture");
var html=(string)typeof(WorkspaceEndpoints).GetMethod("Report",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[reportJob,new[]{rolled},new[]{plan},"hash"])!;
File.WriteAllText("work/review3174/workflow-link-report.html",html);
findings.Add(new{test="HTML workflow report hardcodes enabled link",actualLinkEnabled=false,reportLinkRow=System.Text.RegularExpressions.Regex.Match(html,"<tr><td>Link</td>.*?</tr>").Value});
var fake=new ScanProbe();var scanJob=reportJob with{Id="domain-scan",Action="scan",State="RUNNING",PlanIds=[],CompletedIds=[],ScanTarget=selection with{Setting="1.2.1",ScopeDn=dn,AccountScope="Domain",FirstLink=true,ItemValues=null},ScanControls=["1.2.1"],ScanRows=[]};
store.Put("workflow_jobs",scanJob.Id,scanJob);
using(var workflows=new WorkspaceWorkflows(store,fake,new OperationGate(store),NullLogger<WorkspaceWorkflows>.Instance,TimeProvider.System)){
 var workType=typeof(WorkspaceWorkflows).GetNestedType("Work",BindingFlags.NonPublic)!;var work=Activator.CreateInstance(workType,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,[scanJob.Id,"fixture",null],null)!;
 await (Task)typeof(WorkspaceWorkflows).GetMethod("ProcessScan",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(workflows,[work,scanJob,CancellationToken.None])!;
 var row=store.Require<WorkflowJob>("workflow_jobs",scanJob.Id).ScanRows![0];findings.Add(new{test="domain scan silently becomes local account scan",requested="Domain",forwarded=fake.AccountScope,state=row.State,message=row.Message});
}
var inventory=new GpoInventory("example.test","dc.example.test",actor,[new(gpo,"Existing",false,true)],[new(dn,"Domain","Domain")]);
var type=typeof(GpoWorkflowService).GetNestedType("Connection",BindingFlags.NonPublic)!;
object Connection(GpoInventory inv)=>Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public,null,[actor,actor,Array.Empty<byte>(),inv,DateTimeOffset.UtcNow.AddMinutes(15),DateTimeOffset.UtcNow],null)!;
var connections=typeof(GpoWorkflowService).GetField("connections",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(service)!;
var before=Connection(inventory);connections.GetType().GetMethod("TryAdd")!.Invoke(connections,["fixture",before]);
service.SessionStatus("fixture",actor); // A visible console heartbeat during discovery.
var refreshed=Connection(inventory with{Gpos=[..inventory.Gpos,new("22222222-2222-2222-2222-222222222222","New",false,true)]});
var updated=connections.GetType().GetMethod("TryUpdate")!.Invoke(connections,["fixture",refreshed,before]);
findings.Add(new{test="discovery stale compare-and-swap after heartbeat",inventoryUpdateAccepted=updated,sessionInventoryCount=service.Inventory("fixture",actor).Gpos.Length,discoveredInventoryCount=2});
Directory.CreateDirectory("work/review3174");File.WriteAllText("work/review3174/backend-repros.json",JsonSerializer.Serialize(findings,new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine(JsonSerializer.Serialize(findings));
sealed class ScanProbe:IWorkflowOperations{
 public string? AccountScope;
 public void ValidateConnection(string token,string actor){}
 public GpoWorkflowPlan ValidateSubmission(string id,string operation,GpoConsent consent,string token,string actor)=>throw new NotSupportedException();
 public Task<GpoWorkflowRun> ExecuteAsync(string id,string operation,GpoConsent consent,string token,string actor,string? workflowId=null,GpoRollbackAnchor? rollbackAnchor=null)=>throw new NotSupportedException();
 public Task<GpoWorkflowPlan> PreviewAsync(string token,string actor,GpoSelection selection,CancellationToken ct,bool requireWriteAccess=true){AccountScope=selection.AccountScope;ProductionGpoMappings.ValidateTarget(ProductionGpoMappings.Effective(selection),new(selection.ScopeDn,"Domain","Domain"),selection);throw new NotSupportedException();}
}
