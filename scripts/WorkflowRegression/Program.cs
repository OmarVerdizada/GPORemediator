using System.Reflection;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.DataProtection;

static void Check(bool value,string message){if(!value)throw new Exception(message);}
static void Reject(Action action,string code){try{action();throw new Exception("Expected "+code);}catch(PolicyException e){Check(e.Code==code,"Wrong rejection "+e.Code);}}
try{
  JsonDefaults.Deserialize<SetupConfigRequest>("{\"urls\":\"http://127.0.0.1:5080\",\"domain\":\"example.local\",\"domainController\":\"dc.example.local\",\"approvedGpoIds\":[],\"authorizedOus\":[],\"allowedHosts\":[],\"backupPath\":\"C:\\\\Backups\",\"allowedOperators\":[\"legacy\"]}");
  throw new Exception("Legacy application role fields were accepted in setup JSON");
}catch(System.Text.Json.JsonException){}
const string gpo="11111111-1111-1111-1111-111111111111",other="22222222-2222-2222-2222-222222222222",dn="DC=example,DC=local";
var selected=new GpoSelection(gpo,dn,"1.2.1",15,FirstLink:true);
ProductionGpoMappings.Validate(selected with{GpoId=other});
var localAccount=selected with{ScopeDn="OU=Pilot,"+dn,AccountScope="LocalComputers",FirstLink=false,Refresh="Scope"};
ProductionGpoMappings.Validate(localAccount);
var localMapping=ProductionGpoMappings.Effective(localAccount);
Check(localMapping.Scope=="Computer"&&!localMapping.DomainPolicySensitive,"OU account policy did not resolve to local computer policy");
ProductionGpoMappings.ValidateRefresh(localMapping,"Scope");
Reject(()=>ProductionGpoMappings.ValidateRefresh(localMapping,"Pdc"),"PDC_REFRESH_SCOPE_INVALID");
ProductionGpoMappings.ValidateRefresh(ProductionGpoMappings.Effective(selected),"Pdc");
Reject(()=>ProductionGpoMappings.ValidateRefresh(ProductionGpoMappings.Effective(selected),"Scope"),"DOMAIN_REFRESH_SCOPE_INVALID");
var domainInventory=JsonDefaults.Deserialize<GpoAffectedObjects>("{\"computers\":0,\"servers\":0,\"workstations\":0,\"disabled\":0,\"sampleHosts\":[],\"truncated\":false,\"targetKind\":\"DomainAccount\",\"scopeDn\":\"DC=example,DC=local\"}");
Check(domainInventory!.TargetKind=="DomainAccount"&&domainInventory.ScopeDn==dn,"Live account scope metadata was lost during transport");
ProductionGpoMappings.ValidateTarget(localMapping,new(localAccount.ScopeDn,"Pilot","OU"),localAccount);
Reject(()=>ProductionGpoMappings.ValidateTarget(ProductionGpoMappings.Effective(selected),new(localAccount.ScopeDn,"Pilot","OU"),selected),"PASSWORD_SCOPE_MISMATCH");
Reject(()=>ProductionGpoMappings.ValidateTarget(localMapping,new(dn,"Domain","Domain"),localAccount),"LOCAL_ACCOUNT_OU_REQUIRED");
Reject(()=>ProductionGpoMappings.Validate(selected with{FirstLink=false}),"DOMAIN_POLICY_PRIORITY_REQUIRED");
ProductionGpoMappings.Validate(selected with{GpoId="{"+gpo.ToUpperInvariant()+"}"});
GpoWorkflowRules.ValidateWriteSelection([gpo],[dn],selected);
GpoWorkflowRules.ValidateWriteSelection(["{"+gpo.ToUpperInvariant()+"}"],[dn.ToUpperInvariant()],selected with{ScopeDn="OU=Servers,"+dn});
Reject(()=>GpoWorkflowRules.ValidateWriteSelection([gpo],[dn],selected with{GpoId=other}),"GPO_WRITE_NOT_AUTHORIZED");
Reject(()=>GpoWorkflowRules.ValidateWriteSelection([gpo],["OU=Servers,"+dn],selected),"GPO_WRITE_NOT_AUTHORIZED");
Reject(()=>GpoWorkflowRules.ValidateWriteSelection([gpo],[dn],selected with{ScopeDn="DC=other,DC=local"}),"GPO_WRITE_NOT_AUTHORIZED");
Reject(()=>GpoWorkflowRules.ValidateWriteScope(["*"],[dn]),"WRITE_SCOPE_UNRESTRICTED");
using var store=new Store(":memory:");
var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Windows:ApprovedGpoIds:0",gpo},{"Windows:AuthorizedOus:0",dn}}).Build();
using var service=new GpoWorkflowService(config,store,new OperationGate(store),new EphemeralDataProtectionProvider(),new WindowsPowerShellExecutor(NullLogger<WindowsPowerShellExecutor>.Instance));
var inventory=new GpoInventory("example.local","dc.example.local","EXAMPLE\\Operator",[new(gpo,"Security baseline",false,true),new(other,"Pilot policy",false,true)],[new(dn,"Domain","Domain"),new("OU=Servers,"+dn,"Servers","OU")]);
var discover=typeof(GpoWorkflowService).GetMethod("Authorize",BindingFlags.Instance|BindingFlags.NonPublic)!;
var visible=(GpoInventory)discover.Invoke(service,[inventory])!;
Check(visible.Gpos.Length==2&&visible.Scopes.Length==2,"Write boundary hid read-only discovery");
Console.WriteLine("PASS full read-only inventory with explicit write boundary enforcement");
int cases=0,manual=0;
foreach(var mapping in ProductionGpoMappings.Settings){
  var selection=new GpoSelection(gpo,dn,mapping.Id,mapping.Suggested??0, mapping.DomainPolicySensitive?"Domain":mapping.Scope=="User"?"Users":"LocalComputers",FirstLink:mapping.DomainPolicySensitive,CustomValue:mapping.RequiresInput?(mapping.InputDefault is {Length:>0}?mapping.InputDefault:"Policy test value"):null);
  if(!mapping.Writable){Reject(()=>ProductionGpoMappings.Validate(selection),"GPO_MANUAL_ONLY");manual++;continue;}
  var refreshes=mapping.Scope=="User"?new[]{"None","Scope"}:mapping.DomainPolicySensitive?new[]{"None","Pdc"}:new[]{"None","Scope"};
  foreach(var refresh in refreshes)foreach(var priority in mapping.DomainPolicySensitive?new[]{true}:new[]{false,true}){var candidate=selection with{Refresh=refresh,FirstLink=priority,EndpointScopeDn=refresh=="Scope"&&mapping.Scope=="User"?"OU=Endpoints,"+dn:null,VerificationUser=refresh=="Scope"&&mapping.Scope=="User"?"EXAMPLE\\PilotUser":null};ProductionGpoMappings.Validate(candidate);cases++;}
  if(mapping.Scope=="Computer") Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Pdc"}),"PDC_REFRESH_SCOPE_INVALID");
  if(mapping.DomainPolicySensitive) Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Scope"}),"DOMAIN_REFRESH_SCOPE_INVALID");
   if(mapping.Scope=="User"){
    Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Pdc"}),"USER_REFRESH_TARGET_INVALID");
    Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Scope"}),"ENDPOINT_SCOPE_REQUIRED");
    ProductionGpoMappings.Validate(selection with{Refresh="Scope",EndpointScopeDn="OU=Endpoints,"+dn});
  }
  Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Invalid"}),"GPO_OPTIONS_INVALID");
  if(mapping.AllowValueOverride){
    if(mapping.Minimum is int min){ProductionGpoMappings.Validate(selection with{Value=min});Reject(()=>ProductionGpoMappings.Validate(selection with{Value=min-1}),"GPO_VALUE_INVALID");}
    if(mapping.Maximum is int max){ProductionGpoMappings.Validate(selection with{Value=max});Reject(()=>ProductionGpoMappings.Validate(selection with{Value=max+1}),"GPO_VALUE_INVALID");}
  }
  if(mapping.RequiresInput)Reject(()=>ProductionGpoMappings.Validate(selection with{CustomValue=""}),"GPO_CUSTOM_VALUE_REQUIRED");
}
Check(cases==8*2+386*4&&manual==11,"Catalog coverage incomplete");
var reviewedCases=new List<object>();
foreach(var mapping in ProductionGpoMappings.Settings.Where(x=>!x.Writable)){
    var s=new GpoSelection(gpo,"OU=Pilot,"+dn,mapping.Id,0,"LocalComputers",ItemValues:mapping.Items.Select(x=>x.Value??[]).ToArray(),ReviewContext:"Reviewed Windows version, roles, service accounts and approved exceptions.");
    ProductionGpoMappings.Validate(s);
    Check(ProductionGpoMappings.Effective(s).Writable,"Reviewed control did not produce an executable mapping: "+mapping.Id);
    Reject(()=>ProductionGpoMappings.Validate(s with{ItemValues=null}),"CONTROL_REVIEW_REQUIRED");
    ProductionGpoMappings.Validate(s with{ReviewContext="R"});
    Reject(()=>ProductionGpoMappings.Validate(s with{ReviewContext="  "}),"CONTROL_REVIEW_REQUIRED");
    if(mapping.Id=="2.2.6")s=s with{ItemValues=[["S-1-5-19","S-1-5-20","S-1-5-32-544"]]};
    reviewedCases.Add(new{selection=s,mapping=ProductionGpoMappings.Effective(s)});
}
Directory.CreateDirectory("work/audit");
File.WriteAllText("work/audit/reviewed-values.json",System.Text.Json.JsonSerializer.Serialize(reviewedCases,new System.Text.Json.JsonSerializerOptions{PropertyNamingPolicy=System.Text.Json.JsonNamingPolicy.CamelCase}));
Console.WriteLine("PASS 11 controls require explicit values/environment review");
Console.WriteLine($"PASS {cases} control/refresh/priority combinations on a non-default GPO; {manual} controls block automatic writes");

using(var auditStore=new Store(":memory:")) {
    Check(auditStore.AuditIntegrityReport().Valid,"Empty audit chain invalid");
    auditStore.Audit("test-first","EXAMPLE\\Operator");auditStore.Audit("test-second","EXAMPLE\\Operator");
    Check(auditStore.AuditIntegrityReport().Valid,"Valid audit chain rejected");
    var auditDb=(Microsoft.Data.Sqlite.SqliteConnection)typeof(Store).GetField("db",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(auditStore)!;
    using var tamper=auditDb.CreateCommand();tamper.CommandText="UPDATE audit SET details='tampered' WHERE id=2";
    try { tamper.ExecuteNonQuery();throw new Exception("Append-only audit accepted an update"); } catch(Microsoft.Data.Sqlite.SqliteException e) { Check(e.SqliteErrorCode==19,"Unexpected SQLite failure"); }
    // Corrupted appended row in an isolated in-memory database; no domain or production data.
    tamper.CommandText="INSERT INTO audit(event,operator,job_id,control_id,gpo_id,details,created_at,previous_hash,hash) SELECT event,operator,job_id,control_id,gpo_id,details,created_at,hash,'invalid-hash' FROM audit WHERE id=2";tamper.ExecuteNonQuery();
    var report=auditStore.AuditIntegrityReport();Check(!report.Valid&&report.FirstInvalidEventId==3,"Audit mismatch location not reported");
    Console.WriteLine("PASS audit integrity: empty chain, valid chain and first tampered event");
}

foreach(var action in new[]{"apply","verify","refresh"})
    Reject(()=>GpoWorkflowRules.ValidateMappingVersion("old","new",action,"PUBLISHED"),"GPO_MAPPING_CHANGED");
GpoWorkflowRules.ValidateMappingVersion("old","new","rollback","PUBLISHED");
foreach(var action in new[]{"verify","refresh"})
    GpoWorkflowRules.ValidateMappingVersion("old","new",action,"ROLLED_BACK");
Reject(()=>GpoWorkflowRules.ValidateMappingVersion("old","new","apply","ROLLED_BACK"),"GPO_MAPPING_CHANGED");
Console.WriteLine("PASS mapping upgrades: stale writes blocked; snapshot rollback and restored-snapshot verification remain available");

var evidencePlan=new GpoWorkflowPlan("evidence-fixture","EXAMPLE\\Operator","EXAMPLE\\Executor","WINDOWS","example.local","dc.example.local",selected with{Setting="1.1.4"},new(new(gpo,"Test GPO",false,true),new(dn,"Domain","Domain"),"1","fingerprint","",null,[],[],DesiredValue:"14"),PolicyValues.Now());
var evidenceResult=new GpoWorkflowResult("PUBLISHED","Published",null,null,null,true,true,[new("ws.example.local","SCHEDULED","scheduled")],"VERIFIED_ON_SAMPLE",new("1","1",true,[],[],PolicyValues.Now(),true),[new("ws.example.local","VERIFIED","sample only","14")],"14");
// Real submission/execution preflight, private in-memory session, and an invalid
// ciphertext guard: a regression cannot reach the native executor or live AD.
using(var refreshStore=new Store(":memory:")){
    var refreshConfig=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Mode","Windows"},{"Windows:Domain","example.local"},{"Windows:DomainController","dc.example.local"}}).Build();
    var refreshGate=new OperationGate(refreshStore);
    using var refreshService=new GpoWorkflowService(refreshConfig,refreshStore,refreshGate,new EphemeralDataProtectionProvider(),new WindowsPowerShellExecutor(NullLogger<WindowsPowerShellExecutor>.Instance));
    var inventoryForRefresh=inventory with{ExecutionUser=evidencePlan.ExecutionUser};
    var connectionType=typeof(GpoWorkflowService).GetNestedType("Connection",BindingFlags.NonPublic)!;
    var connection=Activator.CreateInstance(connectionType,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,[evidencePlan.Actor,evidencePlan.ExecutionUser,Array.Empty<byte>(),inventoryForRefresh,DateTimeOffset.UtcNow.AddMinutes(15),DateTimeOffset.UtcNow],null)!;
    var connections=typeof(GpoWorkflowService).GetField("connections",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(refreshService)!;
    connections.GetType().GetMethod("TryAdd")!.Invoke(connections,["refresh-fixture",connection]);
    var hash=(string)typeof(GpoWorkflowService).GetProperty("ConfigHash",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(refreshService)!;
    var refreshPlan=evidencePlan with{Selection=localAccount,ConfigHash=hash};
    var previousRefresh=new GpoWorkflowRun(refreshPlan.Id,refreshPlan,evidenceResult,PolicyValues.Now());
    refreshStore.Put("gpo_plans",refreshPlan.Id,refreshPlan);refreshStore.Put("gpo_runs",refreshPlan.Id,previousRefresh);
    Reject(()=>refreshService.ValidateSubmission(refreshPlan.Id,"refresh",new("",Refresh:"Pdc"),"refresh-fixture",refreshPlan.Actor),"PDC_REFRESH_SCOPE_INVALID");
    Reject(()=>refreshService.ExecuteAsync(refreshPlan.Id,"refresh",new("",Refresh:"Pdc"),"refresh-fixture",refreshPlan.Actor).GetAwaiter().GetResult(),"PDC_REFRESH_SCOPE_INVALID");
    Check(PolicyValues.Hash(refreshStore.Require<GpoWorkflowRun>("gpo_runs",refreshPlan.Id))==PolicyValues.Hash(previousRefresh),"Invalid refresh overwrote the published result");
    Console.WriteLine("PASS invalid OU/PDC refresh rejected at submission and execution without replacing recorded result or invoking native executor");
    // Exercise the real workflow boundary plus real service validation. Do not
    // start the background worker: no credentials/native command can be used.
    refreshConfig["Windows:EnableWrites"]="true";
    refreshConfig["Windows:ApprovedGpoIds:0"]=gpo;
    refreshConfig["Windows:AuthorizedOus:0"]="OU=Users,"+dn;
    refreshConfig["Windows:AuthorizedOus:1"]="OU=Endpoints,"+dn;
    hash=(string)typeof(GpoWorkflowService).GetProperty("ConfigHash",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(refreshService)!;
    var userSelection=new GpoSelection(gpo,"OU=Users,"+dn,"19.7.5.2",3,"Users",Refresh:"None",EndpointScopeDn:"OU=Endpoints,"+dn);
    var userPlan=refreshPlan with{Id="user-refresh-boundary",Selection=userSelection,ConfigHash=hash};
    refreshStore.Put("gpo_plans",userPlan.Id,userPlan);
    refreshStore.Put("gpo_runs",userPlan.Id,new GpoWorkflowRun(userPlan.Id,userPlan,evidenceResult,PolicyValues.Now()));
    var userEvidenceHash=PolicyValues.Hash(refreshStore.Require<GpoWorkflowRun>("gpo_runs",userPlan.Id));
    using var queued=new WorkspaceWorkflows(refreshStore,refreshService,refreshGate,NullLogger<WorkspaceWorkflows>.Instance,TimeProvider.System);
    Reject(()=>queued.Start("refresh",new(Guid.NewGuid().ToString(),[userPlan.Id],new("",Refresh:"Scope"),"Pdc"),"refresh-fixture",userPlan.Actor),"USER_REFRESH_TARGET_INVALID");
    var missingEndpoints=userPlan with{Id="user-no-endpoint",Selection=userSelection with{EndpointScopeDn=null}};
    refreshStore.Put("gpo_plans",missingEndpoints.Id,missingEndpoints);
    Reject(()=>queued.Start("refresh",new(Guid.NewGuid().ToString(),[missingEndpoints.Id],new(""),"Scope"),"refresh-fixture",userPlan.Actor),"ENDPOINT_SCOPE_REQUIRED");
    var accepted=queued.Start("refresh",new(Guid.NewGuid().ToString(),[userPlan.Id],new(""),"Scope"),"refresh-fixture",userPlan.Actor);
    Check(accepted.State=="QUEUED"&&accepted.Refresh=="Scope"&&accepted.Consent.Refresh=="Scope","Explicit workflow refresh was lost before service preflight");
    Check(PolicyValues.Hash(refreshStore.Require<GpoWorkflowRun>("gpo_runs",userPlan.Id))==userEvidenceHash,"Submission changed recorded user evidence");
    Console.WriteLine("PASS real user refresh submission: top-level Scope reaches validation and stored consent; PDC and missing session endpoint OU rejected before enqueue; no native execution");

}
store.Put("gpo_runs",evidencePlan.Id,new GpoWorkflowRun(evidencePlan.Id,evidencePlan,evidenceResult,"2026-10-15T00:00:00Z"));
var exportBefore=service.Evidence(evidencePlan.Id,evidencePlan.Actor);
store.Put("gpo_runs",evidencePlan.Id,new GpoWorkflowRun(evidencePlan.Id,evidencePlan,evidenceResult with{State="ROLLED_BACK",EffectiveStatus="ROLLBACK_ENDPOINT_PENDING",CurrentValue="1"},"2026-10-15T00:01:00Z"));
var exportAfter=service.Evidence(evidencePlan.Id,evidencePlan.Actor);
Check(exportBefore.State=="PUBLISHED"&&exportAfter.State=="ROLLED_BACK"&&exportAfter.CurrentValue=="1"&&exportBefore.IntegrityHash!=exportAfter.IntegrityHash,"Evidence export returned a stale pre-rollback snapshot");
Check(store.List<GpoEvidence>("gpo_evidence").Length==2,"Earlier evidence snapshot was overwritten");
var assurance=evidenceResult.VerificationStages;
Check(assurance.Length==5&&assurance.Single(x=>x.Stage=="GPO_APPLICABILITY").Status=="INSUFFICIENT_EVIDENCE","Link equality was promoted to effective applicability");
Check(assurance.Single(x=>x.Stage=="CLIENT_PROCESSING").Status=="GPUPDATE_SCHEDULED","Scheduled refresh was promoted to completion");
Check((evidenceResult with{EndpointChecks=[new("ws.example.local","MISMATCH","auditpol disagrees","0")]}).VerificationStages.Single(x=>x.Stage=="ENDPOINT_CONFIGURATION").Status=="ENDPOINT_MISMATCH","GPO publication hid an endpoint mismatch");
Console.WriteLine("PASS fresh evidence snapshots, preserved prior exports, five independent stages, scheduled-not-completed and endpoint mismatch separation");
using(var grantStore=new Store(":memory:")){
 var firstScope="OU=One,"+dn;var secondScope="OU=Two,"+dn;
 var grantCfg=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Mode","Windows"},{"Windows:Domain","example.local"},{"Windows:DomainController","dc.example.local"},{"Windows:EnableWrites","true"},{"Windows:ApprovedGpoIds:0",gpo},{"Windows:AuthorizedOus:0",firstScope}}).Build();
 using var grantService=new GpoWorkflowService(grantCfg,grantStore,new OperationGate(grantStore),new EphemeralDataProtectionProvider(),new WindowsPowerShellExecutor(NullLogger<WindowsPowerShellExecutor>.Instance));
 var grantInv=new GpoInventory("example.local","dc.example.local","EXAMPLE\\Executor",[new(gpo,"First",false,true),new(other,"Second",false,true)],[new(firstScope,"One","OU"),new(secondScope,"Two","OU")]);
 var grantType=typeof(GpoWorkflowService).GetNestedType("Connection",BindingFlags.NonPublic)!;
 var grantSessions=typeof(GpoWorkflowService).GetField("connections",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(grantService)!;
 void ConnectGrant(string token,DateTimeOffset created){var connection=Activator.CreateInstance(grantType,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,["EXAMPLE\\Operator",grantInv.ExecutionUser,Array.Empty<byte>(),grantInv,DateTimeOffset.UtcNow.AddMinutes(15),created],null)!;grantSessions.GetType().GetMethod("TryAdd")!.Invoke(grantSessions,[token,connection]);}
 ConnectGrant("one",DateTimeOffset.UtcNow);ConnectGrant("two",DateTimeOffset.UtcNow);
 var grantSelection=localAccount with{GpoId=other,ScopeDn=secondScope,Refresh="None"};
 var grantPreview=new GpoPreview(grantInv.Gpos[1],grantInv.Scopes[1],null,"fp","",null,[],[],Preflight:new(grantInv.Domain,grantInv.DomainController,grantInv.ExecutionUser,true,[],PolicyValues.Now()));
 Check(!grantService.AuthorizePreviewTarget("one","EXAMPLE\\Operator",grantSelection,grantPreview,false),"Read-only scan granted write authorization");
 Check(!grantService.AuthorizePreviewTarget("one","EXAMPLE\\Operator",grantSelection,grantPreview with{Preflight=grantPreview.Preflight! with{Ready=false}},true),"Failed readiness granted write authorization");
 var grantBefore=PolicyValues.Hash(grantCfg.AsEnumerable().ToArray());
 Check(grantService.AuthorizePreviewTarget("one","EXAMPLE\\Operator",grantSelection,grantPreview,true),"Successful target preview did not authorize the second GPO");
 Check(grantService.AuthorizePreviewTarget("one","EXAMPLE\\Operator",grantSelection,grantPreview,false),"Same connected account lost its exact target grant");
 Check(!grantService.AuthorizePreviewTarget("two","EXAMPLE\\Operator",grantSelection,grantPreview,false),"Another connection inherited a target grant");
 Check(!grantService.AuthorizePreviewTarget("one","EXAMPLE\\Operator",grantSelection with{GpoId=gpo},grantPreview,false),"GPO/OU cross-product inherited a target grant");
 Check(grantBefore==PolicyValues.Hash(grantCfg.AsEnumerable().ToArray()),"Target authorization modified configuration or required a restart");
 var grantHash=(string)typeof(GpoWorkflowService).GetProperty("ConfigHash",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(grantService)!;
 var grantPlan=new GpoWorkflowPlan("session-grant","EXAMPLE\\Operator",grantInv.ExecutionUser,"WINDOWS",grantInv.Domain,grantInv.DomainController,grantSelection,grantPreview,PolicyValues.Now(),PolicyValues.Hash(ProductionGpoMappings.Effective(grantSelection)),grantHash,true);
 grantStore.Put("gpo_plans",grantPlan.Id,grantPlan);
 grantService.ValidateSubmission(grantPlan.Id,"apply",new("APPLY",true,ChangeReference:"CHG-test"),"one",grantPlan.Actor);
 Reject(()=>grantService.ValidateSubmission(grantPlan.Id,"apply",new("APPLY",true,ChangeReference:"CHG-test"),"two",grantPlan.Actor),"GPO_WRITE_NOT_AUTHORIZED");
 Reject(()=>grantService.ValidateSubmission(grantPlan.Id,"apply",new("APPLY",true,ChangeReference:"CHG-test"),"one","EXAMPLE\\Other"),"GPO_LOGIN_REQUIRED");
 grantService.Disconnect("one");Reject(()=>grantService.AuthorizePreviewTarget("one",grantPlan.Actor,grantSelection,grantPreview,false),"GPO_LOGIN_REQUIRED");
 ConnectGrant("expired",DateTimeOffset.UtcNow.AddHours(-3));Reject(()=>grantService.AuthorizePreviewTarget("expired",grantPlan.Actor,grantSelection,grantPreview,false),"GPO_LOGIN_REQUIRED");
 Console.WriteLine("PASS session target authorization: second GPO without config changes/restart; preview/readiness, exact pair, actor, other-session, disconnect and absolute-expiry guards; no native execution");
}
var compatibleItem=new GpoMappingItem(Key:"HKLM\\Software\\Test",Name:"Enabled",Type:"DWORD",Value:["1"]);
Check(PolicyValues.Hash(compatibleItem)==PolicyValues.Hash(new{compatibleItem.Section,compatibleItem.Key,compatibleItem.Name,compatibleItem.Type,compatibleItem.Value,compatibleItem.Guid,compatibleItem.State,compatibleItem.Mask}),"Adding an absent optional item comparator invalidated unchanged historical mapping hashes");
Check(evidenceResult.VerificationStages.Single(x=>x.Stage=="AD_SYSVOL_REPLICATION").Status=="INSUFFICIENT_EVIDENCE","Legacy version-only record was upgraded to content verification without a probe");
Check((evidenceResult with{Verification=evidenceResult.Verification! with{EvidenceVersion="2.0-content"}}).VerificationStages.Single(x=>x.Stage=="AD_SYSVOL_REPLICATION").Status=="VERIFIED","Current content/CSE evidence was not recognized");
Console.WriteLine("PASS optional-comparator legacy hash compatibility and version-only evidence migration boundary");
var customCases=new List<object>();
foreach(var pair in new[]{("9.1.5",new[]{new[]{"32768"}}),("19.5.1.1",new[]{new[]{"0"}}),("17.2.1",new[]{new[]{"0"}}),("1.1.4",new[]{new[]{"20"}}),("2.2.12",new[]{new[]{"S-1-5-32-544"}}),("9.1.4",new[]{new[]{"%SystemRoot%\\System32\\logfiles\\firewall\\customfw.log"}}),(ProductionGpoMappings.Settings.First(x=>x.Writable&&x.Items.Length==1&&x.Items[0].Type=="MultiString").Id,new[]{new[]{"one","two"}})}){
 var baseline=ProductionGpoMappings.Require(pair.Item1);
 var selection=new GpoSelection(gpo,baseline.Scope=="Domain"?dn:"OU=Targets,"+dn,baseline.Id,baseline.Suggested??0,baseline.Scope=="Domain"?"Domain":baseline.Scope=="User"?"Users":"LocalComputers",FirstLink:baseline.Scope=="Domain",ItemValues:pair.Item2);
 ProductionGpoMappings.Validate(selection);var effective=ProductionGpoMappings.Effective(selection);
 Check(!effective.AllowValueOverride&&effective.Source.Contains("operator-selected")&&effective.Items[0].Comparator is "==" or "exact","Custom values were not resolved as explicit policy intent");
 Check(ProductionGpoMappings.Require(selection.Setting)==baseline,"Custom values mutated the canonical mapping");
 customCases.Add(new{selection,mapping=effective});
}
var multi=ProductionGpoMappings.Require("18.4.4");
var multiSelection=new GpoSelection(gpo,"OU=Targets,"+dn,multi.Id,0,"LocalComputers",ItemValues:multi.Items.Select(x=>new[]{"0"}).ToArray());
ProductionGpoMappings.Validate(multiSelection);customCases.Add(new{selection=multiSelection,mapping=ProductionGpoMappings.Effective(multiSelection)});
var badValues=new GpoSelection(gpo,"OU=Targets,"+dn,"9.1.5",0,"LocalComputers",ItemValues:[["4294967296"]]);
Reject(()=>ProductionGpoMappings.Validate(badValues),"GPO_VALUE_INVALID");
Reject(()=>ProductionGpoMappings.Validate(badValues with{ItemValues=[["hello"]]}),"GPO_VALUE_INVALID");
Reject(()=>ProductionGpoMappings.Validate(badValues with{ItemValues=[]}),"GPO_CUSTOM_VALUES_INVALID");
Reject(()=>ProductionGpoMappings.Validate(badValues with{Setting="2.2.6",ItemValues=[["S-1-5-32-544"]]}),"GPO_MANUAL_ONLY");
Check(!System.Text.Json.JsonSerializer.Serialize(selected).Contains("ItemValues"),"Absent custom fields changed historical selection serialization");
Directory.CreateDirectory("work/audit");
File.WriteAllText("work/audit/custom-values.json",System.Text.Json.JsonSerializer.Serialize(customCases,new System.Text.Json.JsonSerializerOptions{PropertyNamingPolicy=System.Text.Json.JsonNamingPolicy.CamelCase}));
Console.WriteLine("PASS custom value resolution/types/read-only boundary, canonical mapping isolation and legacy selection serialization; optional user samples");
