using System.Reflection;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.DataProtection;

static void Check(bool value,string message){if(!value)throw new Exception(message);}
static void Reject(Action action,string code){try{action();throw new Exception("Expected "+code);}catch(PolicyException e){Check(e.Code==code,"Wrong rejection "+e.Code);}}
const string gpo="31b2f340-016d-11d2-945f-00c04fb984f9",other="6ac1786c-016f-11d2-945f-00c04fb984f9",dn="DC=example,DC=local";
var selected=new GpoSelection(gpo,dn,"1.2.1",15);
GpoWorkflowRules.ValidateWriteSelection([gpo],[dn],selected);
GpoWorkflowRules.ValidateWriteSelection(["{"+gpo.ToUpperInvariant()+"}"],[dn.ToUpperInvariant()],selected with{ScopeDn="OU=Servers,"+dn});
Reject(()=>GpoWorkflowRules.ValidateWriteSelection([gpo],[dn],selected with{GpoId=other}),"GPO_WRITE_NOT_AUTHORIZED");
Reject(()=>GpoWorkflowRules.ValidateWriteSelection([gpo],["OU=Servers,"+dn],selected),"GPO_WRITE_NOT_AUTHORIZED");
Reject(()=>GpoWorkflowRules.ValidateWriteSelection([gpo],[dn],selected with{ScopeDn="DC=other,DC=local"}),"GPO_WRITE_NOT_AUTHORIZED");
Reject(()=>GpoWorkflowRules.ValidateWriteScope(["*"],[dn]),"WRITE_SCOPE_UNRESTRICTED");
using var store=new Store(":memory:");
var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Windows:ApprovedGpoIds:0",gpo},{"Windows:AuthorizedOus:0",dn}}).Build();
using var service=new GpoWorkflowService(config,store,new OperationGate(store),new EphemeralDataProtectionProvider(),new WindowsPowerShellExecutor(NullLogger<WindowsPowerShellExecutor>.Instance));
var inventory=new GpoInventory("example.local","dc.example.local","EXAMPLE\\Operator",[new(gpo,"Default Domain Policy",true,true),new(other,"Default Domain Controllers Policy",true,true)],[new(dn,"Domain","Domain"),new("OU=Servers,"+dn,"Servers","OU")]);
var discover=typeof(GpoWorkflowService).GetMethod("Authorize",BindingFlags.Instance|BindingFlags.NonPublic)!;
var visible=(GpoInventory)discover.Invoke(service,[inventory])!;
Check(visible.Gpos.Length==2&&visible.Scopes.Length==2,"Write boundary hid read-only discovery");
Console.WriteLine("PASS full read-only inventory with explicit write boundary enforcement");
int cases=0,manual=0;
foreach(var mapping in ProductionGpoMappings.Settings){
  var selection=new GpoSelection(gpo,dn,mapping.Id,mapping.Suggested??0, mapping.DomainPolicySensitive?"Domain":mapping.Scope=="User"?"Users":"LocalComputers",CustomValue:mapping.RequiresInput?(mapping.InputDefault is {Length:>0}?mapping.InputDefault:"Policy test value"):null);
  if(!mapping.Writable){Reject(()=>ProductionGpoMappings.Validate(selection),"GPO_MANUAL_ONLY");manual++;continue;}
  var refreshes=mapping.Scope=="User"?new[]{"None","Scope"}:mapping.DomainPolicySensitive?new[]{"None","Pdc","Scope"}:new[]{"None","Scope"};
  foreach(var refresh in refreshes)foreach(var priority in new[]{false,true}){var candidate=selection with{Refresh=refresh,FirstLink=priority,EndpointScopeDn=refresh=="Scope"&&mapping.Scope=="User"?"OU=Endpoints,"+dn:null,VerificationUser=refresh=="Scope"&&mapping.Scope=="User"?"EXAMPLE\\PilotUser":null};ProductionGpoMappings.Validate(candidate);cases++;}
  if(mapping.Scope=="Computer") Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Pdc"}),"PDC_REFRESH_SCOPE_INVALID");
   if(mapping.Scope=="User"){
    Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Pdc"}),"USER_REFRESH_TARGET_INVALID");
    Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Scope"}),"ENDPOINT_SCOPE_REQUIRED");
    Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Scope",EndpointScopeDn="OU=Endpoints,"+dn}),"VERIFICATION_USER_REQUIRED");
  }
  Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Invalid"}),"GPO_OPTIONS_INVALID");
  if(mapping.AllowValueOverride){
    if(mapping.Minimum is int min){ProductionGpoMappings.Validate(selection with{Value=min});Reject(()=>ProductionGpoMappings.Validate(selection with{Value=min-1}),"GPO_VALUE_INVALID");}
    if(mapping.Maximum is int max){ProductionGpoMappings.Validate(selection with{Value=max});Reject(()=>ProductionGpoMappings.Validate(selection with{Value=max+1}),"GPO_VALUE_INVALID");}
  }
  if(mapping.RequiresInput)Reject(()=>ProductionGpoMappings.Validate(selection with{CustomValue=""}),"GPO_CUSTOM_VALUE_REQUIRED");
}
Check(cases==8*6+386*4&&manual==11,"Catalog coverage incomplete");
Console.WriteLine($"PASS {cases} control/refresh/priority combinations; {manual} controls block automatic writes");

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
var compatibleItem=new GpoMappingItem(Key:"HKLM\\Software\\Test",Name:"Enabled",Type:"DWORD",Value:["1"]);
Check(PolicyValues.Hash(compatibleItem)==PolicyValues.Hash(new{compatibleItem.Section,compatibleItem.Key,compatibleItem.Name,compatibleItem.Type,compatibleItem.Value,compatibleItem.Guid,compatibleItem.State,compatibleItem.Mask}),"Adding an absent optional item comparator invalidated unchanged historical mapping hashes");
Check(evidenceResult.VerificationStages.Single(x=>x.Stage=="AD_SYSVOL_REPLICATION").Status=="INSUFFICIENT_EVIDENCE","Legacy version-only record was upgraded to content verification without a probe");
Check((evidenceResult with{Verification=evidenceResult.Verification! with{EvidenceVersion="2.0-content"}}).VerificationStages.Single(x=>x.Stage=="AD_SYSVOL_REPLICATION").Status=="VERIFIED","Current content/CSE evidence was not recognized");
Console.WriteLine("PASS optional-comparator legacy hash compatibility and version-only evidence migration boundary");
