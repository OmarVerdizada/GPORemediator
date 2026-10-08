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
  var selection=new GpoSelection(gpo,dn,mapping.Id,mapping.Suggested??0, mapping.DomainPolicySensitive?"Domain":"LocalComputers",CustomValue:mapping.RequiresInput?(mapping.InputDefault is {Length:>0}?mapping.InputDefault:"Policy test value"):null);
  if(!mapping.Writable){Reject(()=>ProductionGpoMappings.Validate(selection),"GPO_MANUAL_ONLY");manual++;continue;}
  foreach(var refresh in new[]{"None","Pdc","Scope"})foreach(var priority in new[]{false,true}){ProductionGpoMappings.Validate(selection with{Refresh=refresh,FirstLink=priority});cases++;}
  Reject(()=>ProductionGpoMappings.Validate(selection with{Refresh="Invalid"}),"GPO_OPTIONS_INVALID");
  if(mapping.AllowValueOverride){
    if(mapping.Minimum is int min){ProductionGpoMappings.Validate(selection with{Value=min});Reject(()=>ProductionGpoMappings.Validate(selection with{Value=min-1}),"GPO_VALUE_INVALID");}
    if(mapping.Maximum is int max){ProductionGpoMappings.Validate(selection with{Value=max});Reject(()=>ProductionGpoMappings.Validate(selection with{Value=max+1}),"GPO_VALUE_INVALID");}
  }
  if(mapping.RequiresInput)Reject(()=>ProductionGpoMappings.Validate(selection with{CustomValue=""}),"GPO_CUSTOM_VALUE_REQUIRED");
}
Check(cases==401*6&&manual==4,"Catalog coverage incomplete");
Console.WriteLine($"PASS {cases} control/refresh/priority combinations; {manual} controls block automatic writes");
