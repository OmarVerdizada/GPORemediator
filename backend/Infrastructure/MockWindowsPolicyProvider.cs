using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

public record MockGpo(GpoReference Reference, Dictionary<string,string[]> Settings);
public record MockEndpoint(string Id, string Hostname, Dictionary<string,string[]> Settings, Dictionary<string,string[]> PendingRestart);

public sealed class MockWindowsPolicyProvider : IWindowsPolicyProvider
{
    public const string BaselineId="11111111-1111-4111-8111-111111111111";
    public const string DedicatedId="22222222-2222-4222-8222-222222222222";
    public const string ProtectedId="31b2f340-016d-11d2-945f-00c04fb984f9";
    private readonly Store store;
    private readonly Dictionary<string,string> lastTargets = new();
    public string Mode => "MOCK";
    public MockWindowsPolicyProvider(Store store)
    {
        this.store=store;
        if(store.Get<MockGpo>("mock_gpos",BaselineId) is null)
        {
            var defaults=Catalog.Controls.Where(c=>c.Automated).ToDictionary(c=>c.Id,c=>Initial(c));
            Save(new(Reference(BaselineId,"ORG-Server-Baseline",false),defaults));
            Save(new(Reference(DedicatedId,"ORG-CIS-Server-Remediation",true),new()));
            Save(new(Reference(ProtectedId,"Default Domain Policy",false) with {Protected=true,Approved=false},new()));
        }
    }
    private static GpoReference Reference(string id,string name,bool dedicated) => new(id,name,
        [new("OU=Servers,DC=prosol,DC=az",dedicated?1:2,false,true)], ["Authenticated Users (S-1-5-11)"],null,true,dedicated,false,
        "Inheritance enabled; no enforced ancestor link in this simulated scope",12,"DC-01.prosol.az","1");
    private MockGpo Gpo(string id) => store.Require<MockGpo>("mock_gpos",id);
    private void Save(MockGpo gpo) => store.Put("mock_gpos",gpo.Reference.Id,gpo);
    private static string[] Initial(BenchmarkControl c) => c.PolicyType==PolicyType.USER_RIGHTS_ASSIGNMENT ? ["S-1-5-32-544"] : ["0"];
    private MockEndpoint Endpoint(TargetResource target)
    {
        var endpoint=store.Get<MockEndpoint>("mock_endpoints",target.Id);
        if(endpoint is not null) return endpoint;
        // Reading an absent endpoint does not mutate the mock store (dry-run invariant).
        return new(target.Id,target.Hostname,Catalog.Controls.Where(c=>c.Automated).ToDictionary(c=>c.Id,c=>Initial(c)),new());
    }
    private static bool Scenario(TargetResource target,string name)=>target.Hostname.Contains(name,StringComparison.OrdinalIgnoreCase);
    private static VerificationResult Result(bool ok,string code,string message,string[]? actual=null,bool retryable=false)=>new(ok,code,message,actual??[],retryable,"DC-01.prosol.az");
    public Task<EnvironmentReadiness> ReadinessAsync(CancellationToken ct=default)
    {
        var checks=new[]
        {
            new ReadinessCheck("runtime","Portable application runtime","PASS","MOCK runtime is available."),
            new ReadinessCheck("provider","Policy provider","PASS","Mock provider is active; no Windows or AD writes are possible."),
            new ReadinessCheck("database","Durable local store","PASS","SQLite state store is available."),
            new ReadinessCheck("writes","Domain write safety","PASS","Simulation writes affect only local demo state.")
        };
        return Task.FromResult(new EnvironmentReadiness(Mode,true,"DEMO\\remediation-operator","DC-01.prosol.az",checks,PolicyValues.Now()));
    }
    public Task<TargetResource> ResolveTargetAsync(TargetResource target,CancellationToken ct=default)
    {
        var resolved=target with
        {
            Domain=string.IsNullOrWhiteSpace(target.Domain)?"prosol.az":target.Domain,
            Ou=string.IsNullOrWhiteSpace(target.Ou)?"OU=Servers,DC=prosol,DC=az":target.Ou,
            OperatingSystem=string.IsNullOrWhiteSpace(target.OperatingSystem)?"Windows Server 2022":target.OperatingSystem,
            Profile=target.Profile.Equals("Auto",StringComparison.OrdinalIgnoreCase)?"MemberServer":target.Profile
        };
        return Task.FromResult(resolved);
    }
    public Task<PreflightResult> PreflightAsync(TargetResource target,GpoReference? gpo,CancellationToken ct=default) => Task.FromResult(
        new PreflightResult(true,gpo is null || (gpo.Approved&&!gpo.Protected),true,true,"DEMO\\remediation-operator",[],["Simulated permissions; no Windows or domain changes will occur."],"DC-01.prosol.az"));
    public Task<PolicySourceAnalysis> AnalyzeAsync(TargetResource target,BenchmarkControl control,CancellationToken ct=default)
    {
        var gpos=store.List<MockGpo>("mock_gpos").Where(g=>!g.Reference.Protected).OrderBy(g=>g.Reference.Links.Min(l=>l.Order)).ToArray();
        var undefined=Scenario(target,"UNDEFINED");
        var ambiguous=Scenario(target,"AMBIGUOUS")&&!PolicyValues.Equal(Endpoint(target).Settings.GetValueOrDefault(control.Id,[]),control.ExpectedValue,control.PolicyType);
        var defining=gpos.Where(g=>g.Settings.ContainsKey(control.Id)&&(!undefined||g.Reference.Id!=BaselineId)).ToArray();
        var winner=defining.FirstOrDefault();
        var status=!control.Automated?"UNSUPPORTED":ambiguous?"AMBIGUOUS":winner is null?"NOT_DEFINED":"DETECTED";
        var current=Endpoint(target).Settings.GetValueOrDefault(control.Id,[]);
        return Task.FromResult(new PolicySourceAnalysis(status,status=="DETECTED"?"HIGH":"UNKNOWN",
            status switch {"DETECTED"=>"Simulated RSoP and link precedence identify the effective GPO.","NOT_DEFINED"=>"No domain GPO defines this setting; use a dedicated remediation GPO.","AMBIGUOUS"=>"RSoP could not resolve conflicting source data. Select an approved GPO intentionally.",_=>"Manual or unsupported policy technology."},
            target,gpos.Select(g=>g.Reference).ToArray(),status=="DETECTED"?winner?.Reference.Id:null,current,winner is not null,PolicyValues.Now()));
    }
    public async Task<ImpactAnalysis> PreviewAsync(string findingId,TargetResource target,BenchmarkControl control,TargetSelection selection,CancellationToken ct=default)
    {
        var source=await AnalyzeAsync(target,control,ct); GpoReference selected;
        switch(selection.Strategy)
        {
            case "DETECTED":
                if(source.Status!="DETECTED" || source.WinningGpoId is null) throw new PolicyException("SOURCE_AMBIGUOUS","No deterministic winning GPO is available. Choose an approved or dedicated GPO explicitly.");
                selected=Gpo(source.WinningGpoId).Reference; break;
            case "EXISTING":
                if(selection.GpoId is null) throw new PolicyException("GPO_REQUIRED","Select an approved GPO GUID.");
                selected=Gpo(selection.GpoId).Reference; break;
            case "DEDICATED": selected=Gpo(DedicatedId).Reference; break;
            case "CREATE":
                if(selection.NewGpoName is null || !System.Text.RegularExpressions.Regex.IsMatch(selection.NewGpoName,@"^ORG-[A-Za-z0-9-]{3,64}-Remediation$"))
                    throw new PolicyException("INVALID_GPO_NAME","Use a dedicated name such as ORG-CIS-Test-Remediation.");
                if(store.List<MockGpo>("mock_gpos").Any(g=>g.Reference.Name.Equals(selection.NewGpoName,StringComparison.OrdinalIgnoreCase)))
                    throw new PolicyException("GPO_ALREADY_EXISTS","Select the existing approved GPO instead.");
                var bytes=System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(selection.NewGpoName));
                selected=Reference(new Guid(bytes.AsSpan(0,16)).ToString(),selection.NewGpoName,true) with {Version="0"}; break;
            default: throw new PolicyException("INVALID_SELECTION","Choose DETECTED, EXISTING, DEDICATED, or CREATE.");
        }
        if(!selected.Approved||selected.Protected) throw new PolicyException("GPO_NOT_APPROVED","The selected GPO is protected or not approved for remediation.");
        var old=store.Get<MockGpo>("mock_gpos",selected.Id)?.Settings.GetValueOrDefault(control.Id,[])??[];
        var fingerprint=PolicyValues.Hash(new{target,selected,old,proposed=control.ExpectedValue,selection});
        return new(Guid.NewGuid().ToString(),findingId,control.Id,target,selected,old,control.ExpectedValue,control.RequiresGpUpdate,
            control.RequiresRestart,true,selected.AffectedComputers is null or >1,
            ["MOCK: this operation changes only the local simulation database.","A full GPO rollback restores all its settings; later GPO version changes block rollback."],selection,fingerprint,PolicyValues.Now(),Mode);
    }
    public Task<GpoReference> EnsureGpoAsync(ImpactAnalysis plan,CancellationToken ct=default)
    {
        if(plan.Selection.Strategy=="CREATE")
        {
            if(store.Get<MockGpo>("mock_gpos",plan.Gpo.Id) is not null) throw new PolicyException("STALE_PREVIEW","GPO already exists; preview again.");
            // Inserting a link at order 1 shifts the remaining links, just as GPMC does.
            foreach(var existing in store.List<MockGpo>("mock_gpos"))
                Save(existing with{Reference=existing.Reference with{Links=existing.Reference.Links.Select(l=>l.Target==plan.Target.Ou?l with{Order=l.Order+1}:l).ToArray()}});
            Save(new(plan.Gpo,new()));
        }
        lastTargets[plan.Gpo.Id]=plan.Target.Hostname;
        return Task.FromResult(Gpo(plan.Gpo.Id).Reference);
    }
    public Task<GpoBackup> BackupAsync(string jobId,TargetResource target,BenchmarkControl control,GpoReference gpo,string operatorName,CancellationToken ct=default)
    {
        var snapshot=Gpo(gpo.Id);
        return Task.FromResult(new GpoBackup(Guid.NewGuid().ToString(),jobId,gpo.Id,gpo.Name,control.Id,operatorName,PolicyValues.Now(),target.Id,target.Ou,
            snapshot.Settings.GetValueOrDefault(control.Id,[]),JsonDefaults.Serialize(snapshot),null,Endpoint(target).Settings.GetValueOrDefault(control.Id,[])));
    }
    public Task ApplyAsync(GpoReference gpo,BenchmarkControl control,string[] value,CancellationToken ct=default)
    {
        var current=Gpo(gpo.Id);
        if(current.Reference.Version!=gpo.Version) throw new PolicyException("CONCURRENT_GPO_CHANGE","GPO changed after preview; no write performed.");
        current.Settings[control.Id]=value.ToArray();
        Save(current with {Reference=current.Reference with{Version=(int.Parse(current.Reference.Version??"0")+1).ToString()}});
        return Task.CompletedTask;
    }
    public Task<VerificationResult> VerifyGpoAsync(GpoReference gpo,BenchmarkControl control,string[] expected,CancellationToken ct=default)
    {
        var actual=Gpo(gpo.Id).Settings.GetValueOrDefault(control.Id,[]);
        var failure=lastTargets.GetValueOrDefault(gpo.Id,"").Contains("GPOFAIL",StringComparison.OrdinalIgnoreCase);
        return Task.FromResult(Result(!failure&&PolicyValues.Equal(actual,expected,control.PolicyType),"GPO_VALUE","Independent GPO read-back compared the selected setting.",actual));
    }
    public Task<VerificationResult> VerifyScopeAsync(GpoReference gpo,TargetResource target,CancellationToken ct=default)
    {
        var fresh=Gpo(gpo.Id).Reference;
        var ok=!Scenario(target,"SCOPEFAIL")&&fresh.Links.Any(l=>l.Enabled&&l.Target==target.Ou)
            &&JsonDefaults.Serialize(fresh.Links)==JsonDefaults.Serialize(gpo.Links)
            &&fresh.SecurityFiltering.SequenceEqual(gpo.SecurityFiltering)&&fresh.WmiFilter==gpo.WmiFilter;
        return Task.FromResult(Result(ok,"GPO_SCOPE",ok?"Link, order, enforcement, filter, and inheritance match preview.":"Scope verification failed; endpoint compliance is not asserted."));
    }
    public Task<VerificationResult> RefreshAsync(TargetResource target,CancellationToken ct=default)
    {
        if(Scenario(target,"GPUPDATEFAIL")) return Task.FromResult(Result(false,"GPUPDATE_FAILED","Simulated endpoint refresh failure."));
        var endpoint=Endpoint(target);
        foreach(var control in Catalog.Controls.Where(c=>c.Automated))
        {
            var winner=store.List<MockGpo>("mock_gpos").Where(g=>g.Settings.ContainsKey(control.Id)&&g.Reference.Links.Any(l=>l.Enabled&&l.Target==target.Ou))
                .OrderBy(g=>g.Reference.Links.Min(l=>l.Order)).ThenBy(g=>g.Reference.Id==DedicatedId?0:1).FirstOrDefault();
            if(winner is null) continue;
            if(control.RequiresRestart==RestartRequirement.REQUIRED) endpoint.PendingRestart[control.Id]=winner.Settings[control.Id];
            else endpoint.Settings[control.Id]=winner.Settings[control.Id];
        }
        store.Put("mock_endpoints",target.Id,endpoint);
        return Task.FromResult(Result(true,"GPUPDATE_COMPLETE","Simulated synchronous computer policy refresh completed."));
    }
    public Task<VerificationResult> VerifyRsopAsync(TargetResource target,GpoReference gpo,BenchmarkControl control,string[] expected,CancellationToken ct=default)
    {
        var actual=Endpoint(target).Settings.GetValueOrDefault(control.Id,[]);
        return Task.FromResult(Result(!Scenario(target,"RSOPFAIL")&&PolicyValues.Equal(actual,expected,control.PolicyType),"RSOP_VALUE","Simulated resultant policy compared with expected value.",actual));
    }
    public Task<VerificationResult> VerifyEndpointAsync(TargetResource target,BenchmarkControl control,string[] expected,CancellationToken ct=default)
    {
        var actual=Endpoint(target).Settings.GetValueOrDefault(control.Id,[]);
        return Task.FromResult(Result(!Scenario(target,"ENDPOINTFAIL")&&PolicyValues.Equal(actual,expected,control.PolicyType),"ENDPOINT_VALUE","Independent simulated endpoint read compared with expected value.",actual));
    }
    public Task<VerificationResult> RestartAsync(TargetResource target,CancellationToken ct=default)
    {
        var endpoint=Endpoint(target); foreach(var setting in endpoint.PendingRestart) endpoint.Settings[setting.Key]=setting.Value;
        endpoint.PendingRestart.Clear(); store.Put("mock_endpoints",target.Id,endpoint);
        return Task.FromResult(Result(true,"RESTART_COMPLETE","Explicitly authorized simulated restart completed."));
    }
    public Task RestoreAsync(GpoBackup backup,BenchmarkControl control,CancellationToken ct=default)
    {
        var current=Gpo(backup.GpoId);
        if(backup.PostWriteVersion is null || current.Reference.Version!=backup.PostWriteVersion)
            throw new PolicyException("ROLLBACK_CONFLICT","GPO version changed after this job or its version is unknown. Review the backup before manual recovery.");
        var snapshot=JsonDefaults.Deserialize<MockGpo>(backup.ProviderData);
        Save(snapshot with {Reference=snapshot.Reference with {Version=(int.Parse(current.Reference.Version??"0")+1).ToString()}});
        return Task.CompletedTask;
    }
    public Task<VerificationResult> VerifyRollbackAsync(GpoBackup backup,BenchmarkControl control,CancellationToken ct=default)
    {
        var snapshot=JsonDefaults.Deserialize<MockGpo>(backup.ProviderData); var current=Gpo(backup.GpoId);
        var ok=PolicyValues.Hash(snapshot.Settings)==PolicyValues.Hash(current.Settings);
        return Task.FromResult(Result(ok,"ROLLBACK_GPO_VERIFIED","Full simulated GPO settings compared to the backup.",current.Settings.GetValueOrDefault(control.Id,[])));
    }
}
