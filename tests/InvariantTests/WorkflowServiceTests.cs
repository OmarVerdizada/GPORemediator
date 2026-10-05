using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;

static class WorkflowServiceTests
{
    public static void Run()
    {
        using var store = new Store(":memory:");
        var gate = new OperationGate(store);
        var executor = new FixtureExecutor();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>
        {
            ["Mode"]="Windows", ["Windows:Domain"]="example.test",
            ["Windows:DomainController"]="dc.example.test", ["Windows:EnableWrites"]="true",
            ["Windows:ApprovedGpoIds:0"]=executor.Gpo.Id, ["Windows:AuthorizedOus:0"]=executor.Scope.Dn,
            ["Windows:AllowedHosts:0"]="*"
        }).Build();
        using var service = new GpoWorkflowService(config,store,gate,new EphemeralDataProtectionProvider(),executor);
        const string actor=@"TEST\operator";
        var login = new GpoLoginRequest{UserName=actor,Password="fixture-only"};
        var connection = service.ConnectAsync(login,actor,CancellationToken.None).GetAwaiter().GetResult();
        if(login.Password!="")throw new Exception("Login request retained password");
        var selection=new GpoSelection(executor.Gpo.Id,executor.Scope.Dn,"1.1.4",14);
        var plan=service.PreviewAsync(connection.Token,actor,selection,CancellationToken.None).GetAwaiter().GetResult();
        var consent=new GpoConsent("APPLY",true,false,"CHG-TEST");
        var applied=service.ExecuteAsync(plan.Id,"apply",consent,connection.Token,actor).GetAwaiter().GetResult();
        var replay=service.ExecuteAsync(plan.Id,"apply",consent,connection.Token,actor).GetAwaiter().GetResult();
        if(applied.Id!=replay.Id||applied.Result.State!=replay.Result.State||executor.ApplyCalls!=1)throw new Exception("Apply replay executed a second write");
        var evidence=service.Evidence(plan.Id,actor);
        if(evidence.IntegrityHash!=GpoWorkflowRules.EvidenceHash(evidence))throw new Exception("Exported evidence hash is not reproducible");
        if(evidence.IntegrityHash==GpoWorkflowRules.EvidenceHash(evidence with{CorrelationId="altered"}))throw new Exception("Correlation is not covered by evidence hash");

        executor.BlockVerify=true;
        var verifying=service.ExecuteAsync(plan.Id,"verify",new(""),connection.Token,actor);
        if(!executor.VerifyStarted.Task.Wait(TimeSpan.FromSeconds(5)))throw new Exception("Verification did not start");
        Expect("GPO_OPERATION_BUSY",()=>service.ExecuteAsync(plan.Id,"rollback",new("ROLLBACK"),connection.Token,actor).GetAwaiter().GetResult());
        Expect("GPO_OPERATION_BUSY",()=>gate.BeginMaintenance(()=>{}));
        executor.VerifyRelease.SetResult();
        verifying.GetAwaiter().GetResult();
        if(gate.OperationActive)throw new Exception("Verification leaked its operation gate");

        // Successful live values do not authorize refresh of an ambiguous write.
        executor.VerifyState="REVIEW_REQUIRED";
        Expect("GPO_DRIFT_DETECTED",()=>service.ExecuteAsync(plan.Id,"refresh",new(""),connection.Token,actor).GetAwaiter().GetResult());
        if(executor.RefreshCalls!=0||gate.OperationActive)throw new Exception("Ambiguous refresh ran or leaked its gate");
        config["Windows:ApprovedGpoIds:0"]="*";
        // Generate under the wildcard discovery context, then reject the write.
        plan=service.PreviewAsync(connection.Token,actor,selection,CancellationToken.None).GetAwaiter().GetResult();
        Expect("WRITE_SCOPE_UNRESTRICTED",()=>service.ExecuteAsync(plan.Id,"apply",consent,connection.Token,actor).GetAwaiter().GetResult());
    }

    static void Expect(string code,Action action)
    {
        try{action();throw new Exception("Expected "+code);}
        catch(PolicyException ex) when(ex.Code==code){}
    }

    sealed class FixtureExecutor : IWindowsPowerShellExecutor
    {
        public readonly GpoChoice Gpo=new(Guid.NewGuid().ToString(),"Fixture",false,true);
        public readonly GpoScope Scope=new("DC=example,DC=test","example.test","Domain");
        public int ApplyCalls,RefreshCalls;
        public bool BlockVerify;
        public string VerifyState="PUBLISHED";
        public readonly TaskCompletionSource VerifyStarted=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource VerifyRelease=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<T> RunAsync<T>(string operation,object configuration,object payload,CancellationToken ct)
        {
            object result;
            if(operation=="gpoInventory")result=new GpoInventory("example.test","dc.example.test",@"TEST\operator",[Gpo],[Scope]);
            else if(operation=="gpoPreview")result=new GpoPreview(Gpo,Scope,"8","fp","",null,[],[],DesiredValue:"14");
            else
            {
                if(operation=="gpoApply")ApplyCalls++;
                if(operation=="gpoRefresh")RefreshCalls++;
                if(operation=="gpoVerify"&&BlockVerify){VerifyStarted.TrySetResult();await VerifyRelease.Task.WaitAsync(ct);}
                result=new GpoWorkflowResult(operation=="gpoVerify"?VerifyState:"PUBLISHED","Fixture", "backup","directory","fp-after",true,true,[],"ENDPOINT_VERIFICATION_PENDING",CurrentValue:"14");
            }
            return (T)result;
        }
    }
}
