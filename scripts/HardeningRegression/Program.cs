using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

static class Tests
{
    private static int passed;
    private static void Check(bool condition,string name)
    {
        if(!condition)throw new Exception("SECURITY REGRESSION FAILED: "+name);
        passed++;Console.WriteLine("PASS "+name);
    }
    private static void ExpectThrow(Action fn,string name)
    {
        try{fn();}
        catch(PolicyException){Check(true,name);return;}
        throw new Exception("SECURITY REGRESSION FAILED: "+name);
    }
    public static int Main()
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows is required.");
        var gpo=Guid.NewGuid().ToString("D");
        var userOu="OU=Users,DC=lab,DC=test";
        var endpointOu="OU=Endpoints,DC=lab,DC=test";
        var otherOu="OU=Privileged,DC=lab,DC=test";
        var allowed=new[]{userOu,endpointOu};
        var selection=new GpoSelection(gpo,userOu,"2.3.1",0,EndpointScopeDn:endpointOu);
        Check(GpoWorkflowRules.IsWriteAuthorized(new[]{gpo},allowed,selection),"explicit user and endpoint OUs authorized");
        Check(!GpoWorkflowRules.IsWriteAuthorized(new[]{gpo},new[]{userOu},selection),"secondary endpoint OU outside write boundary denied");
        Check(!GpoWorkflowRules.IsWriteAuthorized(new[]{gpo},allowed,selection with{EndpointScopeDn=otherOu}),"unauthorized endpoint OU denied");
        Check(!GpoWorkflowRules.IsWriteAuthorized(new[]{Guid.NewGuid().ToString("D")},allowed,selection),"wrong GPO denied");
        Check(!GpoWorkflowRules.IsWriteAuthorized(new[]{gpo},allowed,selection with{ScopeDn=otherOu}),"wrong target OU denied");
        ExpectThrow(()=>GpoWorkflowRules.ValidateWriteScope(new[]{"*"},new[]{userOu}),"wildcard GPO write blocked");
        ExpectThrow(()=>GpoWorkflowRules.ValidateWriteScope(new[]{gpo},new[]{"*"}),"wildcard OU write blocked");
        using(var store=new Store(":memory:"))
        {
            store.Audit("GPO_TEST","DOMAIN\\Operator",details:new{password="SuperSecret-1234",note="test"});
            store.Audit("GPO_TEST_2","DOMAIN\\Operator");
            Check(store.AuditIntegrityReport().Valid,"new audit rows authenticate with HMAC");
            var serialized=store.AuditEvents()[0].Details;
            Check(!serialized.Contains("SuperSecret-1234",StringComparison.Ordinal),"audit secret redacted");
            // Simulate SQLite administrator tampering (drop SQLite-only protection).
            store.Execute("DROP TRIGGER audit_macs_no_update");
            store.Execute("UPDATE audit_macs SET tag='0000000000000000000000000000000000000000000000000000000000000000' WHERE audit_id=1");
            Check(!store.AuditIntegrityReport().Valid,"tampered HMAC detected");
        }
        // Persistent key loss cannot silently generate a new key for an authenticated DB.
        var temp=Path.Combine(Path.GetTempPath(),"gpr-security-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var bootstrap=Path.Combine(temp,"bootstrap.ps1");
            File.WriteAllText(bootstrap,"param([string]$RequestJson)\n($RequestJson | ConvertFrom-Json).operation\n");
            var launcher=Path.Combine(temp,"Invoke-Gpo.ps1");
            var generate=typeof(GpoScriptWorkspaces).GetMethod("ExpectedLauncher",BindingFlags.Static|BindingFlags.NonPublic)!;
            var ensure=typeof(GpoScriptWorkspaces).GetMethod("EnsureGenerated",BindingFlags.Static|BindingFlags.NonPublic)!;
            var cache=Path.Combine(temp,"cache");
            string Ensure(string path)=>(string)ensure.Invoke(null,new object[]{cache,"lab.test",gpo,path})!;
            void RejectCache(string name){
                try{Ensure(bootstrap);throw new Exception("Tampered cache accepted");}
                catch(TargetInvocationException error)when(error.InnerException is PolicyException policy&&policy.Code=="GPO_SCRIPT_TAMPERED"){Check(true,name);}
            }
            var legacy=Path.Combine(cache,"lab.test",gpo);Directory.CreateDirectory(legacy);
            var legacyFile=Path.Combine(legacy,"Invoke-Gpo.ps1");File.WriteAllText(legacyFile,"# prior release or installation path; never execute");
            var generated=Ensure(bootstrap);
            Check(generated!=legacyFile&&File.ReadAllText(legacyFile).StartsWith("# prior"),"legacy generated cache preserved without execution or sign-in failure");
            Check(Ensure(bootstrap)==generated,"same installation reuses verified launcher");
            var relocated=Ensure(Path.Combine(temp,"new-installation","bootstrap.ps1"));
            Check(relocated!=generated&&File.Exists(generated),"relocation creates separate verified launcher and preserves previous entry");
            var launcherBytes=File.ReadAllBytes(generated);
            File.AppendAllText(generated,"#tampered");RejectCache("current launcher tampering still rejected");File.WriteAllBytes(generated,launcherBytes);
            var manifest=Path.Combine(Path.GetDirectoryName(generated)!,"scope.json");var manifestBytes=File.ReadAllBytes(manifest);
            File.AppendAllText(manifest," ");RejectCache("current manifest tampering still rejected");File.WriteAllBytes(manifest,manifestBytes);
            var parallel=Enumerable.Range(0,8).AsParallel().Select(_=>Ensure(bootstrap)).ToArray();
            Check(parallel.All(path=>path==generated),"concurrent inventory sync reuses the same intact launcher");
            File.WriteAllText(launcher,(string)generate.Invoke(null,new object[]{"lab.test",gpo,bootstrap})!);
            (int Exit,string Output) Invoke(string operation,string domain,string id)
            {
                var start=new ProcessStartInfo("powershell.exe"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
                foreach(var argument in new[]{"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",launcher})start.ArgumentList.Add(argument);
                using var process=Process.Start(start)!;
                var selection=new{gpoId=id};
                process.StandardInput.Write(JsonSerializer.Serialize(new{operation,configuration=new{domain},payload=new{data=new{selection,plan=new{selection}}}}));
                process.StandardInput.Close();
                var output=process.StandardOutput.ReadToEnd();
                var error=process.StandardError.ReadToEnd();
                process.WaitForExit();
                return(process.ExitCode,output+error);
            }
            foreach(var operation in new[]{"gpoPreview","gpoApply","gpoVerify","gpoRollback","gpoRollbackInspect","gpoRefresh"})
            {
                var result=Invoke(operation,"lab.test",gpo);
                Check(result.Exit==0&&result.Output.Trim()==operation,"isolated launcher dispatches "+operation+" to local stub only");
            }
            foreach(var request in new[]{("gpoApply","other.test",gpo),("gpoApply","lab.test",Guid.NewGuid().ToString("D")),("gpoInventory","lab.test",gpo)})
            {
                var result=Invoke(request.Item1,request.Item2,request.Item3);
                Check(result.Exit!=0&&result.Output.Contains("GPO_ISOLATION_DENIED"),"isolated launcher rejects wrong domain, GPO or operation");
            }
            var db=Path.Combine(temp,"security-test.db");
            using(var store=new Store(db)){store.Audit("CHECKPOINT","DOMAIN\\Operator");Check(store.AuditIntegrityReport().Valid,"DPAPI authenticated journal created");}
            var key=Path.Combine(temp,"audit-hmac-key.dpapi");
            Check(File.Exists(key),"DPAPI key stored outside SQLite DB");
            File.Delete(key);
            var denied=false;
            try{using var _=new Store(db);}catch(InvalidOperationException){denied=true;}
            Check(denied,"missing persisted MAC key blocks startup");

            var backup=Path.Combine(temp,"delegated-backup");
            Directory.CreateDirectory(backup);
            var delegateSid=new System.Security.Principal.SecurityIdentifier("S-1-5-21-111111111-222222222-333333333-4444");
            var backupAcl=new System.Security.AccessControl.DirectorySecurity();
            var currentSid=System.Security.Principal.WindowsIdentity.GetCurrent().User!;
            backupAcl.SetOwner(currentSid);
            backupAcl.SetAccessRuleProtection(true,false);
            backupAcl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(currentSid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));
            backupAcl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(delegateSid,System.Security.AccessControl.FileSystemRights.Modify,System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));
            new DirectoryInfo(backup).SetAccessControl(backupAcl);
            PrivateFiles.EnsureDirectoryPreservingAcl(backup);
            var rules=new DirectoryInfo(backup).GetAccessControl().GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier));
            var preserved=false;
            foreach(System.Security.AccessControl.FileSystemAccessRule rule in rules)
                if(rule.IdentityReference==delegateSid&&(rule.FileSystemRights&System.Security.AccessControl.FileSystemRights.Modify)!=0){preserved=true;break;}
            Check(preserved,"backup directory initialization preserves delegated ACL");
        }
        finally {try{Directory.Delete(temp,true);}catch(IOException){}}
        Console.WriteLine($"SECURITY REGRESSIONS PASSED: {passed}");
        return 0;
    }
}
