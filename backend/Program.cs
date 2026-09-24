using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;

var builder=WebApplication.CreateBuilder(args);
// Recovery setup must remain reachable even when the saved JSON or HTTPS configuration is broken.
var localSetup=builder.Configuration.GetValue<bool>("LocalSetup");
if(!localSetup) builder.Configuration.AddJsonFile("appsettings.Local.json",optional:true,reloadOnChange:false);
builder.Configuration.AddEnvironmentVariables().AddCommandLine(args);
if(localSetup) builder.Configuration["Mode"]="Mock";
var configuredMode=builder.Configuration["Mode"]??"Mock";
if(!new[]{"Mock","Windows"}.Contains(configuredMode,StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException("Mode must be Mock or Windows.");
var real=configuredMode.Equals("Windows",StringComparison.OrdinalIgnoreCase);
var mode=real?"WINDOWS":"MOCK";
var dbPath=builder.Configuration["DatabasePath"]??Path.Combine(builder.Environment.ContentRootPath,"data",real?"windows.db":"mock.db");
// One worker per durable database. A second service must not replay or interleave privileged jobs.
using var databaseLock=new Mutex(false,"GpoRemediator-"+PolicyValues.Hash(Path.GetFullPath(dbPath))[..24]);
bool ownsLock;
try { ownsLock=databaseLock.WaitOne(0); } catch(AbandonedMutexException) { ownsLock=true; }
if(!ownsLock) throw new InvalidOperationException("Another GPO Remediator process is already using this database.");
builder.WebHost.ConfigureKestrel(o=>o.Limits.MaxRequestBodySize=32*1024);
builder.Services.ConfigureHttpJsonOptions(o=>o.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter()));
builder.Services.AddAntiforgery(o=> { o.HeaderName="X-CSRF-Token"; o.Cookie.Name="GpoRemediator.Csrf"; o.Cookie.HttpOnly=true; o.Cookie.SameSite=SameSiteMode.Strict; o.Cookie.SecurePolicy=real?CookieSecurePolicy.Always:CookieSecurePolicy.SameAsRequest; });
if(real) { builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate(); builder.Services.AddAuthorization(); }
builder.Services.AddSingleton(new Store(dbPath)); builder.Services.AddSingleton<AdapterRegistry>();
if(real) builder.Services.AddSingleton<IWindowsPolicyProvider,WindowsPolicyProvider>();
else builder.Services.AddSingleton<IWindowsPolicyProvider,MockWindowsPolicyProvider>();
builder.Services.AddSingleton<RemediationEngine>(); builder.Services.AddHostedService(sp=>sp.GetRequiredService<RemediationEngine>());
var app=builder.Build();
var store=app.Services.GetRequiredService<Store>();
store.BindExecutionMode(mode);
foreach(var control in Catalog.Controls) store.Put("controls",control.Id,control);
foreach(var control in OperatorBenchmark.Load()) store.Put("controls",control.Id,control);
if(!real&&store.Get<TargetResource>("targets","srv-app-01") is null)
{
    var target=new TargetResource("srv-app-01","SRV-APP-01.prosol.az","prosol.az","OU=Servers,DC=prosol,DC=az","Windows Server 2022","MemberServer");
    store.Put("targets",target.Id,target);
    foreach(var (id,control,current) in new[]{("f-network","cis-2.2.3",new[]{"S-1-5-32-544"}),("f-security","sec-blank-password",new[]{"0"}),("f-restart","sec-uac",new[]{"0"})})
    { var finding=new Finding(id,control,target.Id,current,"FAIL",PolicyValues.Now()); store.Put("findings",id,finding,"FAIL"); store.Audit("FINDING_CREATED","DEMO\\seed",controlId:control,details:new{finding.Id,target=target.Hostname,mode}); }
}
app.Use(async(context,next)=>
{
    context.Response.Headers["X-Content-Type-Options"]="nosniff";
    context.Response.Headers["X-Frame-Options"]="DENY";
    context.Response.Headers["Referrer-Policy"]="no-referrer";
    context.Response.Headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
    if(context.Request.Path.StartsWithSegments("/api")) context.Response.Headers.CacheControl="no-store";
    try
    {
        if(!real && (!IPAddress.IsLoopback(context.Connection.RemoteIpAddress??IPAddress.None) || !new[]{"localhost","127.0.0.1","::1"}.Contains(context.Request.Host.Host)))
            throw new PolicyException("LOOPBACK_ONLY","Mock mode accepts only localhost requests. It is not a remotely authenticated service.");
        if(real&&!context.Request.IsHttps) throw new PolicyException("HTTPS_REQUIRED","Windows mode requires HTTPS and Integrated Authentication.");
        await next(context);
    }
    catch(AntiforgeryValidationException) { context.Response.StatusCode=403; await context.Response.WriteAsJsonAsync(new{code="CSRF_INVALID",message="Refresh the session and retry the request with its anti-forgery token."}); }
    catch(PolicyException ex)
    {
        context.Response.StatusCode=ex.Code=="NOT_FOUND"?404:ex.Code is "LOOPBACK_ONLY" or "HTTPS_REQUIRED" or "OPERATOR_DENIED" or "ORIGIN_DENIED"?403:409;
        await context.Response.WriteAsJsonAsync(new{code=ex.Code,message=Redactor.Clean(ex.Message)});
    }
    catch(BadHttpRequestException) { context.Response.StatusCode=400; await context.Response.WriteAsJsonAsync(new{code="INVALID_REQUEST",message="The request format or values are invalid."}); }
    catch(JsonException) { context.Response.StatusCode=400; await context.Response.WriteAsJsonAsync(new{code="INVALID_JSON",message="Request must contain valid typed JSON."}); }
    catch(Exception ex) { app.Logger.LogError("Request failed: {Type}",ex.GetType().Name); context.Response.StatusCode=500; await context.Response.WriteAsJsonAsync(new{code="INTERNAL_ERROR",message="The operation could not complete. Review the job's recorded diagnostic state."}); }
});
if(real) { app.UseAuthentication(); app.UseAuthorization(); }
app.Use(async(context,next)=>
{
    if(real)
    {
        if(context.User.Identity?.IsAuthenticated!=true) { await context.ChallengeAsync(); return; }
        var allowed=builder.Configuration.GetSection("Windows:AllowedOperators").Get<string[]>()??[];
        if(!allowed.Contains(context.User.Identity.Name??"",StringComparer.OrdinalIgnoreCase)) throw new PolicyException("OPERATOR_DENIED","Your Windows identity is not in the configured remediation operator allowlist.");
    }
    if(context.Request.Path.StartsWithSegments("/api")&&!HttpMethods.IsGet(context.Request.Method)&&!HttpMethods.IsHead(context.Request.Method))
    {
        var origin=context.Request.Headers.Origin.ToString();
        var expected=$"{context.Request.Scheme}://{context.Request.Host}";
        if(!string.Equals(origin,expected,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("ORIGIN_DENIED","Mutation requests must come from this application's exact origin.");
        await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context);
        if(real&&!builder.Configuration.GetValue<bool>("Windows:EnableWrites") && (context.Request.Path.Value!.EndsWith("/apply")||context.Request.Path.Value!.EndsWith("/rollback")||context.Request.Path.Value!.EndsWith("/verify")))
            throw new PolicyException("WRITES_DISABLED","EnableWrites is false in the Windows service configuration. Discovery and dry-run remain available.");
    }
    await next(context);
});
string Operator(HttpContext context)=>real?context.User.Identity!.Name!:"DEMO\\remediation-operator";
bool ValidHostname(string value)=>!string.IsNullOrWhiteSpace(value)&&value.Length<=253&&Regex.IsMatch(value,@"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
string[] CleanList(string[]? values)=>values?.Select(x=>x.Trim()).Where(x=>x.Length>0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()??[];
string RestartMarkerPath()=>Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath,"..","work","restart.request.json"));
void ConfigureService(bool restart,Action save,IHostApplicationLifetime lifetime)
{
    var engine=app.Services.GetRequiredService<RemediationEngine>();
    if(restart&&!builder.Configuration.GetValue<bool>("LauncherManaged")) throw new PolicyException("LAUNCHER_REQUIRED","Use GpoRemediator.cmd before saving with an automatic restart.");
    // Serialize config saves with job submissions and other lifecycle requests.
    engine.BeginMaintenance(()=>{ save(); if(restart) ScheduleRestart(lifetime,"Windows"); });
    if(!restart) engine.EndMaintenance();
}
void ScheduleRestart(IHostApplicationLifetime lifetime,string requestedMode)
{
    var marker=RestartMarkerPath(); Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
    File.WriteAllText(marker,JsonSerializer.Serialize(new{mode=requestedMode,requestedAt=PolicyValues.Now()},JsonDefaults.Options));
    _=Task.Run(async()=>{ await Task.Delay(900); lifetime.StopApplication(); });
}
SetupConfigView CurrentSetupConfig()
{
    var path=Path.Combine(builder.Environment.ContentRootPath,"appsettings.Local.json");
    if(File.Exists(path))
    {
        try
        {
            using var doc=JsonDocument.Parse(File.ReadAllText(path)); var root=doc.RootElement;
            var win=root.TryGetProperty("Windows",out var w)?w:default;
            string Text(JsonElement element,string name,string fallback="")=>element.ValueKind==JsonValueKind.Object&&element.TryGetProperty(name,out var value)&&value.ValueKind==JsonValueKind.String?(value.GetString()??fallback):fallback;
            bool Flag(JsonElement element,string name)=>element.ValueKind==JsonValueKind.Object&&element.TryGetProperty(name,out var value)&&value.ValueKind==JsonValueKind.True;
            string[] Array(JsonElement element,string name)=>element.ValueKind==JsonValueKind.Object&&element.TryGetProperty(name,out var value)&&value.ValueKind==JsonValueKind.Array?value.EnumerateArray().Where(v=>v.ValueKind==JsonValueKind.String).Select(v=>v.GetString()!).Where(v=>!string.IsNullOrWhiteSpace(v)).ToArray():[];
            return new SetupConfigView(Text(root,"Urls","https://management.example.com:5443"),Text(win,"Domain"),Text(win,"DomainController"),Array(win,"ApprovedGpoIds"),Array(win,"AuthorizedOus"),Array(win,"AllowedHosts"),Array(win,"AllowedOperators"),Text(win,"BackupPath",@"C:\ProgramData\GpoRemediator\Backups"),Flag(win,"EnableWrites"),"backend/appsettings.Local.json",true);
        }
        catch(JsonException) { }
    }
    var section=builder.Configuration.GetSection("Windows");
    var operatorDefaults=section.GetSection("AllowedOperators").Get<string[]>()??[];
    if(operatorDefaults.Length==0&&OperatingSystem.IsWindows()&&!string.IsNullOrWhiteSpace(Environment.UserName)) operatorDefaults=[$"{Environment.UserDomainName}\\{Environment.UserName}"];
    return new SetupConfigView(builder.Configuration["Urls"]??"https://management.example.com:5443",section["Domain"]??"",section["DomainController"]??"",section.GetSection("ApprovedGpoIds").Get<string[]>()??[],section.GetSection("AuthorizedOus").Get<string[]>()??[],section.GetSection("AllowedHosts").Get<string[]>()??[],operatorDefaults,section["BackupPath"]??@"C:\ProgramData\GpoRemediator\Backups",section.GetValue<bool>("EnableWrites"),"backend/appsettings.Local.json",false);
}
object Detail(Finding f)=>new {f.Id,f.ControlId,f.TargetId,f.CurrentValue,f.Status,f.CreatedAt,control=store.Require<BenchmarkControl>("controls",f.ControlId),target=store.Require<TargetResource>("targets",f.TargetId),analysis=store.Get<PolicySourceAnalysis>("analyses",f.Id)};
app.MapGet("/api/session",(HttpContext context,IAntiforgery csrf)=>new {mode,@operator=Operator(context),csrfToken=csrf.GetAndStoreTokens(context).RequestToken,identityStrategy=real?"WindowsIntegrated / service identity":"Mock identity",realModeEnabled=real,setupRequired=localSetup});
app.MapGet("/api/dashboard",()=>new {findings=store.List<Finding>("findings").Select(Detail),jobs=store.List<RemediationJob>("jobs"),mode});
app.MapGet("/api/service",(RemediationEngine engine)=>new {
    mode, processId=Environment.ProcessId, stopping=engine.Maintenance,
    managed=builder.Configuration.GetValue<bool>("LauncherManaged"),
    writesEnabled=real&&builder.Configuration.GetValue<bool>("Windows:EnableWrites"),
    activeJobs=store.List<RemediationJob>("jobs").Count(j=>RemediationEngine.IsActive(j.State))
});
app.MapPost("/api/service/{action}",(string action,HttpContext context,RemediationEngine engine,IHostApplicationLifetime lifetime)=>
{
    if(action is not ("stop" or "restart")) throw new PolicyException("INVALID_ACTION","Choose stop or restart.");
    if(!builder.Configuration.GetValue<bool>("LauncherManaged")) throw new PolicyException("LAUNCHER_REQUIRED","Start the application from GpoRemediator.cmd to use service controls.");
    engine.BeginMaintenance(()=> {
        store.Audit(action=="stop"?"SERVICE_STOP_REQUESTED":"SERVICE_RESTART_REQUESTED",Operator(context),details:new{mode});
        if(action=="restart") ScheduleRestart(lifetime,real?"Windows":"Demo");
        else { var marker=RestartMarkerPath(); if(File.Exists(marker)) File.Delete(marker); _=Task.Run(async()=>{await Task.Delay(900);lifetime.StopApplication();}); }
    });
    return Results.Accepted(value:new{action,accepted=true});
});
app.MapGet("/api/controls",()=>store.List<BenchmarkControl>("controls"));
app.MapGet("/api/findings/{id}",(string id)=>Detail(store.Require<Finding>("findings",id)));
app.MapPost("/api/findings",(CreateFindingRequest request,HttpContext context)=>
{
    var control=store.Require<BenchmarkControl>("controls",request.ControlId);
    if(!ValidHostname(request.Hostname))
        throw new PolicyException("INVALID_HOSTNAME","Enter a DNS hostname without command characters, paths, or wildcards.");
    if(!new[]{"MemberServer","DomainController","Workstation"}.Contains(request.Profile)) throw new PolicyException("INVALID_PROFILE","Choose MemberServer, DomainController, or Workstation.");
    if((request.CurrentValue?.Length??0)>50||request.CurrentValue?.Any(v=>v is null||v.Length>512)==true) throw new PolicyException("INVALID_VALUE","Observed values exceed allowed size.");
    var current=request.CurrentValue is null?[]:PolicyValues.Normalize(request.CurrentValue,control.PolicyType);
    var hostname=request.Hostname.ToUpperInvariant(); var targetId=PolicyValues.Hash(hostname)[..24];
    var domain=real?(builder.Configuration["Windows:Domain"]??""):"prosol.az";
    var target=new TargetResource(targetId,request.Hostname,domain,real?"":"OU=Servers,DC=prosol,DC=az","Windows Server",request.Profile);
    var existing=store.Get<TargetResource>("targets",targetId);
    if(existing is not null&&existing.Profile!=request.Profile) throw new PolicyException("TARGET_PROFILE_CONFLICT","An existing target has a different server role; resolve its inventory before proceeding.");
    store.Put("targets",targetId,existing??target);
    // Manually asserted values never establish verified compliance.
    if(request.BenchmarkSelection && !control.Automated)
        throw new PolicyException("UNSUPPORTED_POLICY_TYPE","This benchmark entry does not have an approved remediation adapter.");
    var status=request.BenchmarkSelection?"NOT_SCANNED":"FAIL";
    var finding=new Finding(Guid.NewGuid().ToString(),control.Id,targetId,current,status,PolicyValues.Now());
    store.Put("findings",finding.Id,finding,status); store.Audit("FINDING_CREATED",Operator(context),controlId:control.Id,details:new{finding.Id,target=target.Hostname,source=request.BenchmarkSelection?"benchmark-selection":"manual"});
    return Results.Created($"/api/findings/{finding.Id}",finding);
});
app.MapPost("/api/findings/{id}/analyze",async(string id,HttpContext context,RemediationEngine engine,CancellationToken ct)=>await engine.AnalyzeAsync(id,Operator(context),ct));
app.MapPost("/api/findings/{id}/preview",async(string id,PreviewRequest request,HttpContext context,RemediationEngine engine,CancellationToken ct)=>
{ if(request.Selection is null) throw new PolicyException("INVALID_SELECTION","A target strategy is required."); var result=await engine.PreviewAsync(id,request.Selection,Operator(context),ct); return new{impact=result.Impact,preflight=result.Preflight}; });
app.MapPost("/api/findings/{id}/dry-run",async(string id,JsonElement body,HttpContext context,RemediationEngine engine,CancellationToken ct)=>
{ if(!body.TryGetProperty("previewId",out var p)||p.ValueKind!=JsonValueKind.String) throw new PolicyException("PREVIEW_REQUIRED","Preview ID is required."); return await engine.DryRunAsync(id,p.GetString()!,Operator(context),ct); });
app.MapPost("/api/findings/{id}/apply",(string id,ApplyRequest request,HttpContext context,RemediationEngine engine)=>
{ if(request.Options is null||string.IsNullOrEmpty(request.PreviewId)) throw new PolicyException("INVALID_REQUEST","Preview and job options are required."); var job=engine.Submit(id,request,Operator(context)); return Results.Accepted($"/api/jobs/{job.Id}",job); });
app.MapGet("/api/automation/readiness",async(RemediationEngine engine,CancellationToken ct)=>await engine.ReadinessAsync(ct));
app.MapPost("/api/automation/scan",async(TargetScanRequest request,HttpContext context,RemediationEngine engine,CancellationToken ct)=>
{
    if(!ValidHostname(request.Hostname)) throw new PolicyException("INVALID_HOSTNAME","Enter an exact DNS hostname without wildcards, paths, or command characters.");
    if(!new[]{"Auto","MemberServer","DomainController","Workstation"}.Contains(request.Profile)) throw new PolicyException("INVALID_PROFILE","Choose Auto, MemberServer, DomainController, or Workstation.");
    var hostname=request.Hostname.Trim(); var targetId=PolicyValues.Hash(hostname.ToUpperInvariant())[..24];
    var domain=real?(builder.Configuration["Windows:Domain"]??""):"prosol.az";
    var seed=new TargetResource(targetId,hostname,domain,"","Windows",request.Profile);
    return await engine.ScanTargetAsync(seed,Operator(context),ct);
});
app.MapPost("/api/findings/{id}/safe-plan",async(string id,HttpContext context,RemediationEngine engine,CancellationToken ct)=>await engine.PrepareSafePlanAsync(id,Operator(context),ct));
app.MapGet("/api/setup/config",()=>CurrentSetupConfig());
app.MapPost("/api/setup/config",(SetupConfigRequest request,HttpContext context,IHostApplicationLifetime lifetime)=>
{
    if(!Uri.TryCreate(request.Urls,UriKind.Absolute,out var uri)||uri.Scheme!="https"||!ValidHostname(uri.Host)) throw new PolicyException("INVALID_HTTPS_URL","Use an HTTPS URL with a DNS hostname, for example https://management.example.com:5443.");
    var domain=request.Domain.Trim().ToLowerInvariant(); var dc=request.DomainController.Trim().ToLowerInvariant();
    if(!ValidHostname(domain)||!domain.Contains('.')||!ValidHostname(dc)||!dc.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("INVALID_DOMAIN","Domain and writable DC must be exact DNS names in the same domain.");
    var gpos=CleanList(request.ApprovedGpoIds); var ous=CleanList(request.AuthorizedOus); var hosts=CleanList(request.AllowedHosts); var operators=CleanList(request.AllowedOperators);
    var protectedIds=new HashSet<string>(["31b2f340-016d-11d2-945f-00c04fb984f9","6ac1786c-016f-11d2-945f-00c04fb984f9"],StringComparer.OrdinalIgnoreCase);
    if(gpos.Length==0||gpos.Any(x=>!Guid.TryParse(x,out var id)||protectedIds.Contains(id.ToString()))) throw new PolicyException("INVALID_GPO_ALLOWLIST","Provide one or more approved remediation GPO GUIDs; default domain policies are prohibited.");
    if(ous.Length==0||ous.Any(x=>!x.StartsWith("OU=",StringComparison.OrdinalIgnoreCase)||x.IndexOfAny(['\r','\n','\0'])>=0)) throw new PolicyException("INVALID_OU_ALLOWLIST","Provide exact OU distinguished names beginning with OU=.");
    if(hosts.Length==0||hosts.Any(x=>!ValidHostname(x)||!x.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase))) throw new PolicyException("INVALID_HOST_ALLOWLIST","Provide exact target FQDNs inside the configured domain.");
    if(operators.Length==0||operators.Any(x=>!Regex.IsMatch(x,@"^[^\\/\s]+\\[^\\/\s]+$"))) throw new PolicyException("INVALID_OPERATOR_ALLOWLIST","Use exact Windows identities such as PROSOL\\omar.verdizada.");
    if(real&&!operators.Contains(Operator(context),StringComparer.OrdinalIgnoreCase)) throw new PolicyException("OPERATOR_SELF_LOCKOUT","The active Windows operator must remain in AllowedOperators when saving a live configuration.");
    var backup=request.BackupPath.Trim(); if(!Regex.IsMatch(backup,@"^[A-Za-z]:\\")||backup.IndexOfAny(['\r','\n','\0'])>=0) throw new PolicyException("INVALID_BACKUP_PATH","Use a local absolute Windows path such as C:\\ProgramData\\GpoRemediator\\Backups.");
    var output=new
    {
        Mode="Windows", Urls=request.Urls.Trim(),
        Kestrel=new{Certificates=new{Default=new{Subject=uri.Host,Store="My",Location="LocalMachine",AllowInvalid=false}}},
        Windows=new{EnableWrites=false,Domain=domain,DomainController=dc,ApprovedGpoIds=gpos,AuthorizedOus=ous,AllowedHosts=hosts,AllowedOperators=operators,AllowCreateGpo=false,BackupPath=backup}
    };
    var path=Path.Combine(builder.Environment.ContentRootPath,"appsettings.Local.json"); var temp=path+".tmp";
    ConfigureService(request.AutoRestart,()=> { File.WriteAllText(temp,JsonSerializer.Serialize(output,new JsonSerializerOptions(JsonDefaults.Options){WriteIndented=true})); File.Move(temp,path,true);
    store.Audit("SETUP_CONFIG_SAVED",Operator(context),details:new{domain,domainController=dc,gpoCount=gpos.Length,ouCount=ous.Length,hostCount=hosts.Length,operatorCount=operators.Length,writes=false,autoRestart=request.AutoRestart});
    },lifetime);
    return new{saved=true,restartRequired=true,restartScheduled=request.AutoRestart,writesEnabled=false,path="backend/appsettings.Local.json"};
});
app.MapPost("/api/setup/write-mode",async(WriteModeRequest request,HttpContext context,RemediationEngine engine,IHostApplicationLifetime lifetime,CancellationToken ct)=>
{
    if(!real) throw new PolicyException("WINDOWS_MODE_REQUIRED","Write mode can only be changed after the service has started in Windows mode.");
    var expected=request.Enable?"ENABLE WRITES":"DISABLE WRITES";
    if(!string.Equals(request.Confirmation?.Trim(),expected,StringComparison.Ordinal)) throw new PolicyException("CONFIRMATION_REQUIRED",$"Type {expected} exactly to continue.");
    if(request.Enable)
    {
        var readiness=await engine.ReadinessAsync(ct);
        if(!readiness.Ready) throw new PolicyException("ENVIRONMENT_NOT_READY","All required Windows/AD readiness checks must pass before writes can be enabled.");
    }
    var path=Path.Combine(builder.Environment.ContentRootPath,"appsettings.Local.json");
    if(!File.Exists(path)) throw new PolicyException("CONFIG_NOT_FOUND","Save the Windows configuration first.");
    var node=JsonNode.Parse(File.ReadAllText(path))?.AsObject()??throw new PolicyException("INVALID_CONFIG","The Windows configuration file is invalid JSON.");
    var windows=node["Windows"]?.AsObject()??throw new PolicyException("INVALID_CONFIG","The Windows configuration section is missing.");
    windows["EnableWrites"]=request.Enable;
    ConfigureService(request.AutoRestart,()=> { var temp=path+".tmp"; File.WriteAllText(temp,node.ToJsonString(new JsonSerializerOptions(JsonDefaults.Options){WriteIndented=true})); File.Move(temp,path,true);
    store.Audit(request.Enable?"WRITE_MODE_ENABLE_REQUESTED":"WRITE_MODE_DISABLE_REQUESTED",Operator(context),details:new{enabled=request.Enable,autoRestart=request.AutoRestart});
    },lifetime);
    return new{saved=true,enableWrites=request.Enable,restartRequired=true,restartScheduled=request.AutoRestart};
});
app.MapGet("/api/jobs",()=>store.List<RemediationJob>("jobs"));
app.MapGet("/api/jobs/{id}",(string id)=>
{
    var job=store.Require<RemediationJob>("jobs",id); var b=job.BackupId is null?null:store.Get<GpoBackup>("backups",job.BackupId);
    return new{job,steps=store.Steps(id),backup=b is null?null:new{b.Id,b.JobId,b.GpoId,b.GpoName,b.ControlId,b.Operator,b.CreatedAt,b.TargetId,b.Scope,b.PreviousValue,b.PostWriteVersion},verifications=store.Verifications(id)};
});
app.MapPost("/api/jobs/{id}/verify",(string id,HttpContext context,RemediationEngine engine)=>Results.Accepted($"/api/jobs/{id}",engine.SubmitFollowup(id,"VERIFY",Operator(context))));
app.MapPost("/api/jobs/{id}/rollback",(string id,JsonElement body,HttpContext context,RemediationEngine engine)=>
{ var acknowledged=body.TryGetProperty("acknowledge",out var p)&&p.ValueKind==JsonValueKind.True; return Results.Accepted($"/api/jobs/{id}",engine.SubmitFollowup(id,"ROLLBACK",Operator(context),acknowledged)); });
app.MapGet("/api/audit",()=>new{events=store.AuditEvents().Reverse(),integrityValid=store.AuditIntegrity()});
app.MapGet("/api/settings",(HttpContext context,AdapterRegistry registry)=>new
{
    mode,identityStrategy=real?"Windows Integrated Authentication; process service identity executes":"Simulated local identity",@operator=Operator(context),
    productionRequirements=new[]{"Domain-joined Windows host; Windows PowerShell 5.1; RSAT ActiveDirectory and GroupPolicy modules","HTTPS with Windows Integrated Authentication and an explicit operator allowlist","Delegated read/edit rights to approved GPO GUIDs, target/OU allowlists, endpoint RSoP and WinRM access","Provision and approve dedicated remediation GPOs before production use; backup folder restricted to service administrators"},
    supportedTypes=registry.SupportedTypes,
    limitations=new[]{"MOCK changes only local SQLite. Setup can request a controlled launcher restart into WINDOWS; live policy writes still require explicit write-mode authorization.","Domain account policy and PSO changes require a separate manual workflow.","Production creation/linking of new GPOs is not automated; select an administrator-provisioned approved dedicated GPO.","No SecHard or Nessus integration. Original demonstration policy pack only; validate your licensed benchmark.","Real AD replication, ACLs, security CSE, and endpoint verification require a staging domain validation.","Audit hash chain detects ordinary alterations; a database administrator can rewrite the chain. Export to an external audit sink for production assurance."}
});
var frontendPath=Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath,"..","frontend","dist"));
if(Directory.Exists(frontendPath))
{
    var files=new Microsoft.Extensions.FileProviders.PhysicalFileProvider(frontendPath);
    app.UseDefaultFiles(new DefaultFilesOptions{FileProvider=files}); app.UseStaticFiles(new StaticFileOptions{FileProvider=files});
    app.MapFallback(async context=> { if(context.Request.Path.StartsWithSegments("/api")) {context.Response.StatusCode=404; await context.Response.WriteAsJsonAsync(new{code="NOT_FOUND",message="API route does not exist."});} else { context.Response.ContentType="text/html; charset=utf-8"; await context.Response.SendFileAsync(Path.Combine(frontendPath,"index.html")); } });
}
await app.RunAsync();

public partial class Program { }
