using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.DataProtection;

var builder=WebApplication.CreateBuilder(args);
// Recovery setup must remain reachable even when the saved JSON or HTTPS configuration is broken.
var localSetup=builder.Configuration.GetValue<bool>("LocalSetup");
if(!localSetup) builder.Configuration.AddJsonFile("appsettings.Local.json",optional:true,reloadOnChange:false);
builder.Configuration.AddEnvironmentVariables().AddCommandLine(args);
if(localSetup) builder.Configuration["Mode"]="Setup";
var configuredMode=builder.Configuration["Mode"]??"Windows";
if(!new[]{"Setup","Windows"}.Contains(configuredMode,StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException("Mode must be Setup or Windows.");
var real=configuredMode.Equals("Windows",StringComparison.OrdinalIgnoreCase);
var setup=configuredMode.Equals("Setup",StringComparison.OrdinalIgnoreCase);
var mode=real?"WINDOWS":"SETUP";
var dbPath=builder.Configuration["DatabasePath"]??Path.Combine(builder.Environment.ContentRootPath,"data",real?"windows.db":"setup.db");
// One worker per durable database. A second service must not replay or interleave privileged jobs.
using var databaseLock=new Mutex(false,"GpoRemediator-"+PolicyValues.Hash(Path.GetFullPath(dbPath))[..24]);
bool ownsLock;
try { ownsLock=databaseLock.WaitOne(0); } catch(AbandonedMutexException) { ownsLock=true; }
if(!ownsLock) throw new InvalidOperationException("Another GPO Remediator process is already using this database.");
builder.WebHost.ConfigureKestrel(o=>o.Limits.MaxRequestBodySize=32*1024);
builder.Services.ConfigureHttpJsonOptions(o=>o.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter()));
builder.Services.AddAntiforgery(o=> { o.HeaderName="X-CSRF-Token"; o.Cookie.Name="GpoRemediator.Csrf"; o.Cookie.HttpOnly=true; o.Cookie.SameSite=SameSiteMode.Strict; o.Cookie.SecurePolicy=CookieSecurePolicy.SameAsRequest; });
builder.Services.AddDataProtection().SetApplicationName("GpoRemediator");
if(real) { builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate(); builder.Services.AddAuthorization(); }
builder.Services.AddSingleton(new Store(dbPath));
builder.Services.AddSingleton<OperationGate>();
builder.Services.AddSingleton<GpoWorkflowService>();
var app=builder.Build();
var store=app.Services.GetRequiredService<Store>();
store.BindExecutionMode(mode);
var interruptedRuns=store.RecoverInterruptedGpoRuns();
if(interruptedRuns>0) app.Logger.LogWarning("Recovered {Count} interrupted GPO operation record(s) into REVIEW_REQUIRED state.",interruptedRuns);
app.Use(async(context,next)=>
{
    context.Response.Headers["X-Content-Type-Options"]="nosniff";
    context.Response.Headers["X-Frame-Options"]="DENY";
    context.Response.Headers["Referrer-Policy"]="no-referrer";
    context.Response.Headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
    if(context.Request.Path.StartsWithSegments("/api")) context.Response.Headers.CacheControl="no-store";
    try
    {
        if(!IPAddress.IsLoopback(context.Connection.RemoteIpAddress??IPAddress.None) || !new[]{"localhost","127.0.0.1","::1"}.Contains(context.Request.Host.Host))
            throw new PolicyException("LOOPBACK_ONLY","GPO Remediator is local-only in this release. Open it from localhost on the management server.");
        await next(context);
    }
    catch(AntiforgeryValidationException) { context.Response.StatusCode=403; await context.Response.WriteAsJsonAsync(new{code="CSRF_INVALID",message="Refresh the session and retry the request with its anti-forgery token."}); }
    catch(PolicyException ex)
    {
        context.Response.StatusCode=ex.Code=="NOT_FOUND"?404:ex.Code is "LOOPBACK_ONLY" or "OPERATOR_DENIED" or "ORIGIN_DENIED"?403:409;
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
    if(setup && context.Request.Path.StartsWithSegments("/api") &&
       !context.Request.Path.StartsWithSegments("/api/setup") &&
       !context.Request.Path.StartsWithSegments("/api/session") &&
       !context.Request.Path.StartsWithSegments("/api/service"))
        throw new PolicyException("WINDOWS_MODE_REQUIRED","Setup mode is configuration-only. Save the Windows / AD settings and restart into Windows mode for discovery, preview, apply, verify, rollback, or gpupdate.");
    if(context.Request.Path.StartsWithSegments("/api")&&!HttpMethods.IsGet(context.Request.Method)&&!HttpMethods.IsHead(context.Request.Method))
    {
        var origin=context.Request.Headers.Origin.ToString();
        var expected=$"{context.Request.Scheme}://{context.Request.Host}";
        if(!string.Equals(origin,expected,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("ORIGIN_DENIED","Mutation requests must come from this application's exact origin.");
        await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context);
        var path=context.Request.Path.Value!;
        if(real&&!builder.Configuration.GetValue<bool>("Windows:EnableWrites") && context.Request.Path.StartsWithSegments("/api/gpo") && (path.EndsWith("/apply")||path.EndsWith("/rollback")))
            throw new PolicyException("WRITES_DISABLED","Enable writes in Settings before Apply or Rollback. Discovery, preview and verification remain read-only.");
    }
    await next(context);
});
string Operator(HttpContext context)=>real?context.User.Identity!.Name!:"SETUP\\local-configuration";
bool ValidHostname(string value)=>!string.IsNullOrWhiteSpace(value)&&value.Length<=253&&Regex.IsMatch(value,@"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
string[] CleanList(string[]? values)=>values?.Select(x=>x.Trim()).Where(x=>x.Length>0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()??[];
string RestartMarkerPath()=>Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath,"..","work","restart.request.json"));
void ConfigureService(bool restart,Action save,IHostApplicationLifetime lifetime)
{
    var gate=app.Services.GetRequiredService<OperationGate>();
    if(restart&&!builder.Configuration.GetValue<bool>("LauncherManaged")) throw new PolicyException("LAUNCHER_REQUIRED","Use GpoRemediator.cmd before saving with an automatic restart.");
    // Serialize config saves with job submissions and other lifecycle requests.
    gate.BeginMaintenance(()=>{ save(); if(restart) ScheduleRestart(lifetime,"Windows"); });
    if(!restart) gate.EndMaintenance();
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
            return new SetupConfigView(Text(root,"Urls","http://127.0.0.1:5080"),Text(win,"Domain"),Text(win,"DomainController"),Array(win,"ApprovedGpoIds"),Array(win,"AuthorizedOus"),Array(win,"AllowedHosts"),Array(win,"AllowedOperators"),Text(win,"BackupPath",@"C:\ProgramData\GpoRemediator\Backups"),Flag(win,"EnableWrites"),"backend/appsettings.Local.json",true);
        }
        catch(JsonException) { }
    }
    var section=builder.Configuration.GetSection("Windows");
    var operatorDefaults=section.GetSection("AllowedOperators").Get<string[]>()??[];
    if(operatorDefaults.Length==0&&OperatingSystem.IsWindows()&&!string.IsNullOrWhiteSpace(Environment.UserName)) operatorDefaults=[$"{Environment.UserDomainName}\\{Environment.UserName}"];
    return new SetupConfigView(builder.Configuration["Urls"]??"http://127.0.0.1:5080",section["Domain"]??"",section["DomainController"]??"",section.GetSection("ApprovedGpoIds").Get<string[]>()??[],section.GetSection("AuthorizedOus").Get<string[]>()??[],section.GetSection("AllowedHosts").Get<string[]>()??[],operatorDefaults,section["BackupPath"]??@"C:\ProgramData\GpoRemediator\Backups",section.GetValue<bool>("EnableWrites"),"backend/appsettings.Local.json",false);
}
app.MapGet("/api/session",(HttpContext context,IAntiforgery csrf)=>new {mode,@operator=Operator(context),csrfToken=csrf.GetAndStoreTokens(context).RequestToken,identityStrategy=real?"WindowsIntegrated / delegated GPO execution":"Local setup only",realModeEnabled=real,setupRequired=localSetup});
app.MapGet("/api/service",(OperationGate gate)=>new {
    mode, processId=Environment.ProcessId, stopping=gate.Maintenance,
    managed=builder.Configuration.GetValue<bool>("LauncherManaged"),
    writesEnabled=real&&builder.Configuration.GetValue<bool>("Windows:EnableWrites"),
    activeJobs=store.List<GpoWorkflowRun>("gpo_runs").Count(j=>j.Result.State.EndsWith("ING",StringComparison.OrdinalIgnoreCase))
});
app.MapPost("/api/service/{action}",(string action,HttpContext context,OperationGate gate,IHostApplicationLifetime lifetime)=>
{
    if(action is not ("stop" or "restart")) throw new PolicyException("INVALID_ACTION","Choose stop or restart.");
    if(!builder.Configuration.GetValue<bool>("LauncherManaged")) throw new PolicyException("LAUNCHER_REQUIRED","Start the application from GpoRemediator.cmd to use service controls.");
    gate.BeginMaintenance(()=> {
        store.Audit(action=="stop"?"SERVICE_STOP_REQUESTED":"SERVICE_RESTART_REQUESTED",Operator(context),details:new{mode});
        if(action=="restart") ScheduleRestart(lifetime,real?"Windows":"Setup");
        else { var marker=RestartMarkerPath(); if(File.Exists(marker)) File.Delete(marker); _=Task.Run(async()=>{await Task.Delay(900);lifetime.StopApplication();}); }
    });
    return Results.Accepted(value:new{action,accepted=true});
});
string GpoToken(HttpContext context)=>context.Request.Cookies["GpoRemediator.GpoConnection"]??"";
app.MapPost("/api/gpo/connect",async(GpoLoginRequest request,HttpContext context,GpoWorkflowService service,CancellationToken ct)=>{
    var connected=await service.ConnectAsync(request,Operator(context),ct);
    service.Disconnect(GpoToken(context));
    context.Response.Cookies.Append("GpoRemediator.GpoConnection",connected.Token,new CookieOptions{HttpOnly=true,Secure=context.Request.IsHttps,SameSite=SameSiteMode.Strict,Path="/api/gpo",MaxAge=TimeSpan.FromMinutes(10)});
    return connected.Inventory;
});
app.MapPost("/api/gpo/disconnect",(HttpContext context,GpoWorkflowService service)=>{service.Disconnect(GpoToken(context));context.Response.Cookies.Delete("GpoRemediator.GpoConnection",new CookieOptions{Path="/api/gpo"});return new{disconnected=true};});
app.MapGet("/api/gpo/inventory",(HttpContext context,GpoWorkflowService service)=>service.Inventory(GpoToken(context),Operator(context)));
app.MapGet("/api/gpo/readiness",async(HttpContext context,GpoWorkflowService service,CancellationToken ct)=>await service.ReadinessAsync(GpoToken(context),Operator(context),ct));
app.MapPost("/api/gpo/discover",async(HttpContext context,GpoWorkflowService service,CancellationToken ct)=>await service.DiscoverAsync(GpoToken(context),Operator(context),ct));
app.MapGet("/api/gpo/settings",()=>ProductionGpoMappings.Settings);
app.MapGet("/api/gpo/history",(HttpContext context,GpoWorkflowService service)=>service.History(Operator(context)));
app.MapGet("/api/gpo/{id}/evidence",(string id,HttpContext context,GpoWorkflowService service)=>service.Evidence(id,Operator(context)));
app.MapPost("/api/gpo/preview",async(GpoSelection request,HttpContext context,GpoWorkflowService service,CancellationToken ct)=>await service.PreviewAsync(GpoToken(context),Operator(context),request,ct));
app.MapPost("/api/gpo/{id}/apply",async(string id,GpoConsent request,HttpContext context,GpoWorkflowService service)=>await service.ExecuteAsync(id,"apply",request,GpoToken(context),Operator(context)));
app.MapPost("/api/gpo/{id}/rollback",async(string id,GpoConsent request,HttpContext context,GpoWorkflowService service)=>await service.ExecuteAsync(id,"rollback",request,GpoToken(context),Operator(context)));
app.MapPost("/api/gpo/{id}/verify",async(string id,HttpContext context,GpoWorkflowService service)=>await service.ExecuteAsync(id,"verify",new(""),GpoToken(context),Operator(context)));
app.MapGet("/api/setup/discover",() =>
{
    if(!OperatingSystem.IsWindows()) throw new PolicyException("WINDOWS_REQUIRED","Automatic setup discovery is available only on Windows. Enter the domain and writable DC manually.");
    var warnings=new List<string>();
    var domain=(IPGlobalProperties.GetIPGlobalProperties().DomainName??"").Trim().Trim('.').ToLowerInvariant();
    if(string.IsNullOrWhiteSpace(domain)||!domain.Contains('.')) warnings.Add("The machine DNS domain suffix could not be detected reliably. Enter the AD DNS domain manually.");
    var logon=(Environment.GetEnvironmentVariable("LOGONSERVER")??"").Trim().TrimStart('\\');
    var dc=logon.ToLowerInvariant();
    if(!string.IsNullOrWhiteSpace(dc)&&!dc.Contains('.')&&!string.IsNullOrWhiteSpace(domain)) dc+="."+domain;
    if(string.IsNullOrWhiteSpace(dc)) warnings.Add("LOGONSERVER did not identify a domain controller. Enter the writable DC FQDN manually.");
    var identity=WindowsIdentity.GetCurrent().Name??"";
    if(string.IsNullOrWhiteSpace(identity)||!identity.Contains('\\')) warnings.Add("The current Windows identity is not a DOMAIN\\user identity; verify AllowedOperators manually.");
    return new {domain,domainController=dc,@operator=identity,backupPath=@"C:\ProgramData\GpoRemediator\Backups",warnings=warnings.ToArray()};
});
app.MapGet("/api/setup/config",()=>CurrentSetupConfig());
app.MapPost("/api/setup/config",(SetupConfigRequest request,HttpContext context,IHostApplicationLifetime lifetime)=>
{
    var localUrl=$"http://127.0.0.1:{context.Request.Host.Port??5080}";
    var domain=request.Domain.Trim().ToLowerInvariant(); var dc=request.DomainController.Trim().ToLowerInvariant();
    if(!ValidHostname(domain)||!domain.Contains('.')||!ValidHostname(dc)||!dc.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("INVALID_DOMAIN","Domain and writable DC must be exact DNS names in the same domain.");
    var gpos=CleanList(request.ApprovedGpoIds); var ous=CleanList(request.AuthorizedOus); var hosts=CleanList(request.AllowedHosts); var operators=CleanList(request.AllowedOperators);
    // GPOs and OUs are discovered after authentication; stale manual allowlist values are deliberately discarded.
    gpos=[]; ous=[]; hosts=[];
    if(operators.Length==0||operators.Any(x=>!Regex.IsMatch(x,@"^[^\\/\s]+\\[^\\/\s]+$"))) throw new PolicyException("INVALID_OPERATOR_ALLOWLIST","Use exact Windows identities such as PROSOL\\omar.verdizada.");
    if(real&&!operators.Contains(Operator(context),StringComparer.OrdinalIgnoreCase)) throw new PolicyException("OPERATOR_SELF_LOCKOUT","The active Windows operator must remain in AllowedOperators when saving a live configuration.");
    var backup=request.BackupPath.Trim(); if(!Regex.IsMatch(backup,@"^[A-Za-z]:\\")||backup.IndexOfAny(['\r','\n','\0'])>=0) throw new PolicyException("INVALID_BACKUP_PATH","Use a local absolute Windows path such as C:\\ProgramData\\GpoRemediator\\Backups.");
    var output=new
    {
        Mode="Windows", Urls=localUrl,
        Windows=new{Workflow="GpoRemediation",EnableWrites=false,Domain=domain,DomainController=dc,ApprovedGpoIds=gpos,AuthorizedOus=ous,AllowedHosts=hosts,AllowedOperators=operators,AllowCreateGpo=false,BackupPath=backup}
    };
    var path=Path.Combine(builder.Environment.ContentRootPath,"appsettings.Local.json"); var temp=path+".tmp";
    ConfigureService(request.AutoRestart,()=> { File.WriteAllText(temp,JsonSerializer.Serialize(output,new JsonSerializerOptions(JsonDefaults.Options){WriteIndented=true})); File.Move(temp,path,true);
    store.Audit("SETUP_CONFIG_SAVED",Operator(context),details:new{domain,domainController=dc,gpoCount=gpos.Length,ouCount=ous.Length,hostCount=hosts.Length,operatorCount=operators.Length,writes=false,autoRestart=request.AutoRestart});
    },lifetime);
    return new{saved=true,restartRequired=true,restartScheduled=request.AutoRestart,writesEnabled=false,path="backend/appsettings.Local.json"};
});
app.MapPost("/api/setup/write-mode",async(WriteModeRequest request,HttpContext context,GpoWorkflowService gpo,IHostApplicationLifetime lifetime,CancellationToken ct)=>
{
    if(!real) throw new PolicyException("WINDOWS_MODE_REQUIRED","Write mode can only be changed after the service has started in Windows mode.");
    var expected=request.Enable?"ENABLE WRITES":"DISABLE WRITES";
    if(!string.Equals(request.Confirmation?.Trim(),expected,StringComparison.Ordinal)) throw new PolicyException("CONFIRMATION_REQUIRED",$"Type {expected} exactly to continue.");
    if(request.Enable)
    {
        var readiness=await gpo.ReadinessAsync(GpoToken(context),Operator(context),ct);
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
app.MapGet("/api/audit",()=>new{events=store.AuditEvents().Reverse(),integrityValid=store.AuditIntegrity()});
app.MapGet("/api/settings",(HttpContext context)=>new
{
    mode,identityStrategy=real?"Windows Integrated Authentication plus short-lived delegated GPO execution credentials":"Configuration only",@operator=Operator(context),
    benchmark=ProductionGpoMappings.Catalog.Meta.Benchmark, mappedControls=ProductionGpoMappings.Catalog.Meta.Mapped,
    handlers=ProductionGpoMappings.Settings.Select(x=>x.Handler).Distinct().OrderBy(x=>x).ToArray(),
    productionRequirements=new[]{"Domain-connected Windows management host with Kerberos/WinRM access to a writable DC; AD/GroupPolicy modules are validated on that DC","Local-only HTTP on 127.0.0.1","Delegated or administrative authority to edit the selected GPO, its SYSVOL content where required, and the selected gPLink","Local Backup-GPO repository writable on the selected DC"},
    safetyPipeline=new[]{"server-authoritative CIS mapping","environment and selection preflight","stale-plan fingerprint check","exclusive per-GPO lock","full Backup-GPO before writes","idempotent mapping write","link read-back","AD/SYSVOL version verification","optional bounded gpupdate scheduling","conflict-aware full snapshot rollback","append-only hash-chained audit and evidence"}
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
