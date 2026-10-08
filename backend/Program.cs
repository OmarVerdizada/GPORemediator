using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Security.Claims;
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
builder.Configuration.AddEnvironmentVariables().AddCommandLine(args);
var localSetup=builder.Configuration.GetValue<bool>("LocalSetup");
var localConfigPath=Path.GetFullPath(builder.Configuration["LocalConfigPath"]??Path.Combine(builder.Environment.ContentRootPath,"appsettings.Local.json"));
if(!localSetup) builder.Configuration.AddJsonFile(new Microsoft.Extensions.FileProviders.PhysicalFileProvider(Path.GetDirectoryName(localConfigPath)!),Path.GetFileName(localConfigPath),optional:true,reloadOnChange:false);
builder.Configuration.AddEnvironmentVariables().AddCommandLine(args);
if(localSetup) builder.Configuration["Mode"]="Setup";
var configuredMode=builder.Configuration["Mode"]??"Windows";
if(!new[]{"Setup","Windows"}.Contains(configuredMode,StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException("Mode must be Setup or Windows.");
var real=configuredMode.Equals("Windows",StringComparison.OrdinalIgnoreCase);
var setup=configuredMode.Equals("Setup",StringComparison.OrdinalIgnoreCase);
var mode=real?"WINDOWS":"SETUP";
var setupOwner=OperatingSystem.IsWindows()?(WindowsIdentity.GetCurrent().Name??""):Environment.UserName;
// The desktop console runs as its launcher owner. Windows authentication is
// optional for installations that deliberately require per-browser identities.
var windowsOperatorAuth=string.Equals(builder.Configuration["OperatorAuthentication"],"Windows",StringComparison.OrdinalIgnoreCase);
var programData=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
var dataRoot=Path.Combine(programData,"GpoRemediator","Data");
Directory.CreateDirectory(dataRoot);
var dbPath=builder.Configuration["DatabasePath"]??Path.Combine(dataRoot,real?"windows.db":"setup.db");
// One worker per durable database. A second service must not replay or interleave privileged jobs.
using var databaseLock=new Mutex(false,"Global\\GpoRemediator-"+PolicyValues.Hash(Path.GetFullPath(dbPath))[..24]);
bool ownsLock;
try { ownsLock=databaseLock.WaitOne(0); } catch(AbandonedMutexException) { ownsLock=true; }
if(!ownsLock) throw new InvalidOperationException("Another GPO Remediator process is already using this database.");
builder.WebHost.ConfigureKestrel(o=>o.Limits.MaxRequestBodySize=32*1024);
builder.Services.ConfigureHttpJsonOptions(o=>o.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter()));
builder.Services.AddAntiforgery(o=> { o.HeaderName="X-CSRF-Token"; o.Cookie.Name="GpoRemediator.Csrf"; o.Cookie.HttpOnly=true; o.Cookie.SameSite=SameSiteMode.Strict; o.Cookie.SecurePolicy=CookieSecurePolicy.SameAsRequest; });
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataRoot,"Keys"))).SetApplicationName("GpoRemediator");
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization();
builder.Services.AddSingleton(new Store(dbPath));
builder.Services.AddSingleton<OperationGate>();
builder.Services.AddSingleton<GpoWorkflowService>();
builder.Services.AddSingleton<WindowsPowerShellExecutor>();
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
    var correlationId=context.Request.Headers["X-Correlation-ID"].FirstOrDefault();
    if(string.IsNullOrWhiteSpace(correlationId)||correlationId.Length>128||!Regex.IsMatch(correlationId,"^[A-Za-z0-9._-]+$")) correlationId=Guid.NewGuid().ToString("N");
    context.Items["CorrelationId"]=correlationId;
    context.Response.Headers["X-Correlation-ID"]=correlationId;
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
        context.Response.StatusCode=ex.Code switch {
            "NOT_FOUND"=>404,
            "GPO_LOGIN_REQUIRED"=>401,
            "LOOPBACK_ONLY" or "OPERATOR_DENIED" or "SETUP_OPERATOR_DENIED" or "ROLE_DENIED" or "ORIGIN_DENIED"=>403,
            "INVALID_REQUEST" or "INVALID_DOMAIN" or "INVALID_SCOPE_ALLOWLIST" or "INVALID_GPO_ALLOWLIST" or "INVALID_BACKUP_PATH"=>422,
            "GPO_OPERATION_BUSY" or "SERVICE_STOPPING"=>423,
            "WINDOWS_TIMEOUT"=>504,
            "WINDOWS_REQUIRED" or "POWERSHELL_START_FAILED"=>503,
            _=>409 };
        await context.Response.WriteAsJsonAsync(new{code=ex.Code,category=ErrorCategory(ex.Code),correlationId=context.Items["CorrelationId"],message=Redactor.Clean(ex.Message)});
    }
    catch(BadHttpRequestException) { context.Response.StatusCode=400; await context.Response.WriteAsJsonAsync(new{code="INVALID_REQUEST",message="The request format or values are invalid."}); }
    catch(JsonException) { context.Response.StatusCode=400; await context.Response.WriteAsJsonAsync(new{code="INVALID_JSON",message="Request must contain valid typed JSON."}); }
    catch(Exception ex) { app.Logger.LogError(ex,"Request {CorrelationId} failed for {Method} {Path}",context.Items["CorrelationId"],context.Request.Method,context.Request.Path); context.Response.StatusCode=500; await context.Response.WriteAsJsonAsync(new{code="INTERNAL_ERROR",correlationId=context.Items["CorrelationId"],message="The operation could not complete. Review the protected diagnostic log with this correlation ID."}); }
});
if(windowsOperatorAuth) app.UseAuthentication();
else app.Use(async(context,next)=>
{
    context.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name,setupOwner)],"LocalLauncher"));
    await next(context);
});
app.UseAuthorization();
app.Use(async(context,next)=>
{
    if(!context.Request.Path.StartsWithSegments("/api/v1/health"))
    {
        if(context.User.Identity?.IsAuthenticated!=true) { await context.ChallengeAsync(); return; }
        if(real && Role(context)=="Denied") throw new PolicyException("OPERATOR_DENIED","Your Windows identity has no configured GPO Remediator role.");
        if(setup && !string.Equals(WindowsAccount.Normalize(context.User.Identity.Name??""),WindowsAccount.Normalize(setupOwner),StringComparison.OrdinalIgnoreCase))
            throw new PolicyException("SETUP_OPERATOR_DENIED","Setup is restricted to the Windows identity that launched the service.");
    }
    if(setup && context.Request.Path.StartsWithSegments("/api") &&
       !context.Request.Path.StartsWithSegments("/api/v1/health") &&
       !context.Request.Path.StartsWithSegments("/api/setup") &&
       !context.Request.Path.StartsWithSegments("/api/session") &&
       !context.Request.Path.StartsWithSegments("/api/service"))
        throw new PolicyException("WINDOWS_MODE_REQUIRED","Setup mode is configuration-only. Save the Windows / AD settings and restart into Windows mode for discovery, preview, apply, verify, rollback, or gpupdate.");
    if(real && context.Request.Path.StartsWithSegments("/api"))
    {
        var path=context.Request.Path.Value??"";
        if(path.StartsWith("/api/setup",StringComparison.OrdinalIgnoreCase)||path.StartsWith("/api/service",StringComparison.OrdinalIgnoreCase)) RequireRole(context,"Administrator");
        else if(path.StartsWith("/api/audit",StringComparison.OrdinalIgnoreCase)) RequireRole(context,"Administrator","Auditor");
        else if(path.EndsWith("/apply",StringComparison.OrdinalIgnoreCase)||path.EndsWith("/rollback",StringComparison.OrdinalIgnoreCase)||path.EndsWith("/refresh",StringComparison.OrdinalIgnoreCase)) RequireRole(context,"Administrator","Remediator");
        else RequireRole(context,"Administrator","Remediator","Auditor","Viewer");
    }
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
string ErrorCategory(string code)=>code switch
{
    var x when x.StartsWith("AUTH_",StringComparison.OrdinalIgnoreCase) || x.Contains("LOGIN",StringComparison.OrdinalIgnoreCase) || x.Contains("CREDENTIAL",StringComparison.OrdinalIgnoreCase) || x=="OPERATOR_DENIED" => "AUTH",
    var x when x.StartsWith("GPO_",StringComparison.OrdinalIgnoreCase) || x.Contains("ROLLBACK",StringComparison.OrdinalIgnoreCase) || x.Contains("MAPPING",StringComparison.OrdinalIgnoreCase) => "GPO",
    var x when x.StartsWith("AD_",StringComparison.OrdinalIgnoreCase) || x.Contains("DIRECTORY",StringComparison.OrdinalIgnoreCase) || x.Contains("LDAP",StringComparison.OrdinalIgnoreCase) => "AD",
    var x when x.Contains("SYSVOL",StringComparison.OrdinalIgnoreCase) || x.Contains("REPLICATION",StringComparison.OrdinalIgnoreCase) => "SYSVOL",
    var x when x.Contains("REFRESH",StringComparison.OrdinalIgnoreCase) || x.Contains("ENDPOINT",StringComparison.OrdinalIgnoreCase) => "REFRESH",
    var x when x.Contains("SERVICE",StringComparison.OrdinalIgnoreCase) || x.Contains("LAUNCHER",StringComparison.OrdinalIgnoreCase) => "SERVICE",
    _ => "GENERAL"
};
string Operator(HttpContext context)=>context.User.Identity?.Name??(setup?"SETUP\\local-configuration":"UNKNOWN");
string Role(HttpContext context)
{
    if(setup) return "Administrator";
    var actor=WindowsAccount.Normalize(context.User.Identity?.Name??"");
    bool In(string key)=>(builder.Configuration.GetSection("Windows:Roles:"+key).Get<string[]>()??[]).Select(WindowsAccount.Normalize).Contains(actor,StringComparer.OrdinalIgnoreCase);
    if(In("Administrators")) return "Administrator";
    if(In("Remediators")) return "Remediator";
    if(In("Auditors")) return "Auditor";
    if(In("Viewers")) return "Viewer";
    // Compatibility for configurations created before roles were introduced.
    if((builder.Configuration.GetSection("Windows:AllowedOperators").Get<string[]>()??[]).Select(WindowsAccount.Normalize).Contains(actor,StringComparer.OrdinalIgnoreCase)) return "Administrator";
    return "Denied";
}
void RequireRole(HttpContext context,params string[] roles)
{
    if(!roles.Contains(Role(context),StringComparer.OrdinalIgnoreCase)) throw new PolicyException("ROLE_DENIED","This action is not permitted for the authenticated operator role.");
}
bool ValidHostname(string value)=>!string.IsNullOrWhiteSpace(value)&&value.Length<=253&&Regex.IsMatch(value,@"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
string[] CleanList(string[]? values)=>values?.Select(x=>x.Trim()).Where(x=>x.Length>0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()??[];
string RestartMarkerPath()=>Path.Combine(programData,"GpoRemediator","State","restart.request.json");
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
    var path=localConfigPath;
    if(File.Exists(path))
    {
        try
        {
            using var doc=JsonDocument.Parse(File.ReadAllText(path)); var root=doc.RootElement;
            JsonElement Property(JsonElement element,string name)=>element.ValueKind==JsonValueKind.Object
                ?element.EnumerateObject().FirstOrDefault(p=>p.Name.Equals(name,StringComparison.OrdinalIgnoreCase)).Value:default;
            var win=Property(root,"Windows");
            string Text(JsonElement element,string name,string fallback="")=>Property(element,name) is var value&&value.ValueKind==JsonValueKind.String?(value.GetString()??fallback):fallback;
            bool Flag(JsonElement element,string name)=>Property(element,name).ValueKind==JsonValueKind.True;
            string[] Array(JsonElement element,string name)=>Property(element,name) is var value&&value.ValueKind==JsonValueKind.Array?value.EnumerateArray().Where(v=>v.ValueKind==JsonValueKind.String).Select(v=>v.GetString()!).Where(v=>!string.IsNullOrWhiteSpace(v)).ToArray():[];
            var roles=Property(win,"Roles");
            return new SetupConfigView(Text(root,"Urls","http://127.0.0.1:5080"),Text(win,"Domain"),Text(win,"DomainController"),Array(win,"ApprovedGpoIds"),Array(win,"AuthorizedOus"),Array(win,"AllowedHosts"),Array(win,"AllowedOperators"),Text(win,"BackupPath",@"C:\ProgramData\GpoRemediator\Backups"),Flag(win,"EnableWrites"),localConfigPath,true,Array(roles,"Remediators"),Array(roles,"Auditors"),Array(roles,"Viewers"));
        }
        catch(JsonException) { }
    }
    var section=builder.Configuration.GetSection("Windows");
    var operatorDefaults=section.GetSection("AllowedOperators").Get<string[]>()??[];
    if(operatorDefaults.Length==0&&OperatingSystem.IsWindows()&&!string.IsNullOrWhiteSpace(Environment.UserName)) operatorDefaults=[$"{Environment.UserDomainName}\\{Environment.UserName}"];
    var rolesSection=section.GetSection("Roles");
    return new SetupConfigView(builder.Configuration["Urls"]??"http://127.0.0.1:5080",section["Domain"]??"",section["DomainController"]??"",section.GetSection("ApprovedGpoIds").Get<string[]>()??[],section.GetSection("AuthorizedOus").Get<string[]>()??[],section.GetSection("AllowedHosts").Get<string[]>()??[],operatorDefaults,section["BackupPath"]??@"C:\ProgramData\GpoRemediator\Backups",section.GetValue<bool>("EnableWrites"),localConfigPath,false,rolesSection.GetSection("Remediators").Get<string[]>()??[],rolesSection.GetSection("Auditors").Get<string[]>()??[],rolesSection.GetSection("Viewers").Get<string[]>()??[]);
}
app.MapGet("/api/v1/health/live",()=>Results.Ok(new{status="live",version="1.0"}));
app.MapGet("/api/v1/health/ready",()=>Results.Ok(new{status="ready",mode,database=true}));
app.MapGet("/api/session",(HttpContext context,IAntiforgery csrf)=>new {mode,@operator=Operator(context),role=Role(context),csrfToken=csrf.GetAndStoreTokens(context).RequestToken,identityStrategy=windowsOperatorAuth?"Authenticated Windows operator plus explicit delegated execution identity":"Local launcher owner plus explicit delegated execution identity",realModeEnabled=real,setupRequired=localSetup});
app.MapGet("/api/service",(OperationGate gate)=>new {
    mode, processId=Environment.ProcessId, stopping=gate.Maintenance,
    managed=builder.Configuration.GetValue<bool>("LauncherManaged"),
    writesEnabled=real&&builder.Configuration.GetValue<bool>("Windows:EnableWrites"),
    activeJobs=store.CountActiveGpoRuns()
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
    context.Response.Cookies.Append("GpoRemediator.GpoConnection",connected.Token,new CookieOptions{HttpOnly=true,Secure=context.Request.IsHttps,SameSite=SameSiteMode.Strict,Path="/api"});
    return connected.Inventory;
});
app.MapPost("/api/gpo/disconnect",(HttpContext context,GpoWorkflowService service)=>{service.Disconnect(GpoToken(context));context.Response.Cookies.Delete("GpoRemediator.GpoConnection",new CookieOptions{Path="/api"});return new{disconnected=true};});
app.MapGet("/api/gpo/inventory",(HttpContext context,GpoWorkflowService service)=>service.Inventory(GpoToken(context),Operator(context)));
app.MapGet("/api/gpo/session",(HttpContext context,GpoWorkflowService service)=>service.SessionStatus(GpoToken(context),Operator(context)));
app.MapGet("/api/gpo/readiness",async(HttpContext context,GpoWorkflowService service,CancellationToken ct)=>await service.ReadinessAsync(GpoToken(context),Operator(context),ct));
app.MapPost("/api/gpo/discover",async(HttpContext context,GpoWorkflowService service,CancellationToken ct)=>await service.DiscoverAsync(GpoToken(context),Operator(context),ct));
app.MapGet("/api/gpo/settings",()=>ProductionGpoMappings.Settings.Select(x=>new {
    x.Id,x.ControlId,x.Title,x.Category,x.Level,x.Automation,x.Handler,x.Recommended,x.Scope,x.RequiresInput,x.InputType,x.InputLabel,x.InputDefault,
    x.AllowValueOverride,x.Minimum,x.Maximum,x.Suggested,x.Unit,x.Comparator,x.DomainPolicySensitive,x.RequiresGpUpdate,x.RequiresRestart,x.Warnings,x.Source,x.Writable,
    operationalImpact=x.DomainPolicySensitive||x.RequiresRestart?"HIGH":x.RequiresGpUpdate||x.Handler is "SecurityTemplate" or "AdvancedAudit"?"MEDIUM":"LOW",
    impactReason=x.DomainPolicySensitive?"Domain-wide authentication or lockout behavior may change.":x.RequiresRestart?"A restart-sensitive policy is involved.":x.RequiresGpUpdate?"Endpoint policy refresh and staged verification are required.":"The mapping is scoped and still requires preview and verification.",
    impactReasonAz=x.DomainPolicySensitive?"Domen üzrə autentifikasiya və ya kilidlənmə davranışı dəyişə bilər.":x.RequiresRestart?"Restart-a həssas siyasət iştirak edir.":x.RequiresGpUpdate?"Endpoint siyasət yenilənməsi və mərhələli yoxlama tələb olunur.":"Mapping məhdud scope üçündür, lakin preview və sonrakı yoxlama yenə tələb olunur."
}));
app.MapGet("/api/gpo/history",(HttpContext context,GpoWorkflowService service)=>service.History(Operator(context)));
app.MapGet("/api/gpo/{id}/evidence",(string id,HttpContext context,GpoWorkflowService service)=>service.Evidence(id,Operator(context)));
app.MapPost("/api/gpo/preview",async(GpoSelection request,HttpContext context,GpoWorkflowService service,CancellationToken ct)=>await service.PreviewAsync(GpoToken(context),Operator(context),request,ct));
app.MapPost("/api/gpo/{id}/apply",async(string id,GpoConsent request,HttpContext context,GpoWorkflowService service)=>await service.ExecuteAsync(id,"apply",request,GpoToken(context),Operator(context)));
app.MapPost("/api/gpo/{id}/rollback",async(string id,GpoConsent request,HttpContext context,GpoWorkflowService service)=>await service.ExecuteAsync(id,"rollback",request,GpoToken(context),Operator(context)));
app.MapPost("/api/gpo/{id}/verify",async(string id,HttpContext context,GpoWorkflowService service)=>await service.ExecuteAsync(id,"verify",new(""),GpoToken(context),Operator(context)));
app.MapPost("/api/gpo/{id}/refresh",async(string id,HttpContext context,GpoWorkflowService service)=>await service.ExecuteAsync(id,"refresh",new(""),GpoToken(context),Operator(context)));
app.MapPost("/api/gpo/{id}/replan",async(string id,HttpContext context,GpoWorkflowService service,CancellationToken ct)=>await service.ReplanAsync(id,GpoToken(context),Operator(context),ct));
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
    if(request is null) throw new PolicyException("INVALID_REQUEST","Configuration body is required.");
    var domain=(request.Domain??"").Trim().ToLowerInvariant(); var dc=(request.DomainController??"").Trim().ToLowerInvariant();
    if(!ValidHostname(domain)||!domain.Contains('.')||!ValidHostname(dc)||!dc.EndsWith("."+domain,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("INVALID_DOMAIN","Domain and writable DC must be exact DNS names in the same domain.");
    var gpos=CleanList(request.ApprovedGpoIds); var ous=CleanList(request.AuthorizedOus); var hosts=CleanList(request.AllowedHosts); var operators=CleanList(request.AllowedOperators).Select(WindowsAccount.Normalize).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    string[] Accounts(string[]? values)=>CleanList(values).Select(WindowsAccount.Normalize).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    var remediators=Accounts(request.Remediators); var auditors=Accounts(request.Auditors); var viewers=Accounts(request.Viewers);
    if(gpos.Length==0||gpos.Any(x=>x!="*"&&!Guid.TryParse(x.Trim('{','}'),out _))) throw new PolicyException("INVALID_GPO_ALLOWLIST","Enter at least one approved GPO GUID, or an explicit * only when unrestricted GPO access is intended.");
    if(ous.Length==0||ous.Any(x=>x!="*"&&!(x.StartsWith("OU=",StringComparison.OrdinalIgnoreCase)||x.StartsWith("DC=",StringComparison.OrdinalIgnoreCase)))) throw new PolicyException("INVALID_SCOPE_ALLOWLIST","Enter at least one authorized OU/domain distinguished name, or an explicit * only when unrestricted scope access is intended.");
    if(operators.Length==0||operators.Any(x=>!WindowsAccount.IsOperator(x))) throw new PolicyException("INVALID_OPERATOR_ALLOWLIST","Enter an account as DOMAIN\\user. Use the detected Windows account if unsure.");
    if(remediators.Concat(auditors).Concat(viewers).Any(x=>!WindowsAccount.IsOperator(x))) throw new PolicyException("INVALID_ROLE_ACCOUNT","Every role member must be entered as DOMAIN\\user.");
    var overlap=operators.Concat(remediators).Concat(auditors).Concat(viewers).GroupBy(x=>x,StringComparer.OrdinalIgnoreCase).FirstOrDefault(x=>x.Count()>1);
    if(overlap is not null) throw new PolicyException("DUPLICATE_ROLE_MEMBER",$"{overlap.Key} belongs to more than one role. Assign each account to exactly one role.");
    if(real&&!operators.Contains(Operator(context),StringComparer.OrdinalIgnoreCase)) throw new PolicyException("OPERATOR_SELF_LOCKOUT","The active Windows operator must remain in AllowedOperators when saving a live configuration.");
    var backup=(request.BackupPath??"").Trim();
    var backupRoot=Path.Combine(programData,"GpoRemediator","Backups");
    if(!Regex.IsMatch(backup,@"^[A-Za-z]:\\")||backup.IndexOfAny(['\r','\n','\0'])>=0) throw new PolicyException("INVALID_BACKUP_PATH","Use the protected ProgramData backup repository.");
    backup=Path.GetFullPath(backup);
    if(!backup.Equals(backupRoot,StringComparison.OrdinalIgnoreCase)&&!backup.StartsWith(backupRoot+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new PolicyException("INVALID_BACKUP_PATH",$"BackupPath must be {backupRoot} or one of its subdirectories.");
    var output=new
    {
        Mode="Windows", Urls=localUrl,
        Windows=new{Workflow="GpoRemediation",EnableWrites=false,Domain=domain,DomainController=dc,ApprovedGpoIds=gpos,AuthorizedOus=ous,AllowedHosts=hosts,AllowedOperators=operators,Roles=new{Administrators=operators,Remediators=remediators,Auditors=auditors,Viewers=viewers},BackupPath=backup}
    };
    var path=localConfigPath; Directory.CreateDirectory(Path.GetDirectoryName(path)!); var temp=path+".tmp";
    ConfigureService(request.AutoRestart,()=> { File.WriteAllText(temp,JsonSerializer.Serialize(output,new JsonSerializerOptions{WriteIndented=true})); File.Move(temp,path,true);
    store.Audit("SETUP_CONFIG_SAVED",Operator(context),details:new{domain,domainController=dc,gpoCount=gpos.Length,ouCount=ous.Length,hostCount=hosts.Length,administratorCount=operators.Length,remediatorCount=remediators.Length,auditorCount=auditors.Length,viewerCount=viewers.Length,writes=false,autoRestart=request.AutoRestart});
    },lifetime);
    return new{saved=true,restartRequired=true,restartScheduled=request.AutoRestart,writesEnabled=false,path=localConfigPath};
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
    var path=localConfigPath;
    if(!File.Exists(path)) throw new PolicyException("CONFIG_NOT_FOUND","Save the Windows configuration first.");
    var node=JsonNode.Parse(File.ReadAllText(path))?.AsObject()??throw new PolicyException("INVALID_CONFIG","The Windows configuration file is invalid JSON.");
    var windows=(node["Windows"]??node["windows"])?.AsObject()??throw new PolicyException("INVALID_CONFIG","The Windows configuration section is missing.");
    if(request.Enable)
    {
        string[] Boundary(string name) => windows.FirstOrDefault(p=>p.Key.Equals(name,StringComparison.OrdinalIgnoreCase)).Value is JsonArray array
            ? array.Select(v=>v?.GetValue<string>()??"").ToArray() : [];
        GpoWorkflowRules.ValidateWriteScope(Boundary("ApprovedGpoIds"),Boundary("AuthorizedOus"));
    }
    var writeKey=windows.Select(p=>p.Key).FirstOrDefault(k=>k.Equals("EnableWrites",StringComparison.OrdinalIgnoreCase))??"EnableWrites";
    windows[writeKey]=request.Enable;
    ConfigureService(request.AutoRestart,()=> { var temp=path+".tmp"; File.WriteAllText(temp,node.ToJsonString(new JsonSerializerOptions(JsonDefaults.Options){WriteIndented=true})); File.Move(temp,path,true);
    store.Audit(request.Enable?"WRITE_MODE_ENABLE_REQUESTED":"WRITE_MODE_DISABLE_REQUESTED",Operator(context),details:new{enabled=request.Enable,autoRestart=request.AutoRestart});
    },lifetime);
    return new{saved=true,enableWrites=request.Enable,restartRequired=true,restartScheduled=request.AutoRestart};
});
app.MapGet("/api/audit",()=>new{events=store.AuditEvents(500).Reverse(),integrityValid=store.AuditIntegrity(),pageSize=500});
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
    app.UseDefaultFiles(new DefaultFilesOptions{FileProvider=files});
    app.UseStaticFiles(new StaticFileOptions{FileProvider=files,OnPrepareResponse=context=>{
        var name=context.File.Name;
        context.Context.Response.Headers.CacheControl=!name.Equals("index.html",StringComparison.OrdinalIgnoreCase)&&context.Context.Request.Query.ContainsKey("v")?"public,max-age=31536000,immutable":"no-cache";
    }});
    app.MapFallback(async context=> { if(context.Request.Path.StartsWithSegments("/api")) {context.Response.StatusCode=404; await context.Response.WriteAsJsonAsync(new{code="NOT_FOUND",message="API route does not exist."});} else { context.Response.ContentType="text/html; charset=utf-8"; context.Response.Headers.CacheControl="no-cache"; await context.Response.SendFileAsync(Path.Combine(frontendPath,"index.html")); } });
}
await app.RunAsync();

public partial class Program { }
