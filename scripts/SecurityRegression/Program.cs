using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

static void Check(bool value,string message){if(!value)throw new Exception(message);}
static void Reject(Action action,string code){try{action();throw new Exception("Expected "+code);}catch(PolicyException error){Check(error.Code==code,"Unexpected code "+error.Code);}}
Check(EndpointTargeting.Resolve(null,[])=="SelectedOu","New empty config did not select OU targeting");
Check(EndpointTargeting.Resolve(null,["ws.example.local"])=="ExplicitHosts","Legacy explicit host list expanded");
Check(EndpointTargeting.Resolve("SelectedOu",["ws.example.local"])=="SelectedOu","Automatic mode remained restricted by old host list");
Reject(()=>EndpointTargeting.Resolve("*",[]),"INVALID_ENDPOINT_TARGETING");
OperatorSecurity.ValidateHosts(["dc.example.local","ws.example.local"],"example.local");
foreach(var host in new[]{"*","*.example.local","ws.evil.local","dc.example.local.evil","dc.example.local\n","127.0.0.1"})
 Reject(()=>OperatorSecurity.ValidateHosts([host],"example.local"),"INVALID_HOST_ALLOWLIST");
var context=new DefaultHttpContext();context.Request.Host=new HostString("localhost",5080);context.Connection.RemoteIpAddress=IPAddress.Loopback;
RequestSecurity.RequireLoopback(context);
context.Request.Host=new HostString("evil.example");Reject(()=>RequestSecurity.RequireLoopback(context),"LOOPBACK_ONLY");
context.Request.Host=new HostString("localhost");context.Connection.RemoteIpAddress=IPAddress.Parse("192.0.2.1");Reject(()=>RequestSecurity.RequireLoopback(context),"LOOPBACK_ONLY");

var sandbox=Path.Combine(Path.GetTempPath(),"gpo-security-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(sandbox);
try{
 var scripts=Path.Combine(sandbox,"scripts");Directory.CreateDirectory(scripts);
 foreach(var name in new[]{"Invoke-GpoWorkflow.ps1","GpoWorkflow.Worker.ps1","SecurityTemplate.psm1","FineGrainedPassword.ps1","PolicyDiagnostics.ps1"})File.WriteAllBytes(Path.Combine(scripts,name),BundledAssets.Read("Scripts/"+name));
 BundledAssets.VerifyScripts(scripts);
 File.AppendAllText(Path.Combine(scripts,"GpoWorkflow.Worker.ps1"),"#tampered");
 Reject(()=>BundledAssets.VerifyScripts(scripts),"SCRIPT_INTEGRITY_FAILED");
 if(OperatingSystem.IsWindows()){
  var legacy=Path.Combine(sandbox,"legacy");PrivateFiles.ProtectDirectory(legacy);
  var oldServices=new ServiceCollection();oldServices.AddLogging();
  oldServices.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(legacy));
  using(var oldProvider=oldServices.BuildServiceProvider())oldProvider.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>().CreateProtector("legacy").Protect([1,2,3]);
  Check(Directory.GetFiles(legacy,"*.xml").Length>0,"Legacy key fixture missing");
  PrivateFiles.RetireUnencryptedKeys(legacy,Path.Combine(sandbox,"recovery"));
  Check(Directory.GetFiles(legacy,"*.xml").Length==0&&Directory.GetFiles(Path.Combine(sandbox,"recovery"),"*.dpapi").Length>0,"Plaintext legacy keys survived migration");
  var keys=Path.Combine(sandbox,"keys");PrivateFiles.ProtectDirectory(keys);
  var services=new ServiceCollection();services.AddLogging();
  Microsoft.AspNetCore.DataProtection.DataProtectionBuilderExtensions.SetApplicationName(
   Microsoft.AspNetCore.DataProtection.DataProtectionBuilderExtensions.ProtectKeysWithDpapi(
    Microsoft.AspNetCore.DataProtection.DataProtectionBuilderExtensions.PersistKeysToFileSystem(services.AddDataProtection(),new DirectoryInfo(keys))),"SecurityRegression");
  using var provider=services.BuildServiceProvider();
  var protector=provider.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>().CreateProtector("test");
  var encrypted=protector.Protect(Encoding.UTF8.GetBytes("test-secret"));Check(Encoding.UTF8.GetString(protector.Unprotect(encrypted))=="test-secret","DPAPI round trip");
  Check(Directory.GetFiles(keys,"*.xml").Any(file=>File.ReadAllText(file).Contains("encryptedSecret")),"Keys persisted without encryption");
 }
 var builder=WebApplication.CreateBuilder(new WebApplicationOptions{EnvironmentName="Production",ContentRootPath=sandbox});
 builder.WebHost.UseTestServer();builder.Logging.ClearProviders();
 builder.Services.AddAntiforgery(options=>{options.HeaderName="X-CSRF-Token";options.Cookie.HttpOnly=true;options.Cookie.SameSite=SameSiteMode.Strict;});
 builder.Services.AddRateLimiter(OperatorSecurity.ConfigureLoginRateLimit);
 builder.Services.AddSingleton<IOperatorPasswordVerifier,FixturePasswordVerifier>();
 builder.Services.AddSingleton<OperatorConfirmation>();
 builder.Services.AddSingleton(_=>new Store(Path.Combine(sandbox,"operator.db")));
 await using var app=builder.Build();
 app.UseRouting();
 // Test fixture only: supplies Windows identities without contacting AD.
 app.Use(async(ctx,next)=>{
  var actor=ctx.Request.Headers["Test-Identity"].ToString();
  if(actor.Length>0)ctx.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name,actor),new Claim(ClaimTypes.NameIdentifier,actor)],"Test"));
  try{OperatorSecurity.RequireIdentity(ctx);await RequestSecurity.ValidateMutationAsync(ctx);ctx.RequestServices.GetRequiredService<OperatorConfirmation>().Require(ctx);await next(ctx);}
  catch(PolicyException e){ctx.Response.StatusCode=e.Code=="AUTHENTICATION_REQUIRED"?401:403;await ctx.Response.WriteAsync(e.Code);}
  catch(AntiforgeryValidationException){ctx.Response.StatusCode=403;await ctx.Response.WriteAsync("CSRF_INVALID");}
 });
 app.UseRateLimiter();
 app.MapGet("/api/session",(HttpContext ctx,IAntiforgery anti)=>new{token=anti.GetAndStoreTokens(ctx).RequestToken}).WithMetadata(new OperatorBootstrap());
 OperatorConfirmation.MapEndpoints(app,(request,ctx,ct)=>{
  // The injected AD adapter must succeed before either workspace access or connection is issued.
  if(request.UserName!="TEST\\executor"||request.Password!="fixture-password")throw new PolicyException("OPERATOR_PASSWORD_INVALID","Rejected delegated credentials");
  Check(ctx.User.Identity?.Name?.StartsWith("TEST\\")==true,"Delegated account replaced operator identity");
  ctx.Response.Cookies.Append("GpoRemediator.GpoConnection","fixture-connection",new CookieOptions{HttpOnly=true,SameSite=SameSiteMode.Strict,Path="/api"});
  return Task.CompletedTask;
 });
 app.MapGet("/api/private",()=>Results.Ok());
 foreach(var action in new[]{"apply","rollback"})
  app.MapPost("/api/gpo/{id}/"+action,(GpoRefreshRequest request)=>new{refresh=request.Refresh});
 GpoEndpoints.MapRefresh(app,(id,consent,context)=>Task.FromResult<object>(new{refresh=consent.Refresh}));
 app.MapPost("/api/setup/config",()=>Results.Ok());
 app.MapPost("/api/service/{action}",(string action)=>action is "stop" or "restart"?Results.Accepted():Results.BadRequest())
  .WithMetadata(new OperatorBootstrap());
 app.MapPost("/api/undeclared",()=>Results.Ok());
 app.MapPost("/api/gpo/connect",()=>Results.Ok()).RequireRateLimiting("delegated-login");
 BundledAssets.MapFrontend(app);
 await app.StartAsync();
 using var client=app.GetTestClient();client.BaseAddress=new Uri("http://localhost");
 async Task<(string Token,string Cookie)> Session(string actor,bool confirm=true){
  using var req=new HttpRequestMessage(HttpMethod.Get,"/api/session");req.Headers.Add("Test-Identity",actor);
  using var response=await client.SendAsync(req);Check(response.IsSuccessStatusCode,"Session failed for "+actor);
  var session=((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!,response.Headers.GetValues("Set-Cookie").First().Split(';')[0]);
  if(!confirm)return session;
  using var signed=await Post("/api/operator/sign-in",actor,session,json:"{\"password\":\"fixture-password\",\"userName\":\"TEST\\\\executor\"}");
  Check(signed.IsSuccessStatusCode,"Startup confirmation failed for "+actor);
  var proofCookie=signed.Headers.GetValues("Set-Cookie").Single(x=>x.StartsWith(OperatorConfirmation.CookieName+"="));Check(proofCookie.Contains("httponly",StringComparison.OrdinalIgnoreCase)&&proofCookie.Contains("samesite=strict",StringComparison.OrdinalIgnoreCase),"Proof cookie missing protections");
  return(session.Item1,session.Item2+"; "+string.Join("; ",signed.Headers.GetValues("Set-Cookie").Select(x=>x.Split(';')[0])));
 }
 async Task<HttpResponseMessage> Post(string route,string actor,(string Token,string Cookie) session,string? origin="http://localhost",bool token=true,string json="{\"refresh\":\"Scope\"}"){
  using var req=new HttpRequestMessage(HttpMethod.Post,route){Content=new StringContent(json,Encoding.UTF8,"application/json")};
  if(actor.Length>0)req.Headers.Add("Test-Identity",actor);if(origin is not null)req.Headers.Add("Origin",origin);
  req.Headers.Add("Cookie",session.Cookie);if(token)req.Headers.Add("X-CSRF-Token",session.Token);
  return await client.SendAsync(req);
 }
 var unconfirmed=await Session("TEST\\Admin",false);
 foreach(var action in new[]{"stop","restart"}){
  using(var response=await Post("/api/service/"+action,"TEST\\Admin",unconfirmed))Check(response.StatusCode==HttpStatusCode.Accepted,"Native administrator lifecycle client blocked without browser confirmation: "+action);
  using(var response=await Post("/api/service/"+action,"TEST\\Admin",unconfirmed,token:false))Check(response.StatusCode==HttpStatusCode.Forbidden,"Lifecycle CSRF bypass: "+action);
  using(var response=await Post("/api/service/"+action,"TEST\\Admin",unconfirmed,"http://evil.example"))Check(response.StatusCode==HttpStatusCode.Forbidden,"Lifecycle origin bypass: "+action);
 }
 foreach(var actor in new[]{"TEST\\Writer","TEST\\Viewer","TEST\\Auditor"}){
  var native=await Session(actor,false);
  using var response=await Post("/api/service/stop",actor,native);Check(response.StatusCode==HttpStatusCode.Accepted,"Role-free lifecycle blocked: "+actor);
 }
 async Task<HttpResponseMessage> Private(string actor,string cookie){
  using var req=new HttpRequestMessage(HttpMethod.Get,"/api/private");req.Headers.Add("Test-Identity",actor);req.Headers.Add("Cookie",cookie);return await client.SendAsync(req);
 }
 using(var response=await Private("TEST\\Admin",unconfirmed.Cookie))Check(response.StatusCode==HttpStatusCode.Forbidden,"Startup proof not required");
 using(var response=await Post("/api/operator/sign-in","TEST\\Admin",unconfirmed,json:"{\"password\":\"wrong\"}"))Check(response.StatusCode==HttpStatusCode.Forbidden,"Wrong password accepted");
 using(var response=await Post("/api/operator/sign-in","TEST\\Admin",unconfirmed,token:false,json:"{\"password\":\"fixture-password\",\"userName\":\"TEST\\\\executor\"}"))Check(response.StatusCode==HttpStatusCode.Forbidden,"Startup CSRF bypass");
 using(var response=await Post("/api/operator/sign-in","TEST\\Admin",unconfirmed,json:"{\"password\":\"fixture-password\",\"actor\":\"TEST\\\\Writer\"}"))Check(response.StatusCode==HttpStatusCode.BadRequest,"Alternate actor accepted");
 using(var response=await Post("/api/gpo/test/apply","TEST\\Admin",unconfirmed))Check(response.StatusCode==HttpStatusCode.Forbidden,"Write executed before startup confirmation");
 var confirmed=await Session("TEST\\Admin");
 Check(confirmed.Cookie.Contains(OperatorConfirmation.CookieName)&&confirmed.Cookie.Contains("GpoRemediator.GpoConnection="),"Single sign-in did not issue both sessions");
 using(var response=await Private("TEST\\Admin",confirmed.Cookie))Check(response.IsSuccessStatusCode,"Refresh needs repeated confirmation");
 using(var response=await Private("TEST\\Writer",confirmed.Cookie))Check(response.StatusCode==HttpStatusCode.Forbidden,"Proof crossed Windows identity");
 using(var response=await Private("TEST\\Admin",confirmed.Cookie.Replace(OperatorConfirmation.CookieName+"=",OperatorConfirmation.CookieName+"=tampered")))Check(response.StatusCode==HttpStatusCode.Forbidden,"Tampered proof accepted");
 var restarted=new OperatorConfirmation(new FixturePasswordVerifier());
 var setupContext=new DefaultHttpContext();setupContext.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name,"TEST\\Admin")],"Test"));
 Reject(()=>restarted.SignIn(setupContext,new OperatorPassword("wrong")),"OPERATOR_PASSWORD_INVALID");
 restarted.SignIn(setupContext,new OperatorPassword("fixture-password"));
 Check(setupContext.Response.Headers.SetCookie.Any(x=>x?.StartsWith(OperatorConfirmation.CookieName+"=")==true),"Initial setup owner confirmation failed");
 var restartedContext=new DefaultHttpContext();restartedContext.User=new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name,"TEST\\Admin")],"Test"));restartedContext.Request.Headers.Cookie=confirmed.Cookie;
 Check(!restarted.Confirmed(restartedContext),"Restart retained prior startup proof");
 foreach(var role in new[]{"Viewer","Auditor","Admin","Writer","Unconfigured","Conflict","Legacy"}){
  var actor="TEST\\"+role;var session=await Session(actor);
  foreach(var action in new[]{"apply","rollback","refresh"})foreach(var suffix in new[]{action,action+"/",action.ToUpperInvariant()}){
   using var response=await Post("/api/gpo/test/"+suffix,actor,session);
   Check(response.StatusCode==HttpStatusCode.OK,"Application role restriction remains: "+role+"/"+suffix);
  }
 }
 var admin=await Session("TEST\\Admin");
 foreach(var target in new[]{"Pdc","Scope"}){
  using var response=await Post("/api/gpo/test/refresh","TEST\\Admin",admin,json:JsonSerializer.Serialize(new{refresh=target}));
  Check(response.IsSuccessStatusCode&&(await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("refresh").GetString()==target,"Production refresh route discarded "+target);
 }
 foreach(var target in new[]{"None","*","bad"}){
  using var response=await Post("/api/gpo/test/refresh","TEST\\Admin",admin,json:JsonSerializer.Serialize(new{refresh=target}));
  Check(!response.IsSuccessStatusCode,"Invalid refresh target accepted: "+target);
 }
 using(var response=await Post("/api/gpo/test/refresh","TEST\\Admin",admin,"http://evil.example"))Check(response.StatusCode==HttpStatusCode.Forbidden,"Cross-origin write accepted");
 using(var response=await Post("/api/gpo/test/refresh","TEST\\Admin",admin,token:false))Check(response.StatusCode==HttpStatusCode.Forbidden,"Missing CSRF accepted");
 using(var response=await Post("/api/gpo/test/refresh","TEST\\Admin",admin,null))Check(response.StatusCode==HttpStatusCode.Forbidden,"Missing Origin accepted");
 using(var response=await Post("/api/gpo/test/refresh","",admin))Check(response.StatusCode==HttpStatusCode.Unauthorized,"Anonymous write accepted");
 using(var response=await Post("/api/gpo/test/refresh","TEST\\Writer",admin))Check(response.StatusCode==HttpStatusCode.Forbidden,"Cross-identity CSRF accepted");
 using(var response=await Post("/api/undeclared","TEST\\Admin",admin))Check(response.StatusCode==HttpStatusCode.OK,"Role metadata still required");
 using(var response=await Post("/api/gpo/test/refresh","TEST\\Admin",admin,json:"{\"refresh\":\"Scope\",\"command\":\"injected\"}"))Check(response.StatusCode==HttpStatusCode.BadRequest,"Unknown refresh fields accepted");
 var throttled=await Session("TEST\\Writer",false);
 for(var i=0;i<5;i++){using var response=await Post("/api/operator/sign-in","TEST\\Writer",throttled,json:"{\"password\":\"wrong\"}");Check(response.StatusCode==(i<4?HttpStatusCode.Forbidden:HttpStatusCode.TooManyRequests),"Startup password retry throttle failed");}
 var viewer=await Session("TEST\\Viewer");
 using(var response=await Post("/api/setup/config","TEST\\Viewer",viewer))Check(response.StatusCode==HttpStatusCode.OK,"Application role blocked configuration");
 for(var i=0;i<6;i++){using var response=await Post("/api/gpo/connect","TEST\\Viewer",viewer);Check(response.StatusCode==(i<5?HttpStatusCode.OK:HttpStatusCode.TooManyRequests),"Login rate limit failed");}
 using(var req=new HttpRequestMessage(HttpMethod.Get,"/index.html")){
  req.Headers.Add("Test-Identity","TEST\\Viewer");using var response=await client.SendAsync(req);
  Check(response.IsSuccessStatusCode&&(await response.Content.ReadAsStringAsync()).Contains("GPO Remediator"),"Compiled UI asset unavailable");
 }
 await app.StopAsync();
 Console.WriteLine("PASS security: startup password/CSRF/identity/tamper/restart gate, role-free endpoints/case/trailing slash, unconfigured and legacy identities, CSRF/origin/identity isolation, anonymous denial, login rate limit, refresh JSON, host boundary, script tampering, DPAPI and compiled UI.");
}finally{Directory.Delete(sandbox,true);}

sealed class FixturePasswordVerifier : IOperatorPasswordVerifier { public bool Verify(string actor,string password)=>password=="fixture-password"; }
