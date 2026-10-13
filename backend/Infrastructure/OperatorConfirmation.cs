using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json.Serialization;
using GpoRemediator.Domain;
using Microsoft.Win32.SafeHandles;

namespace GpoRemediator.Infrastructure;

public sealed record OperatorBootstrap;
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record OperatorPassword(string Password);
public interface IOperatorPasswordVerifier { bool Verify(string actor,string password); }
public sealed class WindowsOperatorPasswordVerifier : IOperatorPasswordVerifier
{
    [DllImport("advapi32.dll",EntryPoint="LogonUserW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser(string user,string domain,string password,int type,int provider,out SafeAccessTokenHandle token);
    public bool Verify(string actor,string password){
        if(!OperatingSystem.IsWindows()||!WindowsAccount.IsOperator(actor))return false;
        var parts=actor.Split('\\',2);
        // Network logon validates credentials; it does not impersonate or grant execution privileges.
        if(!LogonUser(parts[1],parts[0],password,3,0,out var token)){token?.Dispose();return false;}
        using(token)using(var identity=new WindowsIdentity(token.DangerousGetHandle())){
            var expected=(SecurityIdentifier)new NTAccount(actor).Translate(typeof(SecurityIdentifier));
            return identity.User?.Equals(expected)==true;
        }
    }
}
public sealed class OperatorConfirmation(IOperatorPasswordVerifier verifier)
{
    public const string CookieName="GpoRemediator.OperatorConfirmation";
    private sealed record Proof(string Actor);
    private readonly Dictionary<string,Proof> proofs=new(StringComparer.Ordinal);
    private readonly object sync=new();
    private readonly SemaphoreSlim validating=new(4,4);
    private static string Actor(HttpContext context)=>WindowsAccount.Normalize(context.User.Identity?.Name);
    private static string Hash(string value)=>Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));
    public bool Confirmed(HttpContext context){
        if(context.User.Identity?.IsAuthenticated!=true)return false;
        var cookie=context.Request.Cookies[CookieName];if(cookie is null||cookie.Length!=64)return false;
        lock(sync)return proofs.TryGetValue(Hash(cookie),out var proof)&&proof.Actor.Equals(Actor(context),StringComparison.OrdinalIgnoreCase);
    }
    public void Require(HttpContext context){
        if(context.Request.Path.StartsWithSegments("/api")&&context.GetEndpoint()?.Metadata.GetMetadata<OperatorBootstrap>() is null&&!Confirmed(context))
            throw new PolicyException("OPERATOR_CONFIRMATION_REQUIRED","Confirm your Windows account password for this application start. Existing requests were not executed.");
    }
    public void SignIn(HttpContext context,OperatorPassword request){
        if(context.User.Identity?.IsAuthenticated!=true)throw new PolicyException("AUTHENTICATION_REQUIRED","Windows authentication is required.");
        var actor=Actor(context);var password=request.Password;
        if(!WindowsAccount.IsOperator(actor)||string.IsNullOrEmpty(password)||password.Length>1024||password.Contains('\0'))throw new PolicyException("OPERATOR_PASSWORD_INVALID","Windows account confirmation failed.");
        if(!validating.Wait(0))throw new PolicyException("GPO_CONNECTION_LIMIT","Too many concurrent account confirmations.");
        try{if(!verifier.Verify(actor,password))throw new PolicyException("OPERATOR_PASSWORD_INVALID","Windows account confirmation failed. Check your password; repeated failures can lock the Windows account.");}
        finally{validating.Release();}
        var secret=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        lock(sync){
            foreach(var key in proofs.Where(x=>x.Value.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase)).Select(x=>x.Key).ToArray())proofs.Remove(key);
            if(proofs.Count>=64)throw new PolicyException("GPO_CONNECTION_LIMIT","Account confirmation capacity reached.");
            proofs[Hash(secret)]=new(actor);
        }
        context.Response.Cookies.Append(CookieName,secret,new CookieOptions{HttpOnly=true,SameSite=SameSiteMode.Strict,Secure=context.Request.IsHttps,Path="/",MaxAge=TimeSpan.FromDays(365),IsEssential=true});
    }
    public static void MapEndpoints(WebApplication app){
        app.MapPost("/api/operator/sign-in",(OperatorPassword request,HttpContext context,OperatorConfirmation confirmation,Store store)=>{
            confirmation.SignIn(context,request);store.Audit("OPERATOR_STARTUP_CONFIRMED",Actor(context));return Results.Ok(new{confirmed=true});
        }).WithMetadata(new OperatorBootstrap(),new OperatorAccess("Administrator","Remediator","Auditor","Viewer")).RequireRateLimiting("operator-confirmation");
    }
}
