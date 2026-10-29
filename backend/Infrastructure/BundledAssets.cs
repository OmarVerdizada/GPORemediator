using System.Reflection;
using System.Security.Cryptography;
using Microsoft.AspNetCore.StaticFiles;

namespace GpoRemediator.Infrastructure;

public static class BundledAssets
{
    private static readonly Assembly Assembly=typeof(BundledAssets).Assembly;
    public static byte[] Read(string name)
    {
        using var stream=Assembly.GetManifestResourceStream(name)??throw new InvalidOperationException("A bundled asset is missing.");
        using var buffer=new MemoryStream();stream.CopyTo(buffer);return buffer.ToArray();
    }
    public static void VerifyScripts(string directory)
    {
        // A junction in the published runtime path must not redirect trusted script reads.
        PrivateFiles.RejectLinks(directory);
        foreach(var name in new[]{"Invoke-GpoWorkflow.ps1","GpoWorkflow.Worker.ps1","SecurityTemplate.psm1","PolicyDiagnostics.ps1"}){
            var path=Path.Combine(directory,name);
            if(!File.Exists(path)||(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(File.ReadAllBytes(path)),SHA256.HashData(Read("Scripts/"+name))))
                throw new Domain.PolicyException("SCRIPT_INTEGRITY_FAILED","Bundled PowerShell content differs from the compiled product. Reinstall the verified release.");
        }
    }
    public static void MapFrontend(WebApplication app)
    {
        // Serve compiled-in assets. Writable files beside the EXE cannot inject UI code.
        var contentTypes=new FileExtensionContentTypeProvider();
        foreach(var name in Assembly.GetManifestResourceNames().Where(n=>n.StartsWith("Frontend/",StringComparison.Ordinal))){
            var path=name["Frontend/".Length..].Replace('\\','/');var data=Read(name);
            var type=contentTypes.TryGetContentType(path,out var detected)?detected:"application/octet-stream";
            app.MapGet("/"+path,(HttpContext context)=>{context.Response.Headers.CacheControl="no-store";return Results.File(data,type);});
        }
        app.MapGet("/",(HttpContext context)=>{context.Response.Headers.CacheControl="no-store";return Results.File(Read("Frontend/index.html"),"text/html; charset=utf-8");});
    }
}
