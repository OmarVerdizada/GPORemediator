using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

/// <summary>
/// Organizes *individual, integrity-checked* GPO launchers by domain/GPO.
/// Actual PowerShell business logic remains in bundled, compiled-asset-verified scripts.
/// The folders are NOT a security boundary by themselves: the server still authorizes
/// operators, GPO GUIDs, OUs, previews, changes, and backups.
/// </summary>
public static class GpoScriptWorkspaces
{
    private static readonly ConcurrentDictionary<string,object> Locks = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Regex DomainPattern = new(
        @"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly UTF8Encoding Utf8 = new(false);

    public static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "GpoRemediator", "Scripts");

    private static string ValidateDomain(string domain)
    {
        if(string.IsNullOrWhiteSpace(domain) || !DomainPattern.IsMatch(domain))
            throw new PolicyException("GPO_DOMAIN_PATH_INVALID", "A valid domain DNS name is required for isolated GPO scripts.");
        return domain.ToLowerInvariant();
    }

    private static string ValidateGpo(string id)
    {
        if(!Guid.TryParse(id,out var parsed) || parsed==Guid.Empty)
            throw new PolicyException("GPO_ID_INVALID", "A valid non-empty GPO GUID is required for script isolation.");
        return parsed.ToString("D");
    }

    // Only the minimal launcher is specific to a domain/GPO. No credentials, values,
    // controls, commands, backups or mutable policy payloads are written to disk.
    // The PowerShell engine is still exclusively the signed/compiled trusted product.
    private const string LauncherTemplate = """
        # GPORemediator generated, domain/GPO-bound launcher. DO NOT EDIT.
        # This file contains no saved credentials and is verified by the compiled backend.
        $ErrorActionPreference='Stop'
        [Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
        [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
        $expectedDomain='__DOMAIN__'
        $expectedGpo='__GPO__'
        $trustedBootstrap='__BOOTSTRAP__'
        $requestText=$null
        try {
            $requestText=[Console]::In.ReadToEnd()
            $req=$requestText | ConvertFrom-Json -ErrorAction Stop
            if($null -eq $req -or $null -eq $req.configuration -or $null -eq $req.payload -or $null -eq $req.payload.data){throw 'GPO_ISOLATION_DENIED|Missing scoped request.'}
            if([string]$req.configuration.domain -ine $expectedDomain){throw 'GPO_ISOLATION_DENIED|Domain does not match this GPO script.'}
            $operation=[string]$req.operation
            if($operation -notin @('gpoExplain','gpoPreview','gpoApply','gpoVerify','gpoRollback','gpoRollbackInspect','gpoRefresh')){throw 'GPO_ISOLATION_DENIED|Only a selected-GPO operation can use this script.'}
            $selected=if($operation -eq 'gpoPreview'){$req.payload.data.selection}else{$req.payload.data.plan.selection}
            if($null -eq $selected){throw 'GPO_ISOLATION_DENIED|Missing GPO selection.'}
            $guid=[guid]::Empty
            if(![guid]::TryParse([string]$selected.gpoId,[ref]$guid) -or $guid.ToString('D') -ine $expectedGpo){throw 'GPO_ISOLATION_DENIED|Selected GPO does not match this script.'}
            # In-process call: secrets are NEVER passed through a process argument list.
            # The trusted worker maintains its existing validation, authentication, and audit paths.
            & $trustedBootstrap -RequestJson $requestText
        } catch {
            $message=[string]$_.Exception.Message
            $code='GPO_ISOLATION_DENIED'
            if($message -notmatch '^GPO_ISOLATION_DENIED\|'){$message='Domain/GPO isolation guard could not validate the request.'}
            else{$message=$message.Substring('GPO_ISOLATION_DENIED|'.Length)}
            [Console]::Out.WriteLine()
            [Console]::Out.WriteLine('GPO_RESULT:'+(@{ok=$false;code=$code;message=$message} | ConvertTo-Json -Compress))
            exit 1
        } finally {
            $requestText=$null
        }
        """;

    private static string ExpectedLauncher(string domain,string gpoId,string bootstrap)
    {
        // PowerShell single-quoted literal escaping prevents script/text injection.
        string Quote(string value) => value.Replace("'","''",StringComparison.Ordinal);
        return LauncherTemplate.Replace("\r\n","\n",StringComparison.Ordinal).Replace("\r","\n",StringComparison.Ordinal)
            .Replace("__DOMAIN__",Quote(domain),StringComparison.Ordinal)
            .Replace("__GPO__",Quote(gpoId),StringComparison.Ordinal)
            .Replace("__BOOTSTRAP__",Quote(bootstrap),StringComparison.Ordinal) + "\n";
    }

    private static void CreateIfMissing(string file,byte[] expected)
    {
        if(File.Exists(file))return;
        try
        {
            using var writer=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None);
            writer.Write(expected);
            writer.Flush(true);
        }
        catch(IOException) when(File.Exists(file)) { /* An equal concurrent writer may have won. Verify below. */ }
    }

    public static string Ensure(string domain,string gpoId,string trustedBootstrap)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Domain/GPO folders require Windows.");
        var safeDomain=ValidateDomain(domain);
        var safeGpo=ValidateGpo(gpoId);
        var bootstrap=Path.GetFullPath(trustedBootstrap);
        var expectedBootstrap=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"PowerShell","Invoke-GpoWorkflow.ps1"));
        if(!string.Equals(bootstrap,expectedBootstrap,StringComparison.OrdinalIgnoreCase))
            throw new PolicyException("GPO_ISOLATION_DENIED","The scoped launcher must delegate to the bundled trusted PowerShell bootstrap.");
        // Verify all central scripts against the embedded compiled product before generating launchers.
        BundledAssets.VerifyScripts(Path.GetDirectoryName(bootstrap)!);
        return EnsureGenerated(Root,safeDomain,safeGpo,bootstrap);
    }

    // Kept separate so relocation/upgrade fixtures never touch shared application state.
    private static string EnsureGenerated(string root,string safeDomain,string safeGpo,string bootstrap)
    {
        var expected=Utf8.GetBytes(ExpectedLauncher(safeDomain,safeGpo,bootstrap));
        var fingerprint=Convert.ToHexString(SHA256.HashData(expected));
        // Generated launchers contain an absolute bootstrap path. A new installation or
        // template needs its own cache entry, rather than treating the previous entry as
        // tampering. Old entries are preserved and never executed by this installation.
        var domainDirectory=Path.Combine(root,safeDomain);
        var gpoDirectory=Path.Combine(domainDirectory,safeGpo);
        var cacheDirectory=Path.Combine(gpoDirectory,"generated-v2");
        var directory=Path.Combine(cacheDirectory,fingerprint);
        lock(Locks.GetOrAdd(directory,_=>new object()))
        {
            PrivateFiles.ProtectDirectory(root);
            PrivateFiles.ProtectDirectory(domainDirectory);
            PrivateFiles.ProtectDirectory(gpoDirectory);
            PrivateFiles.ProtectDirectory(cacheDirectory);
            PrivateFiles.ProtectDirectory(directory);
            PrivateFiles.RejectLinks(directory);
            var launcher=Path.Combine(directory,"Invoke-Gpo.ps1");
            var manifest=Path.Combine(directory,"scope.json");
            var expectedManifest=Utf8.GetBytes(JsonSerializer.Serialize(new{
                schemaVersion=1, domain=safeDomain, gpoId=safeGpo, launcherSha256=fingerprint
            },new JsonSerializerOptions{WriteIndented=true})+"\n");
            CreateIfMissing(launcher,expected);
            CreateIfMissing(manifest,expectedManifest);
            foreach(var path in new[]{launcher,manifest})
            {
                if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
                    throw new PolicyException("GPO_SCRIPT_TAMPERED","A domain/GPO script or manifest redirects to another file.");
            }
            if(!CryptographicOperations.FixedTimeEquals(File.ReadAllBytes(launcher),expected) ||
               !CryptographicOperations.FixedTimeEquals(File.ReadAllBytes(manifest),expectedManifest))
                throw new PolicyException("GPO_SCRIPT_TAMPERED","Domain/GPO script or manifest differs from the trusted generated content. Do not run it; investigate and restore from a clean release.");
            PrivateFiles.ProtectTree(directory);
            return launcher;
        }
    }

    public static void SyncInventory(GpoInventory inventory)
    {
        var bootstrap=Path.Combine(AppContext.BaseDirectory,"PowerShell","Invoke-GpoWorkflow.ps1");
        if(inventory.Gpos.Length>5000)
            throw new PolicyException("GPO_INVENTORY_TOO_LARGE","Domain inventory exceeds the supported 5000 GPO scope limit.");
        foreach(var gpo in inventory.Gpos)Ensure(inventory.Domain,gpo.Id,bootstrap);
    }

    public static string SelectScript(string operation,object configuration,object payload,string trustedBootstrap)
    {
        if(operation is "gpoInventory" or "gpoReadiness")return trustedBootstrap;
        if(operation is not ("gpoExplain" or "gpoPreview" or "gpoApply" or "gpoVerify" or "gpoRollback" or "gpoRollbackInspect" or "gpoRefresh"))
            throw new PolicyException("OPERATION_DENIED","Unsupported isolated-GPO operation.");
        // Extract scope from the already typed server-owned request, not a user-supplied path.
        var cfg=JsonSerializer.SerializeToElement(configuration,JsonDefaults.Options);
        var data=JsonSerializer.SerializeToElement(payload,JsonDefaults.Options).GetProperty("data");
        var selection=operation=="gpoPreview"?data.GetProperty("selection"):data.GetProperty("plan").GetProperty("selection");
        var domain=cfg.GetProperty("domain").GetString()??"";
        var id=selection.GetProperty("gpoId").GetString()??"";
        return Ensure(domain,id,trustedBootstrap);
    }
}
