using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace GpoRemediator.Infrastructure;

public static class PrivateFiles
{
    public static void RetireUnencryptedKeys(string keys,string recovery)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows is required.");
        ProtectTree(keys);ProtectDirectory(recovery);
        foreach(var file in Directory.EnumerateFiles(keys,"key-*.xml")){
            var bytes=File.ReadAllBytes(file);
            try{
                using var stream=new MemoryStream(bytes);var xml=XDocument.Load(stream);
                if(!xml.Descendants().Any(element=>element.Name.LocalName=="masterKey"))continue;
                // Old releases never persisted encrypted application records; retiring
                // these keys intentionally invalidates old browser antiforgery tokens.
                File.WriteAllBytes(Path.Combine(recovery,Path.GetFileName(file)+".dpapi"),ProtectedData.Protect(bytes,null,DataProtectionScope.CurrentUser));
                File.Delete(file);
            }finally{CryptographicOperations.ZeroMemory(bytes);}
        }
    }
    public static void RejectLinks(string path)
    {
        for(var current=new DirectoryInfo(Path.GetFullPath(path));current is not null;current=current.Parent)
            if(current.Exists&&(current.Attributes&FileAttributes.ReparsePoint)!=0)
                throw new InvalidOperationException("Application state cannot use junctions or symbolic links.");
    }

    public static void ProtectDirectory(string path)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("GPO Remediator requires Windows.");
        RejectLinks(path);
        var directory=Directory.CreateDirectory(path);
        var identity=WindowsIdentity.GetCurrent().User??throw new InvalidOperationException("Windows SID unavailable.");
        // Replace, rather than append to, a possibly unsafe existing DACL.
        var acl=new DirectorySecurity();acl.SetOwner(identity);acl.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{identity,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)}.Distinct())
            acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        directory.SetAccessControl(acl);
    }

    public static void EnsureDirectoryPreservingAcl(string path)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows is required.");
        RejectLinks(path);
        Directory.CreateDirectory(path);
        RejectLinks(path);
    }

    public static void ProtectTree(string root)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows is required.");
        ProtectDirectory(root);
        foreach(var directory in Directory.EnumerateDirectories(root))ProtectTree(directory);
        foreach(var path in Directory.EnumerateFiles(root)){
            if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("Application state cannot use file links.");
            var identity=WindowsIdentity.GetCurrent().User??throw new InvalidOperationException("Windows SID unavailable.");
            var acl=new FileSecurity();acl.SetOwner(identity);acl.SetAccessRuleProtection(true,false);
            foreach(var sid in new[]{identity,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)}.Distinct())
                acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
        }
    }
}
