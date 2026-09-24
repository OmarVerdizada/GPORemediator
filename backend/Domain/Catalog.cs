using System.Security.Cryptography;
using System.Text;

namespace GpoRemediator.Domain;

public static class PolicyValues
{
    public static string[] Normalize(IEnumerable<string> values, PolicyType type) => values
        .Select(v => type == PolicyType.USER_RIGHTS_ASSIGNMENT ? NormalizeSid(v) : v.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToArray();
    public static string NormalizeSid(string value)
    {
        var sid = value.Trim().TrimStart('*').ToUpperInvariant();
        if (!System.Text.RegularExpressions.Regex.IsMatch(sid, @"^S-1-\d+(?:-\d+)+$"))
            throw new PolicyException("INVALID_SID", "User-right assignments must use SIDs, for example S-1-5-32-544.");
        return sid;
    }
    public static bool Equal(IEnumerable<string> a, IEnumerable<string> b, PolicyType type) =>
        Normalize(a, type).SequenceEqual(Normalize(b, type), StringComparer.OrdinalIgnoreCase);
    public static string Hash(object data) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonDefaults.Serialize(data))));
    public static string Now() => DateTimeOffset.UtcNow.ToString("O");
}

public static class Catalog
{
    // This is an original demonstration pack, not a redistributed CIS benchmark.
    public static readonly BenchmarkControl[] Controls =
    [
        Make("cis-2.2.3", "CIS", "2.2.3", "Access this computer from the network", PolicyType.USER_RIGHTS_ASSIGNMENT,
            "SeNetworkLogonRight", ["S-1-5-32-544", "S-1-5-11"], "Administrators; Authenticated Users",
            "Computer Configuration / Windows Settings / Security Settings / Local Policies / User Rights Assignment",
            notes: "Member Server example supplied by the operator. Exact assignment replaces this right only. Check role-specific exceptions before applying."),
        Make("sec-blank-password", "DEMO", "SEC-001", "Restrict blank-password accounts to console logon", PolicyType.SECURITY_OPTION,
            "LimitBlankPasswordUse", ["1"], "Enabled", "Local Policies / Security Options",
            key: @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"),
        Make("sec-uac", "DEMO", "SEC-002", "Run administrators in Admin Approval Mode", PolicyType.SECURITY_OPTION,
            "EnableLUA", ["1"], "Enabled", "Local Policies / Security Options", RestartRequirement.REQUIRED,
            key: @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
        Make("reg-autorun", "DEMO", "REG-001", "Disable AutoRun on all drive types", PolicyType.ADMINISTRATIVE_TEMPLATE,
            "NoDriveTypeAutoRun", ["255"], "All drive types", "Windows Components / AutoPlay Policies",
            key: @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        Make("account-password", "DEMO", "ACC-001", "Domain password policy review", PolicyType.ACCOUNT_POLICY,
            "MinimumPasswordLength", ["14"], "14 characters (illustrative)", "Account Policies / Password Policy",
            automated: false, accountScope: "DOMAIN_WIDE_OR_PSO",
            notes: "Intentional domain policy workflow required. Review domain-wide policy, Default Domain Policy, applicable Fine-Grained Password Policy / PSO, and local account scope separately. This MVP does not write account policy."),
        Make("audit-logon", "DEMO", "AUD-001", "Review advanced audit logon policy", PolicyType.ADVANCED_AUDIT_POLICY,
            "AuditLogon", ["Success", "Failure"], "Success and failure", "Advanced Audit Policy", automated: false),
        Make("firewall-profile", "DEMO", "FW-001", "Review Windows Firewall domain profile", PolicyType.WINDOWS_FIREWALL,
            "DomainProfile", ["Enabled"], "Enabled", "Windows Defender Firewall", automated: false),
        Make("service-review", "DEMO", "SVC-001", "Review unnecessary services", PolicyType.SERVICE_CONFIGURATION,
            "ServiceInventory", ["Reviewed"], "Role-approved services", "System Services", automated: false),
        Make("preference-review", "DEMO", "PREF-001", "Review registry preference ownership", PolicyType.REGISTRY_PREFERENCE,
            "PreferenceReview", ["Reviewed"], "Reviewed", "Preferences / Windows Settings / Registry", automated: false),
        Make("manual-review", "DEMO", "MAN-001", "Review application-specific access exceptions", PolicyType.MANUAL,
            "AccessReview", ["Reviewed"], "Reviewed", "Operational review", automated: false),
        Make("unsupported-example", "DEMO", "UNS-001", "Unmapped policy setting", PolicyType.UNSUPPORTED,
            "Unmapped", [], "Manual mapping required", "Unknown", automated: false),
        Make("registry-example", "DEMO", "REG-002", "Disable automatic administrative logon", PolicyType.REGISTRY_POLICY,
            "AutoAdminLogon", ["0"], "Disabled", "Registry policy", key: @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", registryType: "String")
    ];

    private static BenchmarkControl Make(string id, string benchmark, string number, string title, PolicyType type,
        string technical, string[] expected, string display, string path, RestartRequirement restart = RestartRequirement.NOT_REQUIRED,
        string? key = null, bool automated = true, string? accountScope = null, string? notes = null, string registryType = "DWord") =>
        new(id, benchmark, "operator-supplied-demo-1", number, title,
            "An original, benchmark-agnostic demonstration control. Validate against your licensed benchmark and server role.",
            "L1 example", automated, "Windows Server 2019 / 2022 / 2025", ["MemberServer"], type, path, technical, expected,
            display, true, restart, automated, type is not (PolicyType.MANUAL or PolicyType.UNSUPPORTED),
            accountScope is null ? [] : ["DOMAIN_WIDE_IMPACT"], ["DomainController: separate approved policy pack required"],
            notes ?? "Illustrative policy mapping; this is not a certified or complete benchmark pack.", key, key is null ? null : registryType, accountScope);
}

public interface IRemediationAdapter
{
    PolicyType Type { get; }
    void Validate(BenchmarkControl control, TargetResource target);
    Task ApplyAsync(IWindowsPolicyProvider provider, GpoReference gpo, BenchmarkControl control, CancellationToken ct);
}
public class RegistryPolicyAdapter(PolicyType type) : IRemediationAdapter
{
    public PolicyType Type => type;
    public virtual void Validate(BenchmarkControl control, TargetResource target)
    {
        if (control.RegistryKey is null || control.ExpectedValue.Length != 1)
            throw new PolicyException("INVALID_REGISTRY_MAPPING", "Control has no approved registry mapping.");
    }
    public Task ApplyAsync(IWindowsPolicyProvider provider, GpoReference gpo, BenchmarkControl control, CancellationToken ct) =>
        provider.ApplyAsync(gpo, control, control.ExpectedValue, ct);
}
public sealed class UserRightsAdapter : IRemediationAdapter
{
    public PolicyType Type => PolicyType.USER_RIGHTS_ASSIGNMENT;
    public void Validate(BenchmarkControl control, TargetResource target)
    {
        if (control.TechnicalSettingName != "SeNetworkLogonRight")
            throw new PolicyException("UNSUPPORTED_USER_RIGHT", "Only SeNetworkLogonRight has an approved automated adapter in this policy pack.");
        _ = PolicyValues.Normalize(control.ExpectedValue, Type);
    }
    public Task ApplyAsync(IWindowsPolicyProvider provider, GpoReference gpo, BenchmarkControl control, CancellationToken ct) =>
        provider.ApplyAsync(gpo, control, PolicyValues.Normalize(control.ExpectedValue, Type), ct);
}
public sealed class AdapterRegistry
{
    private readonly Dictionary<PolicyType, IRemediationAdapter> adapters = new IRemediationAdapter[]
    {
        new UserRightsAdapter(), new RegistryPolicyAdapter(PolicyType.REGISTRY_POLICY),
        new RegistryPolicyAdapter(PolicyType.SECURITY_OPTION), new RegistryPolicyAdapter(PolicyType.ADMINISTRATIVE_TEMPLATE)
    }.ToDictionary(a => a.Type);
    public string[] SupportedTypes => adapters.Keys.Select(v => v.ToString()).ToArray();
    public IRemediationAdapter Get(BenchmarkControl control, TargetResource target)
    {
        if (control.PolicyType == PolicyType.ACCOUNT_POLICY)
            throw new PolicyException("DOMAIN_ACCOUNT_POLICY_REVIEW_REQUIRED", "Account Policy requires an intentional domain-wide / PSO / local-account workflow. Arbitrary OU remediation is blocked; default domain policies are never selected automatically.");
        if (!control.Automated || !adapters.TryGetValue(control.PolicyType, out var adapter))
            throw new PolicyException("UNSUPPORTED_POLICY_TYPE", $"{control.PolicyType} requires a manual workflow in this MVP.");
        if (!control.Profiles.Contains(target.Profile))
            throw new PolicyException("ROLE_NOT_APPLICABLE", "This control is not approved for the target role. Select a matching policy pack.");
        adapter.Validate(control, target);
        return adapter;
    }
}
