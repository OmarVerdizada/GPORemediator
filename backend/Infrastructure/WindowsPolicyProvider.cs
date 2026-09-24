using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

public sealed class WindowsPolicyProvider : IWindowsPolicyProvider
{
    private readonly WindowsPowerShellExecutor executor;
    private readonly WindowsConfiguration configuration;
    public string Mode => "WINDOWS";
    private static readonly string[] ProtectedIds = ["31b2f340-016d-11d2-945f-00c04fb984f9", "6ac1786c-016f-11d2-945f-00c04fb984f9"];

    public WindowsPolicyProvider(IConfiguration config, ILogger<WindowsPolicyProvider> logger)
    {
        executor = new WindowsPowerShellExecutor(logger);
        var section = config.GetSection("Windows");
        configuration = new WindowsConfiguration(section["Domain"] ?? "", section["DomainController"] ?? "",
            section.GetSection("ApprovedGpoIds").Get<string[]>() ?? [], section.GetSection("AuthorizedOus").Get<string[]>() ?? [],
            section.GetSection("AllowedHosts").Get<string[]>() ?? [], section.GetValue<bool>("AllowCreateGpo"),
            Path.GetFullPath(section["BackupPath"] ?? Path.Combine(AppContext.BaseDirectory, "data", "gpo-backups")));
    }

    private void ValidateConfiguration()
    {
        static bool Dns(string value) => Regex.IsMatch(value, @"\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\z") && value.Contains('.');
        if (!Dns(configuration.Domain) || !Dns(configuration.DomainController) ||
            !configuration.DomainController.EndsWith("." + configuration.Domain, StringComparison.OrdinalIgnoreCase))
            throw new PolicyException("WINDOWS_CONFIG", "Configure Windows:Domain and a writable Windows:DomainController FQDN in that domain.");
        if (configuration.AllowedHosts.Length == 0 || configuration.AuthorizedOus.Length == 0 || configuration.ApprovedGpoIds.Length == 0)
            throw new PolicyException("WINDOWS_ALLOWLIST_EMPTY", "Configure exact AllowedHosts, AuthorizedOus, and ApprovedGpoIds on the server before enabling real execution.");
        if (configuration.ApprovedGpoIds.Any(x => !Guid.TryParse(x, out _) || ProtectedIds.Contains(x.Trim('{', '}').ToLowerInvariant())))
            throw new PolicyException("GPO_ALLOWLIST_INVALID", "ApprovedGpoIds must contain GUIDs and must exclude both default domain GPOs.");
        if (configuration.AllowedHosts.Any(x => !Dns(x) || !x.EndsWith("." + configuration.Domain, StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("HOST_ALLOWLIST_INVALID", "AllowedHosts must contain exact host FQDNs in the configured domain, without wildcards.");
        if (configuration.AuthorizedOus.Any(x => !x.StartsWith("OU=", StringComparison.OrdinalIgnoreCase) || x.IndexOfAny(['\r', '\n', '\0']) >= 0))
            throw new PolicyException("OU_ALLOWLIST_INVALID", "AuthorizedOus must contain exact OU distinguished names, without line breaks.");
    }
    private void ValidateTarget(TargetResource target)
    {
        ValidateConfiguration();
        if (!configuration.AllowedHosts.Contains(target.Hostname, StringComparer.OrdinalIgnoreCase) ||
            !string.Equals(target.Domain, configuration.Domain, StringComparison.OrdinalIgnoreCase))
            throw new PolicyException("TARGET_NOT_APPROVED", "The target FQDN/domain is outside the server-side Windows allowlist.");
    }
    private void ValidateGpo(GpoReference gpo)
    {
        ValidateConfiguration();
        if (!Guid.TryParse(gpo.Id, out var id) || ProtectedIds.Contains(id.ToString()) ||
            !configuration.ApprovedGpoIds.Any(x => Guid.Parse(x) == id))
            throw new PolicyException("GPO_NOT_APPROVED", "Select an approved GPO GUID. Default domain GPOs are always protected.");
    }
    private Task<T> Run<T>(string operation, object payload, CancellationToken ct) => executor.RunAsync<T>(operation, configuration, payload, ct);

    public async Task<EnvironmentReadiness> ReadinessAsync(CancellationToken ct = default)
    {
        try
        {
            ValidateConfiguration();
            return await Run<EnvironmentReadiness>("environment", new { }, ct);
        }
        catch (PolicyException ex)
        {
            return new EnvironmentReadiness(Mode,false,"Windows service identity",configuration.DomainController,
                [new ReadinessCheck("configuration","Windows provider configuration","FAIL",$"{ex.Code}: {ex.Message}")],DateTimeOffset.UtcNow.ToString("O"));
        }
    }

    public Task<TargetResource> ResolveTargetAsync(TargetResource target, CancellationToken ct = default)
    {
        ValidateTarget(target);
        return Run<TargetResource>("resolveTarget", new { target }, ct);
    }

    public async Task<PreflightResult> PreflightAsync(TargetResource target, GpoReference? gpo, CancellationToken ct = default)
    {
        try
        {
            ValidateTarget(target);
            if (gpo is not null) ValidateGpo(gpo);
            return await Run<PreflightResult>("preflight", new { target, gpo }, ct);
        }
        catch (PolicyException ex)
        {
            return new(false, false, false, false, "Windows service identity", [$"{ex.Code}: {ex.Message}"], [], configuration.DomainController);
        }
    }
    public Task<PolicySourceAnalysis> AnalyzeAsync(TargetResource target, BenchmarkControl control, CancellationToken ct = default)
    {
        ValidateTarget(target);
        return Run<PolicySourceAnalysis>("analyze", new { target, control }, ct);
    }

    public async Task<ImpactAnalysis> PreviewAsync(string findingId, TargetResource target, BenchmarkControl control, TargetSelection selection, CancellationToken ct = default)
    {
        ValidateTarget(target);
        if (selection.Strategy == "CREATE")
            throw new PolicyException("CREATE_REQUIRES_PROVISIONING", "Create and link a dedicated GPO in GPMC using a separately delegated provisioning identity, then approve its GUID in Windows:ApprovedGpoIds. Automatic production creation is intentionally disabled in this MVP.");
        var analysis = await AnalyzeAsync(target, control, ct);
        GpoReference? selected = null;
        if (selection.Strategy == "DETECTED")
        {
            if (analysis.Status != "DETECTED" || analysis.WinningGpoId is null)
                throw new PolicyException("SOURCE_AMBIGUOUS", "RSoP did not identify a unique winning GPO. Select an approved existing dedicated GPO.");
            selected = analysis.ApplicableGpos.FirstOrDefault(x => string.Equals(x.Id, analysis.WinningGpoId, StringComparison.OrdinalIgnoreCase));
        }
        else if (selection.Strategy is "EXISTING" or "DEDICATED")
        {
            var dedicated = analysis.ApplicableGpos.Where(x => x.Approved && x.Dedicated).ToArray();
            if (selection.GpoId is null && dedicated.Length > 1)
                throw new PolicyException("GPO_SELECTION_AMBIGUOUS", "More than one approved dedicated remediation GPO is linked. Select its exact GUID.");
            selected = selection.GpoId is not null
                ? analysis.ApplicableGpos.FirstOrDefault(x => string.Equals(x.Id, selection.GpoId, StringComparison.OrdinalIgnoreCase))
                : dedicated.SingleOrDefault();
        }
        else throw new PolicyException("SELECTION_INVALID", "Unknown target selection strategy.");
        if (selected is null) throw new PolicyException("GPO_SELECTION_REQUIRED", "Choose an approved existing GPO reported by endpoint RSoP as actually applied to this computer. Dedicated GPOs must include 'Remediation' in their display name.");
        ValidateGpo(selected);
        var inspection = await Run<GpoInspection>("inspect", new { target = analysis.Target, control, gpo = selected }, ct);
        var warnings = new List<string>
        {
            "Potentially affected computer count is UNKNOWN: security/WMI filtering, nested groups, sites, and external scope are not reduced to an invented count.",
            "A full-GPO snapshot is restored during rollback; later concurrent GPO edits block automatic rollback.",
            "Source analysis reflects the last available RSoP. Replication and endpoint verification remain mandatory after a change."
        };
        if (inspection.Gpo.WmiFilter is not null) warnings.Add("A WMI filter is present; endpoint application must be established through RSoP.");
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonDefaults.Serialize(new
        {
            target = analysis.Target, controlId = control.Id, gpo = inspection.Gpo,
            oldValue = inspection.Value.Order(StringComparer.OrdinalIgnoreCase), expected = control.ExpectedValue.Order(StringComparer.OrdinalIgnoreCase)
        }))));
        return new(Guid.NewGuid().ToString("N"), findingId, control.Id, analysis.Target, inspection.Gpo,
            inspection.Value, control.ExpectedValue, control.RequiresGpUpdate, control.RequiresRestart, true, true,
            warnings.ToArray(), selection, fingerprint, DateTimeOffset.UtcNow.ToString("O"), Mode);
    }

    public Task<GpoReference> EnsureGpoAsync(ImpactAnalysis plan, CancellationToken ct = default)
    {
        ValidateTarget(plan.Target);
        ValidateGpo(plan.Gpo);
        if (plan.Selection.Strategy == "CREATE") throw new PolicyException("CREATE_REQUIRES_PROVISIONING", "Provision and explicitly approve a dedicated GPO before applying.");
        return Task.FromResult(plan.Gpo);
    }

    public async Task<GpoBackup> BackupAsync(string jobId, TargetResource target, BenchmarkControl control, GpoReference gpo, string operatorName, CancellationToken ct = default)
    {
        ValidateTarget(target); ValidateGpo(gpo);
        var data = await Run<BackupData>("backup", new { target, control, gpo, jobId }, ct);
        return new(Guid.NewGuid().ToString("N"), jobId, gpo.Id, gpo.Name, control.Id, operatorName,
            DateTimeOffset.UtcNow.ToString("O"), target.Id, target.Ou, data.PreviousValue, JsonDefaults.Serialize(data), EndpointPreviousValue: data.EndpointPreviousValue);
    }
    public async Task ApplyAsync(GpoReference gpo, BenchmarkControl control, string[] value, CancellationToken ct = default)
    {
        ValidateGpo(gpo);
        _ = await Run<JsonElement>("apply", new { gpo, control, value }, ct);
    }
    public Task<VerificationResult> VerifyGpoAsync(GpoReference gpo, BenchmarkControl control, string[] expected, CancellationToken ct = default)
    {
        ValidateGpo(gpo); return Run<VerificationResult>("verifyGpo", new { gpo, control, expected }, ct);
    }
    public Task<VerificationResult> VerifyScopeAsync(GpoReference gpo, TargetResource target, CancellationToken ct = default)
    {
        ValidateGpo(gpo); ValidateTarget(target); return Run<VerificationResult>("verifyScope", new { gpo, target }, ct);
    }
    public Task<VerificationResult> RefreshAsync(TargetResource target, CancellationToken ct = default)
    {
        ValidateTarget(target); return Run<VerificationResult>("refresh", new { target }, ct);
    }
    public Task<VerificationResult> VerifyRsopAsync(TargetResource target, GpoReference gpo, BenchmarkControl control, string[] expected, CancellationToken ct = default)
    {
        ValidateTarget(target); ValidateGpo(gpo); return Run<VerificationResult>("verifyRsop", new { target, gpo, control, expected }, ct);
    }
    public Task<VerificationResult> VerifyEndpointAsync(TargetResource target, BenchmarkControl control, string[] expected, CancellationToken ct = default)
    {
        ValidateTarget(target); return Run<VerificationResult>("verifyEndpoint", new { target, control, expected }, ct);
    }
    public Task<VerificationResult> RestartAsync(TargetResource target, CancellationToken ct = default)
    {
        ValidateTarget(target); return Run<VerificationResult>("restart", new { target }, ct);
    }
    public async Task RestoreAsync(GpoBackup backup, BenchmarkControl control, CancellationToken ct = default)
    {
        ValidateConfiguration();
        if (string.IsNullOrWhiteSpace(backup.PostWriteVersion)) throw new PolicyException("ROLLBACK_VERSION_UNKNOWN", "The post-write GPO version was not recorded. Inspect the saved Backup-GPO snapshot and recover manually in GPMC to avoid overwriting a later edit.");
        _ = await Run<JsonElement>("restore", new { backup, control, backupData = JsonDefaults.Deserialize<BackupData>(backup.ProviderData) }, ct);
    }
    public Task<VerificationResult> VerifyRollbackAsync(GpoBackup backup, BenchmarkControl control, CancellationToken ct = default)
    {
        ValidateConfiguration();
        return Run<VerificationResult>("verifyRollback", new { backup, control, backupData = JsonDefaults.Deserialize<BackupData>(backup.ProviderData) }, ct);
    }
    private sealed record WindowsConfiguration(string Domain, string DomainController, string[] ApprovedGpoIds, string[] AuthorizedOus, string[] AllowedHosts, bool AllowCreateGpo, string BackupPath);
    private sealed record GpoInspection(GpoReference Gpo, string[] Value);
    private sealed record BackupData(string BackupId, string Directory, string[] PreviousValue, TargetResource Target, string GpoId, string PreWriteVersion, string[] EndpointPreviousValue, string ContentFingerprint, string SecurityExtensionNames);
}
