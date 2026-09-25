namespace GpoRemediator.Domain;

// Credentials are transport-only. Never put this type in Store, an audit event, or an execution record.
public sealed class GpoLoginRequest
{
    public string UserName { get; set; } = "";
    public string Password { get; set; } = "";
    public override string ToString() => "[GPO login redacted]";
}

public record GpoChoice(string Id, string Name, bool Protected, bool Selectable);
public record GpoScope(string Dn, string Name, string Kind);
public record GpoInventory(string Domain, string DomainController, string ExecutionUser, GpoChoice[] Gpos, GpoScope[] Scopes);

public record GpoSelection(string GpoId, string ScopeDn, string Setting, int Value,
    string AccountScope = "Domain", string Refresh = "None", bool FirstLink = false, string? CustomValue = null);

public record GpoHealthCheck(string Id, string Label, string State, string Message, bool Required = true);
public record GpoEnvironmentStatus(string Domain, string DomainController, string ExecutionUser,
    bool Ready, GpoHealthCheck[] Checks, string CheckedAt);
public record GpoConflictInfo(string Severity, string Code, string Message, string? GpoId = null, string? GpoName = null, string? Scope = null);
public record GpoAffectedObjects(int Computers, int Servers, int Workstations, int Disabled, string[] SampleHosts, bool Truncated, int Users = 0);
public record GpoImpactDetails(string Inheritance, bool BlockInheritance, GpoConflictInfo[] Conflicts,
    GpoAffectedObjects AffectedObjects, string[] ExistingLinkScopes, string[] SecurityFiltering, string? WmiFilter);
public record GpoDcVersionStatus(string DomainController, string? AdVersion, string? GptVersion, bool Reachable, bool VersionsMatch, string Message);
public record GpoEndpointCheck(string Hostname, string State, string Message, string? ActualValue = null);
public record GpoVerificationDetails(string AdVersion, string GptVersion, bool VersionsMatch,
    string[] DomainControllers, string[] ReplicationWarnings, string CheckedAt,
    bool ReplicationConverged = false, GpoDcVersionStatus[]? DcVersions = null);

public record GpoPreview(GpoChoice Gpo, GpoScope Scope, string? PreviousValue, string Fingerprint, string ScopeLinks,
    GpoLink? ExistingLink, string[] RefreshComputers, string[] Warnings,
    GpoImpactDetails? Impact = null, GpoEnvironmentStatus? Preflight = null, string? DesiredValue = null, bool NoChange = false);

public record GpoWorkflowPlan(string Id, string Actor, string ExecutionUser, string Mode, string Domain, string DomainController,
    GpoSelection Selection, GpoPreview Preview, string CreatedAt, string? MappingHash = null);
public record GpoConsent(string Confirmation, bool AcknowledgeImpact = false, bool AcknowledgeProtected = false, string? ChangeReference = null, string? ApprovedBy = null);
public record GpoRefreshResult(string Computer, string State, string Message);
public record GpoWorkflowResult(string State, string Message, string? BackupId, string? BackupDirectory, string? PostFingerprint,
    bool GpoPublished, bool LinkVerified, GpoRefreshResult[] RefreshResults, string EffectiveStatus,
    GpoVerificationDetails? Verification = null, GpoEndpointCheck[]? EndpointChecks = null);
public record GpoWorkflowRun(string Id, GpoWorkflowPlan Plan, GpoWorkflowResult Result, string UpdatedAt, GpoConsent? Approval = null);

public record GpoEvidence(string SchemaVersion, string Product, string Benchmark, string OperationId, string GeneratedAt,
    string Actor, string ExecutionUser, string Domain, string DomainController, string ControlId, string Setting,
    string GpoId, string GpoName, string ScopeDn, string? BeforeValue, string DesiredValue, string State,
    string? BackupId, string? BackupDirectory, string EffectiveStatus, GpoVerificationDetails? Verification,
    string[] Warnings, string IntegrityHash, string? ChangeReference = null, string? ApprovedBy = null, string? Handler = null, string? MappingSource = null,
    GpoEndpointCheck[]? EndpointChecks = null);

public static class GpoWorkflowRules
{
    public static void ValidateConsent(GpoWorkflowPlan plan, GpoConsent consent)
    {
        if (consent.Confirmation != "APPLY" || !consent.AcknowledgeImpact)
            throw new PolicyException("GPO_CONFIRMATION_REQUIRED", "Type APPLY and acknowledge all existing links and the selected scope.");
        if (string.IsNullOrWhiteSpace(consent.ChangeReference) || consent.ChangeReference.Length > 128 || consent.ChangeReference.IndexOfAny(['\r','\n','\0']) >= 0)
            throw new PolicyException("CHANGE_REFERENCE_REQUIRED", "Enter the approved change/ticket reference before Apply.");
        if (string.IsNullOrWhiteSpace(consent.ApprovedBy) || consent.ApprovedBy.Length > 256 || consent.ApprovedBy.IndexOfAny(['\r','\n','\0']) >= 0)
            throw new PolicyException("APPROVER_REQUIRED", "Enter the reviewer/approver before Apply.");
        if (plan.Preview.Gpo.Protected && !consent.AcknowledgeProtected)
            throw new PolicyException("PROTECTED_GPO_CONFIRMATION", "Explicitly acknowledge editing the protected default domain policy.");
    }
}
