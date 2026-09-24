using System.Text.Json;
using System.Text.Json.Serialization;

namespace GpoRemediator.Domain;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PolicyType { REGISTRY_POLICY, REGISTRY_PREFERENCE, SECURITY_OPTION, USER_RIGHTS_ASSIGNMENT, ACCOUNT_POLICY, ADVANCED_AUDIT_POLICY, WINDOWS_FIREWALL, ADMINISTRATIVE_TEMPLATE, SERVICE_CONFIGURATION, MANUAL, UNSUPPORTED }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RestartRequirement { NOT_REQUIRED, RECOMMENDED, REQUIRED }

public record BenchmarkControl(
    string Id, string BenchmarkId, string BenchmarkVersion, string ControlId, string Title,
    string Description, string Level, bool Automated, string OperatingSystem, string[] Profiles,
    PolicyType PolicyType, string PolicyPath, string TechnicalSettingName, string[] ExpectedValue,
    string ExpectedDisplayValue, bool RequiresGpUpdate, RestartRequirement RequiresRestart,
    bool SupportsRollback, bool SupportedByGpo, string[] SpecialConditions, string[] RoleExceptions,
    string Notes, string? RegistryKey = null, string? RegistryType = null, string? AccountPolicyScope = null);
public record TargetResource(string Id, string Hostname, string Domain, string Ou, string OperatingSystem, string Profile);
public record Finding(string Id, string ControlId, string TargetId, string[] CurrentValue, string Status, string CreatedAt);
public record GpoLink(string Target, int Order, bool Enforced, bool Enabled);
public record GpoReference(string Id, string Name, GpoLink[] Links, string[] SecurityFiltering, string? WmiFilter,
    bool Approved, bool Dedicated, bool Protected, string Inheritance, int? AffectedComputers, string? DomainController,
    string? Version = null);
public record PolicySourceAnalysis(string Status, string Confidence, string Message, TargetResource Target,
    GpoReference[] ApplicableGpos, string? WinningGpoId, string[] CurrentValue, bool SettingDefined, string AnalyzedAt);
public record TargetSelection(string Strategy, string? GpoId = null, string? NewGpoName = null);
public record ImpactAnalysis(string Id, string FindingId, string ControlId, TargetResource Target, GpoReference Gpo,
    string[] OldValue, string[] ProposedValue, bool RequiresGpUpdate, RestartRequirement RequiresRestart,
    bool RollbackAvailable, bool BroadImpact, string[] Warnings, TargetSelection Selection, string Fingerprint,
    string CreatedAt, string ExecutionMode);
public record PreflightResult(bool CanRead, bool CanEdit, bool CanLink, bool CanVerify, string Identity,
    string[] Errors, string[] Warnings, string? DomainController);
public record VerificationResult(bool Success, string Code, string Message, string[] ActualValue,
    bool Retryable = false, string? DomainController = null);
public record GpoBackup(string Id, string JobId, string GpoId, string GpoName, string ControlId, string Operator,
    string CreatedAt, string TargetId, string Scope, string[] PreviousValue, string ProviderData,
    string? PostWriteVersion = null, string[]? EndpointPreviousValue = null);
public record JobOptions(bool RunGpUpdate = true, bool AuthorizeRestart = false, bool AcknowledgeBroadImpact = false);
public record ApplyRequest(string PreviewId, JobOptions Options);
public record PreviewRequest(TargetSelection Selection);
public record CreateFindingRequest(string ControlId, string Hostname, string Profile = "MemberServer", string[]? CurrentValue = null, bool BenchmarkSelection = false);
public record RemediationJob(string Id, string FindingId, string ControlId, string TargetId, string GpoId, string State,
    string Operator, string Mode, string CreatedAt, string UpdatedAt, string? Error, JobOptions Options,
    string PreviewId, string? BackupId = null);
public record RemediationStep(long Id, string JobId, string State, string Message, string CreatedAt);
public record AuditEvent(long Id, string Event, string Operator, string? JobId, string? ControlId, string? GpoId,
    string Details, string CreatedAt, string PreviousHash, string Hash);
public record TargetScanRequest(string Hostname, string Profile = "Auto");
public record ScanControlResult(string ControlId, string ControlCode, string Title, string Status, string[] ActualValue,
    string[] ExpectedValue, string Code, string Message, string? FindingId = null);
public record TargetScanResult(TargetResource Target, ScanControlResult[] Results, int Compliant, int NonCompliant,
    int Unavailable, int FindingsCreated, string ScannedAt);
public record ReadinessCheck(string Id, string Label, string Status, string Message, bool Required = true);
public record EnvironmentReadiness(string Mode, bool Ready, string Identity, string? DomainController,
    ReadinessCheck[] Checks, string CheckedAt);
public record SafePlanResult(PolicySourceAnalysis Analysis, ImpactAnalysis Impact, PreflightResult Preflight,
    bool DryRun, int Writes, TargetSelection Selection);
public record SetupConfigRequest(string Urls, string Domain, string DomainController, string[] ApprovedGpoIds,
    string[] AuthorizedOus, string[] AllowedHosts, string[] AllowedOperators, string BackupPath, bool AutoRestart = true);
public record WriteModeRequest(bool Enable, string Confirmation, bool AutoRestart = true);
public record SetupConfigView(string Urls, string Domain, string DomainController, string[] ApprovedGpoIds,
    string[] AuthorizedOus, string[] AllowedHosts, string[] AllowedOperators, string BackupPath, bool EnableWrites,
    string ConfigPath, bool Exists);
public record ExecutionIdentity(string Strategy, string Name);

public sealed class PolicyException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }, WriteIndented = false
    };
    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T Deserialize<T>(string value) => JsonSerializer.Deserialize<T>(value, Options)!;
}
