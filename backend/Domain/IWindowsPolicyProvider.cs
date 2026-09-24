namespace GpoRemediator.Domain;

// All discovery and Preview methods MUST be read-only. Methods use service identity, never browser credentials.
public interface IWindowsPolicyProvider
{
    string Mode { get; }
    Task<EnvironmentReadiness> ReadinessAsync(CancellationToken ct = default);
    Task<TargetResource> ResolveTargetAsync(TargetResource target, CancellationToken ct = default);
    Task<PreflightResult> PreflightAsync(TargetResource target, GpoReference? gpo, CancellationToken ct = default);
    Task<PolicySourceAnalysis> AnalyzeAsync(TargetResource target, BenchmarkControl control, CancellationToken ct = default);
    Task<ImpactAnalysis> PreviewAsync(string findingId, TargetResource target, BenchmarkControl control, TargetSelection selection, CancellationToken ct = default);
    Task<GpoReference> EnsureGpoAsync(ImpactAnalysis plan, CancellationToken ct = default);
    Task<GpoBackup> BackupAsync(string jobId, TargetResource target, BenchmarkControl control, GpoReference gpo, string operatorName, CancellationToken ct = default);
    Task ApplyAsync(GpoReference gpo, BenchmarkControl control, string[] value, CancellationToken ct = default);
    Task<VerificationResult> VerifyGpoAsync(GpoReference gpo, BenchmarkControl control, string[] expected, CancellationToken ct = default);
    Task<VerificationResult> VerifyScopeAsync(GpoReference gpo, TargetResource target, CancellationToken ct = default);
    Task<VerificationResult> RefreshAsync(TargetResource target, CancellationToken ct = default);
    Task<VerificationResult> VerifyRsopAsync(TargetResource target, GpoReference gpo, BenchmarkControl control, string[] expected, CancellationToken ct = default);
    Task<VerificationResult> VerifyEndpointAsync(TargetResource target, BenchmarkControl control, string[] expected, CancellationToken ct = default);
    Task<VerificationResult> RestartAsync(TargetResource target, CancellationToken ct = default);
    Task RestoreAsync(GpoBackup backup, BenchmarkControl control, CancellationToken ct = default);
    Task<VerificationResult> VerifyRollbackAsync(GpoBackup backup, BenchmarkControl control, CancellationToken ct = default);
}
