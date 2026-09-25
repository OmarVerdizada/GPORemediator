using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// Configuration-only provider used only while the local Setup UI is open.
// It intentionally implements no discovery, simulation, preview, write or verification path.
public sealed class SetupOnlyWindowsPolicyProvider : IWindowsPolicyProvider
{
    public string Mode => "SETUP";
    private static PolicyException Blocked() => new("WINDOWS_MODE_REQUIRED","Setup mode is configuration-only. Save the real Windows / AD settings and restart into Windows mode before using remediation features.");

    public Task<EnvironmentReadiness> ReadinessAsync(CancellationToken ct=default) => Task.FromResult(new EnvironmentReadiness(
        Mode,false,"SETUP\\local-configuration","",[
            new ReadinessCheck("runtime","Configuration mode","PASS","Local setup UI is available."),
            new ReadinessCheck("writes","Domain operations","BLOCKED","No AD/GPO discovery, preview, apply, rollback, verification, or gpupdate is available in Setup mode.")
        ],PolicyValues.Now()));
    public Task<TargetResource> ResolveTargetAsync(TargetResource target,CancellationToken ct=default)=>Task.FromException<TargetResource>(Blocked());
    public Task<PreflightResult> PreflightAsync(TargetResource target,GpoReference? gpo,CancellationToken ct=default)=>Task.FromException<PreflightResult>(Blocked());
    public Task<PolicySourceAnalysis> AnalyzeAsync(TargetResource target,BenchmarkControl control,CancellationToken ct=default)=>Task.FromException<PolicySourceAnalysis>(Blocked());
    public Task<ImpactAnalysis> PreviewAsync(string findingId,TargetResource target,BenchmarkControl control,TargetSelection selection,CancellationToken ct=default)=>Task.FromException<ImpactAnalysis>(Blocked());
    public Task<GpoReference> EnsureGpoAsync(ImpactAnalysis plan,CancellationToken ct=default)=>Task.FromException<GpoReference>(Blocked());
    public Task<GpoBackup> BackupAsync(string jobId,TargetResource target,BenchmarkControl control,GpoReference gpo,string operatorName,CancellationToken ct=default)=>Task.FromException<GpoBackup>(Blocked());
    public Task ApplyAsync(GpoReference gpo,BenchmarkControl control,string[] value,CancellationToken ct=default)=>Task.FromException(Blocked());
    public Task<VerificationResult> VerifyGpoAsync(GpoReference gpo,BenchmarkControl control,string[] expected,CancellationToken ct=default)=>Task.FromException<VerificationResult>(Blocked());
    public Task<VerificationResult> VerifyScopeAsync(GpoReference gpo,TargetResource target,CancellationToken ct=default)=>Task.FromException<VerificationResult>(Blocked());
    public Task<VerificationResult> RefreshAsync(TargetResource target,CancellationToken ct=default)=>Task.FromException<VerificationResult>(Blocked());
    public Task<VerificationResult> VerifyRsopAsync(TargetResource target,GpoReference gpo,BenchmarkControl control,string[] expected,CancellationToken ct=default)=>Task.FromException<VerificationResult>(Blocked());
    public Task<VerificationResult> VerifyEndpointAsync(TargetResource target,BenchmarkControl control,string[] expected,CancellationToken ct=default)=>Task.FromException<VerificationResult>(Blocked());
    public Task<VerificationResult> RestartAsync(TargetResource target,CancellationToken ct=default)=>Task.FromException<VerificationResult>(Blocked());
    public Task RestoreAsync(GpoBackup backup,BenchmarkControl control,CancellationToken ct=default)=>Task.FromException(Blocked());
    public Task<VerificationResult> VerifyRollbackAsync(GpoBackup backup,BenchmarkControl control,CancellationToken ct=default)=>Task.FromException<VerificationResult>(Blocked());
}
