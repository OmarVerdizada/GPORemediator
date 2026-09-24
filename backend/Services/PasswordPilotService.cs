using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;

namespace GpoRemediator.Services;

public sealed class PasswordPilotService(IConfiguration config, Store store, RemediationEngine engine, ILogger<PasswordPilotService> logger)
{
    private readonly WindowsPowerShellExecutor executor = new(logger);
    private readonly SemaphoreSlim discoveryGate = new(1, 1);
    private PilotDiscovery? discovery;
    private bool Real => !config.GetValue<bool>("LocalSetup") && string.Equals(config["Mode"], "Windows", StringComparison.OrdinalIgnoreCase);
    private string Mode => Real ? "WINDOWS" : "MOCK";
    private string Domain => config["Windows:Domain"] ?? "";
    private string Dc => config["Windows:DomainController"] ?? "";
    private object Configuration => new { domain = Domain, domainController = Dc, backupPath = config["Windows:BackupPath"] };

    public async Task<PilotDiscovery> DiscoverAsync(CancellationToken ct)
    {
        await discoveryGate.WaitAsync(ct);
        try
        {
            if (discovery is not null) return discovery;
            if (!OperatingSystem.IsWindows()) return discovery = new("", "", "", "", @"C:\ProgramData\GpoRemediator\Backups", ["Automatic AD detection requires Windows; enter configuration manually."]);
            return discovery = await executor.RunAsync<PilotDiscovery>("discover", new { }, new { }, ct);
        }
        finally { discoveryGate.Release(); }
    }
    public async Task<EnvironmentReadiness> ReadinessAsync(CancellationToken ct)
    {
        if (!Real) return new(Mode, true, "Demo identity", null,
            [new("simulation", "Password pilot simulation", "PASS", "Demo changes affect only local state. This does not establish AD readiness.")], PolicyValues.Now());
        try { return await executor.RunAsync<EnvironmentReadiness>("passwordReadiness", Configuration, new { }, ct); }
        catch (PolicyException ex) { return new(Mode, false, "Windows service identity", Dc, [new("pilot", "Password pilot readiness", "FAIL", ex.Message)], PolicyValues.Now()); }
    }
    public async Task<PasswordPlan> PlanAsync(PasswordPlanRequest request, string actor, CancellationToken ct)
    {
        PasswordPilotRules.Validate(request.Setting, request.Value);
        if (string.IsNullOrWhiteSpace(request.User) || request.User.Length > 256 || request.User.IndexOfAny(['\r','\n','\0','*']) >= 0)
            throw new PolicyException("TEST_USER_REQUIRED", "Enter one exact test user's sAMAccountName, UPN or object GUID. No password is requested.");
        var before = await ReadAsync(request.User.Trim(), ct);
        if (before.SourceId is not null && before.Precedence <= 1)
            throw new PolicyException("PSO_PRECEDENCE_CONFLICT", "The current policy already has precedence 1. Choose a different test user or have an administrator resolve its policy; no existing policy will be edited.");
        var after = new Dictionary<string, int>(before.Values) { [request.Setting] = request.Value };
        PasswordPilotRules.ValidateAges(after);
        if (before.Values[request.Setting] == request.Value)
            throw new PolicyException("PASSWORD_ALREADY_SET", "The selected user's effective policy already has this value. No remediation is needed.");
        var plan = new PasswordPlan(Guid.NewGuid().ToString("N"), actor, Mode, Domain, Dc, request.Setting, request.Value,
            before, after, PasswordPilotRules.Fingerprint(before), PolicyValues.Now());
        store.Put("password_plans", plan.Id, plan);
        store.Audit("PASSWORD_PLAN_PREPARED", actor, details: new { plan.Id, before.User, request.Setting, request.Value, writes = 0, mode = Mode });
        return plan;
    }
    private async Task<PasswordSnapshot> ReadAsync(string user, CancellationToken ct)
    {
        if (Real) return await executor.RunAsync<PasswordSnapshot>("passwordRead", Configuration, new { user }, ct);
        var key = PolicyValues.Hash(user.ToUpperInvariant());
        return store.Get<PasswordSnapshot>("password_mock", key) ?? new(key, user, $"CN={user},OU=Demo", null, 0,
            new() { ["PasswordHistoryCount"]=12, ["MaxPasswordAge"]=90, ["MinPasswordAge"]=0, ["MinPasswordLength"]=8,
                ["ComplexityEnabled"]=0, ["ReversibleEncryptionEnabled"]=0, ["LockoutThreshold"]=5,
                ["LockoutDuration"]=1800, ["LockoutObservationWindow"]=1800 },
            ["Simulation only. In Windows mode, only the exact selected user and their effective password policy are read."]);
    }
    public PasswordExecution[] History() => store.List<PasswordExecution>("password_jobs");
    public async Task<PasswordExecution> ApplyAsync(string id, string confirmation, string actor)
    {
        if (confirmation != "APPLY") throw new PolicyException("CONFIRMATION_REQUIRED", "Type APPLY to authorize this test-user policy.");
        var plan = store.Require<PasswordPlan>("password_plans", id);
        AssertContext(plan, actor);
        if (store.Get<PasswordExecution>("password_jobs", id) is { } previous) return previous;
        if (DateTimeOffset.UtcNow - DateTimeOffset.Parse(plan.CreatedAt) > TimeSpan.FromMinutes(15))
            throw new PolicyException("PLAN_EXPIRED", "Prepare a new plan; this preview is older than 15 minutes.");
        AssertWrites();
        engine.BeginMaintenance(() => {
            if (store.Get<PasswordExecution>("password_jobs", id) is not null)
                throw new PolicyException("PASSWORD_ALREADY_STARTED", "This plan already has an execution record. Refresh history.");
        });
        var record = new PasswordExecution(id, plan, "APPLYING", null, "Backup and selected-user policy operation started.", PolicyValues.Now());
        try
        {
            var fresh = await ReadAsync(Real ? plan.Before.UserId : plan.Before.User, CancellationToken.None);
            if (PasswordPilotRules.Fingerprint(fresh) != plan.Fingerprint)
                throw new PolicyException("STALE_PASSWORD_PLAN", "The user's effective policy changed. Prepare a new plan.");
            store.Put("password_jobs", id, record, record.State);
            store.Audit("PASSWORD_APPLY_STARTED", actor, details: new { id, plan.Before.User, plan.Setting, mode = Mode });
            PasswordResult result;
            if (Real) result = await executor.RunAsync<PasswordResult>("passwordApply", Configuration, new { plan }, CancellationToken.None);
            else
            {
                var current = plan.Before with { SourceId = "demo-" + id, Precedence = plan.Before.SourceId is null ? 1000 : plan.Before.Precedence - 1, Values = plan.After };
                store.Put("password_mock", plan.Before.UserId, current);
                result = new(current.SourceId, true, "Simulation verified. No AD policy was written.");
            }
            record = record with { State = result.Verified ? "VERIFIED" : "VERIFICATION_FAILED", PolicyId = result.PolicyId, Message = result.Message, UpdatedAt = PolicyValues.Now() };
        }
        catch (Exception ex)
        {
            record = record with { State = "REVIEW_REQUIRED", Message = ex is PolicyException p ? p.Code + ": " + p.Message : "Operation interrupted. Review the backup and named pilot policy before recovery.", UpdatedAt = PolicyValues.Now() };
        }
        finally { store.Put("password_jobs", id, record, record.State); engine.EndMaintenance(); }
        store.Audit("PASSWORD_APPLY_RESULT", actor, details: record);
        return record;
    }
    public async Task<PasswordExecution> RollbackAsync(string id, string confirmation, string actor)
    {
        if (confirmation != "ROLLBACK") throw new PolicyException("CONFIRMATION_REQUIRED", "Type ROLLBACK to remove the pilot assignment.");
        var record = store.Require<PasswordExecution>("password_jobs", id);
        AssertContext(record.Plan, actor); AssertWrites();
        if (record.State == "ROLLED_BACK") return record;
        // The server-held plan also identifies interrupted operations; PowerShell checks ownership/content before removing anything.
        engine.BeginMaintenance(() => { });
        try
        {
            store.Put("password_jobs", id, record with { State = "ROLLING_BACK" }, "ROLLING_BACK");
            PasswordResult result;
            if (Real) result = await executor.RunAsync<PasswordResult>("passwordRollback", Configuration, new { plan = record.Plan }, CancellationToken.None);
            else
            {
                var current = await ReadAsync(record.Plan.Before.User, CancellationToken.None);
                if (current.SourceId != "demo-" + id) throw new PolicyException("ROLLBACK_CONFLICT", "A later policy is active. Roll back the latest change first.");
                store.Put("password_mock", record.Plan.Before.UserId, record.Plan.Before);
                result = new("demo-" + id, true, "Simulation rollback verified.");
            }
            record = record with { State = result.Verified ? "ROLLED_BACK" : "ROLLBACK_REVIEW_REQUIRED", Message = result.Message, UpdatedAt = PolicyValues.Now() };
        }
        catch (Exception ex) { record = record with { State = "ROLLBACK_REVIEW_REQUIRED", Message = ex is PolicyException p ? p.Code + ": " + p.Message : "Recovery needs administrator review.", UpdatedAt = PolicyValues.Now() }; }
        finally { store.Put("password_jobs", id, record, record.State); engine.EndMaintenance(); }
        store.Audit("PASSWORD_ROLLBACK_RESULT", actor, details: record);
        return record;
    }
    private void AssertWrites()
    {
        if (Real && !config.GetValue<bool>("Windows:EnableWrites")) throw new PolicyException("WRITES_DISABLED", "Enable writes in Settings after checking readiness.");
    }
    private void AssertContext(PasswordPlan plan, string actor)
    {
        if (plan.Mode != Mode || plan.Domain != Domain || plan.DomainController != Dc || plan.Operator != actor)
            throw new PolicyException("PLAN_CONTEXT_CHANGED", "Prepare a new plan under the current operator and environment.");
    }
}
