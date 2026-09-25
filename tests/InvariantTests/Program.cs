using System.Text.Json;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;
using GpoRemediator.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Configuration;

var passed = 0;
var failed = 0;
void Check(bool value, string message) { if (!value) throw new Exception(message); }
void Test(string name, Action action)
{
    try { action(); passed++; Console.WriteLine($"PASS {name}"); }
    catch (Exception e) { failed++; Console.Error.WriteLine($"FAIL {name}: {e.Message}"); }
}
void Reject(string code, Action action)
{
    try { action(); throw new Exception($"Expected policy rejection {code}"); }
    catch (PolicyException e) { Check(e.Code == code, $"Expected {code}, got {e.Code}"); }
}

var network = Catalog.Controls.Single(c => c.Id == "cis-2.2.3");
var target = new TargetResource("test-target", "SRV-APP-01.prosol.az", "prosol.az", "OU=Servers,DC=prosol,DC=az", "Windows Server 2022", "MemberServer");
var adapters = new AdapterRegistry();

Test("CIS 2.2.3 belongs to user rights, uses SIDs, and has the supplied member-server expected set", () =>
{
    Check(network.PolicyType == PolicyType.USER_RIGHTS_ASSIGNMENT, "Wrong policy type");
    Check(network.TechnicalSettingName == "SeNetworkLogonRight", "Wrong Windows user right");
    Check(PolicyValues.Equal(network.ExpectedValue, ["S-1-5-11", "S-1-5-32-544"], network.PolicyType), "Wrong expected SIDs");
    Check(network.Profiles.SequenceEqual(["MemberServer"]), "Role applicability is not constrained");
});
Test("All eleven required policy technologies exist in the catalog model", () =>
{
    foreach (var type in Enum.GetValues<PolicyType>()) Check(Catalog.Controls.Any(c => c.PolicyType == type), $"No representative control for {type}");
});
Test("SID normalization removes security-template marker, whitespace, case and duplicates", () =>
{
    var result = PolicyValues.Normalize([" *s-1-5-32-544 ", "S-1-5-11", "s-1-5-11"], PolicyType.USER_RIGHTS_ASSIGNMENT);
    Check(result.SequenceEqual(["S-1-5-11", "S-1-5-32-544"]), string.Join(',', result));
});
Test("SID comparison treats rights assignments as sets", () =>
{
    Check(PolicyValues.Equal(["S-1-5-32-544", "*S-1-5-11"], ["s-1-5-11", "s-1-5-32-544", "S-1-5-11"], PolicyType.USER_RIGHTS_ASSIGNMENT), "Equivalent assignments compared unequal");
    Check(!PolicyValues.Equal(["S-1-5-32-544"], network.ExpectedValue, network.PolicyType), "Missing Authenticated Users compared equal");
});
Test("Localized names and executable text are rejected as SIDs", () =>
{
    foreach (var value in new[] { "Administrators", "S-1-5-11; whoami", "", "S-2-5-11", "S-1-5-11\nwhoami" })
        Reject("INVALID_SID", () => PolicyValues.NormalizeSid(value));
});
Test("User-right adapter is separate from registry-backed adapters", () =>
{
    Check(adapters.Get(network, target) is UserRightsAdapter, "User rights routed through registry");
    foreach (var id in new[] { "sec-blank-password", "sec-uac", "reg-autorun", "registry-example" })
        Check(adapters.Get(Catalog.Controls.Single(c => c.Id == id), target) is RegistryPolicyAdapter, $"Registry adapter missing for {id}");
    Check(adapters.SupportedTypes.Length == 4, "Unsupported type unexpectedly enabled");
});
Test("Unapproved user-right technical names are rejected", () =>
    Reject("UNSUPPORTED_USER_RIGHT", () => adapters.Get(network with { TechnicalSettingName = "SeDebugPrivilege" }, target)));
Test("Registry mapping must have a key and exactly one expected value", () =>
{
    var registry = Catalog.Controls.Single(c => c.Id == "registry-example");
    Reject("INVALID_REGISTRY_MAPPING", () => adapters.Get(registry with { RegistryKey = null }, target));
    Reject("INVALID_REGISTRY_MAPPING", () => adapters.Get(registry with { ExpectedValue = ["0", "1"] }, target));
});
Test("Domain-controller role cannot use the member-server policy pack", () =>
    Reject("ROLE_NOT_APPLICABLE", () => adapters.Get(network, target with { Profile = "DomainController" })));
Test("Account Policy always requires intentional domain-wide or PSO review", () =>
{
    var account = Catalog.Controls.Single(c => c.Id == "account-password");
    Check(account.AccountPolicyScope == "DOMAIN_WIDE_OR_PSO", "Account scope absent");
    Reject("DOMAIN_ACCOUNT_POLICY_REVIEW_REQUIRED", () => adapters.Get(account, target));
    Reject("DOMAIN_ACCOUNT_POLICY_REVIEW_REQUIRED", () => adapters.Get(account with { Automated = true }, target));
});
Test("Manual and unimplemented policy types fail closed", () =>
{
    foreach (var c in Catalog.Controls.Where(c => !c.Automated && c.PolicyType != PolicyType.ACCOUNT_POLICY))
        Reject("UNSUPPORTED_POLICY_TYPE", () => adapters.Get(c, target));
});
Test("Restart requirement is explicit control metadata", () =>
{
    Check(Catalog.Controls.Single(c => c.Id == "sec-uac").RequiresRestart == RestartRequirement.REQUIRED, "UAC restart not declared");
    Check(network.RequiresRestart == RestartRequirement.NOT_REQUIRED, "User-right restart unexpectedly required");
});
Test("Mock discovery and new-GPO preview do not write simulated GPOs or endpoints", () =>
{
    using var store = new Store(":memory:");
    var provider = new MockWindowsPolicyProvider(store);
    var before = PolicyValues.Hash(store.List<MockGpo>("mock_gpos"));
    _ = provider.AnalyzeAsync(target, network).GetAwaiter().GetResult();
    var preview = provider.PreviewAsync("finding", target, network, new("CREATE", NewGpoName: "ORG-CIS-Test-Remediation")).GetAwaiter().GetResult();
    Check(preview.Gpo.Dedicated && preview.Gpo.Version == "0", "Create preview is not an uncreated dedicated GPO");
    Check(before == PolicyValues.Hash(store.List<MockGpo>("mock_gpos")), "Discovery or preview changed simulated GPO state");
    Check(store.List<MockEndpoint>("mock_endpoints").Length == 0, "Discovery or preview created endpoint policy state");
});
Test("Mock target selection protects default policies and requires a deterministic detected source", () =>
{
    using var store = new Store(":memory:");
    var provider = new MockWindowsPolicyProvider(store);
    Reject("GPO_NOT_APPROVED", () => provider.PreviewAsync("f", target, network, new("EXISTING", MockWindowsPolicyProvider.ProtectedId)).GetAwaiter().GetResult());
    Reject("SOURCE_AMBIGUOUS", () => provider.PreviewAsync("f", target with { Hostname = "SRV-UNDEFINED.prosol.az" }, network, new("DETECTED")).GetAwaiter().GetResult());
    Reject("SOURCE_AMBIGUOUS", () => provider.PreviewAsync("f", target with { Hostname = "SRV-AMBIGUOUS.prosol.az" }, network, new("DETECTED")).GetAwaiter().GetResult());
});
Test("Mock full-GPO backup restores unrelated settings as well as the changed right", () =>
{
    using var store = new Store(":memory:");
    var provider = new MockWindowsPolicyProvider(store);
    var before = store.Require<MockGpo>("mock_gpos", MockWindowsPolicyProvider.BaselineId);
    var snapshotHash = PolicyValues.Hash(before.Settings);
    var backup = provider.BackupAsync("job", target, network, before.Reference, "operator").GetAwaiter().GetResult();
    provider.ApplyAsync(before.Reference, network, network.ExpectedValue).GetAwaiter().GetResult();
    var after = store.Require<MockGpo>("mock_gpos", before.Reference.Id);
    Check(PolicyValues.Equal(after.Settings[network.Id], network.ExpectedValue, network.PolicyType), "Apply failed");
    Check(after.Settings["sec-uac"].SequenceEqual(before.Settings["sec-uac"]), "Unrelated UAC value changed");
    backup = backup with { PostWriteVersion = after.Reference.Version };
    provider.RestoreAsync(backup, network).GetAwaiter().GetResult();
    Check(provider.VerifyRollbackAsync(backup, network).GetAwaiter().GetResult().Success, "Restore verification failed");
    Check(PolicyValues.Hash(store.Require<MockGpo>("mock_gpos", before.Reference.Id).Settings) == snapshotHash, "Full GPO settings did not restore");
});
Test("Mock stale write and conflicting rollback versions fail closed", () =>
{
    using var store = new Store(":memory:");
    var provider = new MockWindowsPolicyProvider(store);
    var gpo = store.Require<MockGpo>("mock_gpos", MockWindowsPolicyProvider.BaselineId).Reference;
    var backup = provider.BackupAsync("job", target, network, gpo, "operator").GetAwaiter().GetResult();
    provider.ApplyAsync(gpo, network, network.ExpectedValue).GetAwaiter().GetResult();
    Reject("CONCURRENT_GPO_CHANGE", () => provider.ApplyAsync(gpo, network, network.ExpectedValue).GetAwaiter().GetResult());
    Reject("ROLLBACK_CONFLICT", () => provider.RestoreAsync(backup with { PostWriteVersion = "obsolete-version" }, network).GetAwaiter().GetResult());
});
Test("Password fields and bearer credentials are redacted", () =>
{
    const string secret = "sensitive-example-123";
    foreach (var raw in new[] { $"password={secret}", $"pwd: {secret}", $"{{\"password\":\"{secret}\",\"access_token\":\"{secret}\"}}", $"Authorization: Bearer {secret}", $"SecureString={secret}" })
    {
        var cleaned = Redactor.Clean(raw);
        Check(!cleaned.Contains(secret), $"Credential not redacted: {cleaned}");
        Check(cleaned.Contains("[REDACTED]"), "Missing redaction marker");
    }
});
Test("Quoted passwords containing whitespace remain entirely redacted", () =>
{
    var cleaned = Redactor.Clean("{\"password\":\"first-part second-secret-part\",\"normal\":\"retained\"}");
    Check(!cleaned.Contains("first-part") && !cleaned.Contains("second-secret-part"), "Part of a quoted credential leaked");
    using var json = JsonDocument.Parse(cleaned);
    Check(json.RootElement.GetProperty("normal").GetString() == "retained", "Non-secret context was damaged");
});
Test("Audit is append-oriented, ordered, hash-linked and redacts details", () =>
{
    using var store = new Store(":memory:");
    store.Audit("FIRST", "operator", details: new { password = "hidden-value", harmless = "context" });
    store.Audit("SECOND", "operator", controlId: network.Id);
    var events = store.AuditEvents();
    Check(events.Length == 2 && events[0].Event == "FIRST", "Append order incorrect");
    Check(events[0].PreviousHash == "GENESIS" && events[1].PreviousHash == events[0].Hash, "Hash links incorrect");
    Check(!events[0].Details.Contains("hidden-value"), "Audit leaked password");
    Check(store.AuditIntegrity(), "Fresh audit is invalid");
    var updateRejected = false;
    try { store.Execute("UPDATE audit SET event='ALTERED' WHERE id=1"); } catch { updateRejected = true; }
    Check(updateRejected, "Audit UPDATE was allowed");
    var deleteRejected = false;
    try { store.Execute("DELETE FROM audit WHERE id=1"); } catch { deleteRejected = true; }
    Check(deleteRejected, "Audit DELETE was allowed");
});
Test("Hash integrity check detects direct database tampering even after trigger removal", () =>
{
    using var store = new Store(":memory:");
    store.Audit("FIRST", "operator"); store.Audit("SECOND", "operator");
    store.Execute("DROP TRIGGER audit_no_update");
    store.Execute("UPDATE audit SET details='changed' WHERE id=1");
    Check(!store.AuditIntegrity(), "Tampering was not detected");
});
Test("Persistence table allowlist prevents identifier injection", () =>
{
    using var store = new Store(":memory:");
    var rejected = false;
    try { store.List<Finding>("findings; DROP TABLE audit;"); } catch (ArgumentException) { rejected = true; }
    Check(rejected, "Dynamic table identifier was accepted");
});
Test("A database cannot be reused across mock and Windows execution modes", () =>
{
    using var mock = new Store(":memory:");
    mock.BindExecutionMode("MOCK"); mock.BindExecutionMode("MOCK");
    var rejected = false;
    try { mock.BindExecutionMode("WINDOWS"); } catch (InvalidOperationException) { rejected = true; }
    Check(rejected, "Mock deployment accepted Windows execution");
    using var windows = new Store(":memory:");
    windows.BindExecutionMode("WINDOWS");
    rejected = false;
    try { windows.BindExecutionMode("MOCK"); } catch (InvalidOperationException) { rejected = true; }
    Check(rejected, "Windows deployment accepted mock execution");
    using var legacy = new Store(":memory:");
    _ = new MockWindowsPolicyProvider(legacy);
    rejected = false;
    try { legacy.BindExecutionMode("WINDOWS"); } catch (InvalidOperationException) { rejected = true; }
    Check(rejected, "Legacy simulated GPO state accepted Windows execution");
});
Test("Jobs and execution steps survive database reopening", () =>
{
    var directory = Path.Combine(Path.GetTempPath(), "GpoRemediator-Invariants", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    var path = Path.Combine(directory, "test.db");
    var at = PolicyValues.Now();
    var job = new RemediationJob("j-persist", "f-persist", network.Id, target.Id, "gpo-persist", "BACKING_UP", "operator", "MOCK", at, at, null, new JobOptions(), "preview-persist");
    using (var store = new Store(path))
    {
        store.Put("jobs", job.Id, job, job.State);
        store.Step(job.Id, "BACKING_UP", "Backup begun; password=must-hide");
    }
    using (var reopened = new Store(path))
    {
        Check(reopened.Require<RemediationJob>("jobs", job.Id).State == "BACKING_UP", "Job state lost");
        var step = reopened.Steps(job.Id).Single();
        Check(step.State == "BACKING_UP" && !step.Message.Contains("must-hide"), "Step missing or unredacted");
    }
    // Verify the resolved path before deleting this newly created test directory.
    var testRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "GpoRemediator-Invariants")) + Path.DirectorySeparatorChar;
    var resolved = Path.GetFullPath(directory);
    Check(resolved.StartsWith(testRoot, StringComparison.OrdinalIgnoreCase) && resolved.Length > testRoot.Length, "Refusing cleanup outside invariant test root");
    Directory.Delete(resolved, true);
});

Test("Service lifecycle refuses to interrupt any active remediation stage", () =>
{
    using var store = new Store(":memory:");
    using var engine = new RemediationEngine(store, new MockWindowsPolicyProvider(store), adapters, NullLogger<RemediationEngine>.Instance);
    foreach(var state in RemediationEngine.ActiveStates)
    {
        var now = PolicyValues.Now();
        var job = new RemediationJob("lifecycle-job", "finding", network.Id, target.Id, "gpo", state, "operator", "MOCK", now, now, null, new JobOptions(), "preview");
        store.Put("jobs", job.Id, job, state);
        var stopped = false;
        Reject("JOB_BUSY", () => engine.BeginMaintenance(() => stopped = true));
        Check(!stopped && !engine.Maintenance, $"Shutdown interrupted {state}");
    }
});
Test("Accepted shutdown blocks apply, verify and rollback submissions", () =>
{
    using var store = new Store(":memory:");
    using var engine = new RemediationEngine(store, new MockWindowsPolicyProvider(store), adapters, NullLogger<RemediationEngine>.Instance);
    engine.BeginMaintenance(() => { });
    Check(engine.Maintenance, "Maintenance was not recorded");
    Reject("SERVICE_STOPPING", () => engine.Submit("finding", new ApplyRequest("preview", new JobOptions()), "operator"));
    Reject("SERVICE_STOPPING", () => engine.SubmitFollowup("job", "VERIFY", "operator"));
    Reject("SERVICE_STOPPING", () => engine.SubmitFollowup("job", "ROLLBACK", "operator", true));
    Reject("SERVICE_STOPPING", () => engine.BeginMaintenance(() => { }));
});
Test("Failed lifecycle scheduling restores service availability", () =>
{
    using var store = new Store(":memory:");
    using var engine = new RemediationEngine(store, new MockWindowsPolicyProvider(store), adapters, NullLogger<RemediationEngine>.Instance);
    try { engine.BeginMaintenance(() => throw new IOException("Cannot persist marker")); } catch(IOException) { }
    Check(!engine.Maintenance, "Failed scheduling left the service locked");
    engine.BeginMaintenance(() => { });
    Check(engine.Maintenance, "A retry could not be accepted");
});

Test("Production GPO mapping registry covers the imported CIS v4 catalog", () =>
{
    var settings=ProductionGpoMappings.Settings;
    Check(settings.Length==405,"Expected 405 unique CIS IDs in the production mapping registry");
    Check(settings.Select(x=>x.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count()==405,"Duplicate production mapping IDs");
    Check(settings.All(x=>x.Handler is "SecurityTemplate" or "Registry" or "RegistrySet" or "AdvancedAudit"),"Unapproved handler exists");
    Check(settings.Count(x=>x.Handler=="Registry")==325,"Registry mapping count changed unexpectedly");
    Check(settings.Count(x=>x.Handler=="SecurityTemplate")==48,"Security-template mapping count changed unexpectedly");
    Check(settings.Count(x=>x.Handler=="AdvancedAudit")==27,"Advanced-audit mapping count changed unexpectedly");
    Check(settings.Count(x=>x.Handler=="RegistrySet")==5,"Registry-set mapping count changed unexpectedly");
    Check(settings.Count(x=>x.RequiresInput)==4,"Organization-value mapping count changed unexpectedly");
});
Test("Advanced Audit mappings expose the actual requested state", () =>
{
    var audit=ProductionGpoMappings.Settings.First(x=>x.Handler=="AdvancedAudit");
    var selection=new GpoSelection(Guid.NewGuid().ToString(),"OU=Servers,DC=example,DC=com",audit.Id,0);
    var display=audit.DesiredDisplay(selection);
    Check(!string.IsNullOrWhiteSpace(display) && display!="<blank>","Advanced Audit desired display regressed to blank");
});
Test("Production mapping validation blocks untrusted or invalid operator values", () =>
{
    var baseSelection=new GpoSelection(Guid.NewGuid().ToString(),"OU=Servers,DC=example,DC=com","18.10.4.1",14);
    ProductionGpoMappings.Validate(baseSelection);
    Reject("GPO_CUSTOM_VALUE_NOT_ALLOWED",()=>ProductionGpoMappings.Validate(baseSelection with{CustomValue="browser supplied registry value"}));
    var rename=baseSelection with{Setting="2.3.1.4",CustomValue=""};
    Reject("GPO_CUSTOM_VALUE_REQUIRED",()=>ProductionGpoMappings.Validate(rename));
    Reject("ACCOUNT_NAME_INVALID",()=>ProductionGpoMappings.Validate(rename with{CustomValue="bad\\name"}));
    ProductionGpoMappings.Validate(rename with{CustomValue="SrvLocalOps"});
    var account=baseSelection with{Setting="1.1.4",ScopeDn="DC=example,DC=com",AccountScope="Domain",Value=21};
    Reject("GPO_VALUE_INVALID",()=>ProductionGpoMappings.Validate(account));
    ProductionGpoMappings.Validate(account with{Value=14});
});
Test("Account Policy override ranges cannot weaken the CIS state", () =>
{
    var gpo=Guid.NewGuid().ToString();
    var domain="DC=example,DC=com";
    Reject("GPO_VALUE_INVALID",()=>ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.1.1",23,AccountScope:"Domain")));
    Reject("GPO_VALUE_INVALID",()=>ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.1.4",13,AccountScope:"Domain")));
    Reject("GPO_VALUE_INVALID",()=>ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.1.5",0,AccountScope:"Domain")));
    Reject("GPO_VALUE_INVALID",()=>ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.1.6",1,AccountScope:"Domain")));
    Reject("GPO_VALUE_INVALID",()=>ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.2.2",0,AccountScope:"Domain")));
    Reject("GPO_VALUE_INVALID",()=>ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.2.2",6,AccountScope:"Domain")));
    ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.1.1",24,AccountScope:"Domain"));
    ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.1.4",20,AccountScope:"Domain"));
    ProductionGpoMappings.Validate(new GpoSelection(gpo,domain,"1.2.2",1,AccountScope:"Domain"));
});
Test("Production mappings keep server-side desired values authoritative", () =>
{
    var fixedRule=ProductionGpoMappings.Require("18.10.8.3");
    var selection=new GpoSelection(Guid.NewGuid().ToString(),"OU=Servers,DC=example,DC=com",fixedRule.Id,999);
    Check(fixedRule.DesiredDisplay(selection)=="255","Fixed benchmark mapping trusted the browser numeric field");
    var account=ProductionGpoMappings.Require("1.1.4");
    Check(account.DesiredDisplay(selection with{Setting=account.Id,Value=16})=="16","Approved Account Policy override was not honored");
});
Test("Only CIS controls classified Automated are writable", () =>
{
    var settings=ProductionGpoMappings.Settings;
    Check(settings.Count(x=>x.Writable)==401,"Expected 401 server-writable mappings");
    foreach(var id in new[]{"1.2.3","2.3.11.6","18.10.43.10.1","18.10.43.10.2"})
    {
        Check(!ProductionGpoMappings.Require(id).Writable,$"{id} unexpectedly writable");
        Reject("GPO_MANUAL_ONLY",()=>ProductionGpoMappings.Validate(new GpoSelection(Guid.NewGuid().ToString(),"DC=example,DC=com",id,1)));
    }
});
Test("All domain-sensitive Account Policy controls are constrained to the domain scope", () =>
{
    var ids=ProductionGpoMappings.Settings.Where(x=>x.DomainPolicySensitive).Select(x=>x.Id).OrderBy(x=>x).ToArray();
    Check(ids.SequenceEqual(new[]{"1.1.1","1.1.3","1.1.4","1.1.5","1.1.6","1.2.1","1.2.2","1.2.3","1.2.4"}),"Domain-sensitive mapping set changed");
    Check(ProductionGpoMappings.Settings.Where(x=>x.DomainPolicySensitive).All(x=>x.Scope=="Domain"),"Domain-sensitive mapping is not Domain scoped");
});
Console.WriteLine($"Invariant tests: {passed} passed; {failed} failed.");
return failed == 0 ? 0 : 1;
