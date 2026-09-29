using System.Text.Json;
using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;

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

Test("Windows operator normalization remains narrow", () =>
{
    Check(WindowsAccount.Normalize(" PROSOL/Administrator ")==@"PROSOL\Administrator", "Slash normalization failed");
    Check(WindowsAccount.IsOperator(@"PROSOL\Administrator"), "Valid DOMAIN\\user rejected");
    Check(!WindowsAccount.IsOperator("Administrator") && !WindowsAccount.IsOperator(@"A\B\C"), "Ambiguous identity accepted");
});

Test("Production catalog contract is complete", () =>
{
    var catalog = ProductionGpoMappings.Catalog;
    Check(catalog.Meta.TotalUnique == 405 && catalog.Mappings.Length == 405, "Catalog count changed");
    Check(catalog.Mappings.Count(x => x.Writable) == 401, "Writable count changed");
    Check(catalog.Mappings.Select(x => x.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 405, "Duplicate mappings exist");
});

Test("Selection validation fails closed", () =>
{
    var writable = ProductionGpoMappings.Settings.First(x => x.Writable && !x.RequiresInput);
    Reject("GPO_SELECTION_REQUIRED", () => ProductionGpoMappings.Validate(new GpoSelection("not-a-guid", "DC=prosol,DC=az", writable.Id, writable.Suggested ?? 0)));
    Reject("GPO_OPTIONS_INVALID", () => ProductionGpoMappings.Validate(new GpoSelection(Guid.NewGuid().ToString(), "DC=prosol,DC=az", writable.Id, writable.Suggested ?? 0, Refresh:"Anything")));
    var manual = ProductionGpoMappings.Settings.First(x => !x.Writable);
    Reject("GPO_MANUAL_ONLY", () => ProductionGpoMappings.Validate(new GpoSelection(Guid.NewGuid().ToString(), "DC=prosol,DC=az", manual.Id, 0)));
});

Test("Consent requires approval metadata", () =>
{
    var mapping = ProductionGpoMappings.Settings.First(x => x.Writable && !x.RequiresInput);
    var gpo = new GpoChoice(Guid.NewGuid().ToString(), "Test", false, true);
    var scope = new GpoScope("DC=prosol,DC=az", "prosol.az", "Domain");
    var selection = new GpoSelection(gpo.Id, scope.Dn, mapping.Id, mapping.Suggested ?? 0);
    var preview = new GpoPreview(gpo, scope, null, "fp", "", null, [], [], DesiredValue:"x");
    var plan = new GpoWorkflowPlan(Guid.NewGuid().ToString("N"), @"PROSOL\Operator", @"PROSOL\Svc", "WINDOWS", "prosol.az", "dc01.prosol.az", selection, preview, PolicyValues.Now(), PolicyValues.Hash(mapping));
    Reject("CHANGE_REFERENCE_REQUIRED", () => GpoWorkflowRules.ValidateConsent(plan, new GpoConsent("APPLY", true)));
    Reject("APPROVER_REQUIRED", () => GpoWorkflowRules.ValidateConsent(plan, new GpoConsent("APPLY", true, false, "CHG-1")));
    GpoWorkflowRules.ValidateConsent(plan, new GpoConsent("APPLY", true, false, "CHG-1", @"PROSOL\Reviewer"));
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

Test("Audit is append-only and hash chained", () =>
{
    using var store = new Store(":memory:");
    store.Audit("FIRST", "operator", details: new { password = "hidden-value", harmless = "context" });
    store.Audit("SECOND", "operator", controlId: "1.1.1");
    var events = store.AuditEvents();
    Check(events.Length == 2 && events[0].PreviousHash == "GENESIS" && events[1].PreviousHash == events[0].Hash, "Audit chain invalid");
    Check(!events[0].Details.Contains("hidden-value"), "Audit leaked a password");
    Check(store.AuditIntegrity(), "Fresh audit integrity failed");
    var rejected=false; try { store.Execute("UPDATE audit SET event='ALTERED' WHERE id=1"); } catch { rejected=true; }
    Check(rejected, "Audit mutation was allowed");
});

Test("Database execution mode cannot be reused", () =>
{
    using var store = new Store(":memory:");
    store.BindExecutionMode("WINDOWS"); store.BindExecutionMode("WINDOWS");
    var rejected=false; try { store.BindExecutionMode("SETUP"); } catch (InvalidOperationException) { rejected=true; }
    Check(rejected, "Database accepted another execution mode");
});

Test("Policy hash is stable for the same object", () =>
{
    var value = new { control="1.1.1", desired=24 };
    Check(PolicyValues.Hash(value) == PolicyValues.Hash(value), "Hash is not deterministic");
    Check(DateTimeOffset.TryParse(PolicyValues.Now(), out _), "Timestamp is not ISO parseable");
});

Test("Endpoint refresh selection is bounded and explicit", () =>
{
    var m=ProductionGpoMappings.Settings.First(x=>x.Writable&&!x.RequiresInput);
    var s=new GpoSelection(Guid.NewGuid().ToString(),"DC=example,DC=com",m.Id,m.Suggested??0);
    ProductionGpoMappings.Validate(s);
    Reject("REFRESH_TARGET_REQUIRED",()=>ProductionGpoMappings.Validate(s with{RunGpUpdate=true}));
    Reject("ENDPOINT_SELECTION_REQUIRED",()=>ProductionGpoMappings.Validate(s with{Refresh="Selected"}));
    Reject("ENDPOINT_SELECTION_REQUIRED",()=>ProductionGpoMappings.Validate(s with{Refresh="Selected",EndpointHosts=Enumerable.Repeat("pc.example.com",101).ToArray()}));
    foreach(var invalid in new[]{"pc","pc.example.com'","pc..example.com","-pc.example.com","pc.example.com\n"})
        Reject("ENDPOINT_NAME_INVALID",()=>ProductionGpoMappings.Validate(s with{Refresh="Selected",EndpointHosts=[invalid]}));
    ProductionGpoMappings.Validate(s with{Refresh="Selected",RunGpUpdate=true,EndpointHosts=["pc.example.com"]});
    var legacy=JsonSerializer.Deserialize<GpoSelection>("{\"GpoId\":\"x\",\"ScopeDn\":\"x\",\"Setting\":\"x\",\"Value\":0}")!;
    Check(!legacy.RunGpUpdate&&legacy.EndpointHosts is null,"Legacy plans enabled refresh");
});

Console.WriteLine($"{passed} passed, {failed} failed");
Environment.ExitCode = failed == 0 ? 0 : 1;
