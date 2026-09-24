namespace GpoRemediator.Domain;

public record PasswordSetting(string Id, string Title, int Minimum, int Maximum, int Suggested, string Unit);
public record PasswordPlanRequest(string User, string Setting, int Value);
public record PasswordConfirmRequest(string Confirmation);
public record PilotDiscovery(string Domain, string DomainController, string Urls, string Operator, string BackupPath, string[] Warnings);
public record PasswordSnapshot(string UserId, string User, string DistinguishedName, string? SourceId, int Precedence,
    Dictionary<string, int> Values, string[] Warnings);
public record PasswordPlan(string Id, string Operator, string Mode, string Domain, string DomainController,
    string Setting, int Value, PasswordSnapshot Before, Dictionary<string, int> After, string Fingerprint, string CreatedAt);
public record PasswordExecution(string Id, PasswordPlan Plan, string State, string? PolicyId, string Message, string UpdatedAt);
public record PasswordResult(string PolicyId, bool Verified, string Message);

public static class PasswordPilotRules
{
    // Operator-editable starting values, not a claim about a licensed benchmark or SecHard's configured thresholds.
    public static readonly PasswordSetting[] Settings = [
        new("PasswordHistoryCount", "Enforce password history", 0, 1024, 24, "passwords"),
        new("MaxPasswordAge", "Maximum password age", 0, 999, 60, "days (0 = never expires)"),
        new("MinPasswordAge", "Minimum password age", 0, 998, 1, "days"),
        new("MinPasswordLength", "Minimum password length", 0, 255, 14, "characters"),
        new("ComplexityEnabled", "Password must meet complexity requirements", 0, 1, 1, "0 = disabled, 1 = enabled"),
        new("ReversibleEncryptionEnabled", "Store passwords using reversible encryption", 0, 1, 0, "0 = disabled, 1 = enabled")
    ];
    public static void Validate(string setting, int value)
    {
        var rule = Settings.SingleOrDefault(s => s.Id == setting)
            ?? throw new PolicyException("PASSWORD_SETTING_UNSUPPORTED", "Choose one of the six password settings in the pilot.");
        if (value < rule.Minimum || value > rule.Maximum)
            throw new PolicyException("PASSWORD_VALUE_INVALID", $"{rule.Title}: enter {rule.Minimum}–{rule.Maximum}.");
    }
    public static void ValidateAges(IReadOnlyDictionary<string, int> values)
    {
        if (values["MaxPasswordAge"] != 0 && values["MinPasswordAge"] >= values["MaxPasswordAge"])
            throw new PolicyException("PASSWORD_AGE_CONFLICT", "Minimum age must be less than maximum age unless maximum is 0 (never expires). Select a compatible value.");
    }
    public static string Fingerprint(PasswordSnapshot snapshot) => PolicyValues.Hash(new {
        snapshot.UserId, snapshot.DistinguishedName, snapshot.SourceId, snapshot.Precedence,
        values = snapshot.Values.OrderBy(x => x.Key, StringComparer.Ordinal).ToArray()
    });
}
