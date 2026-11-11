namespace GpoRemediator.Domain;

public static class PolicyConflicts
{
    private static readonly (string Left,string Right,string Message)[] Relationships =
    [
        ("1.2.1", "1.2.4", "A finite lockout duration must be at least as long as the reset-counter window."),
        ("1.2.2", "1.2.1", "Threshold 0 disables lockout, regardless of the configured duration."),
        ("1.2.2", "1.2.4", "The reset-counter window has no lockout effect while the threshold is 0."),
        ("2.3.2.1", "17.*", "The security option controls whether advanced audit subcategories override legacy audit categories."),
        ("5.2", "18.7.*", "Disabling Print Spooler makes its runtime print settings inactive."),
        ("18.7.1", "18.7.5", "Blocking incoming spooler connections makes the listener protocol inactive."),
        ("18.7.1", "18.7.6", "Blocking incoming spooler connections makes the listener authentication setting inactive."),
        ("18.7.3", "18.7.4", "The outgoing print RPC protocol and authentication are options of the same printer policy."),
        ("18.7.5", "18.7.6", "The incoming print RPC protocol and authentication are options of the same printer policy."),
        ("18.7.9", "18.7.11", "Administrator-only print driver installation can take precedence over the Point and Print install prompt."),
        ("18.7.9", "18.7.12", "Administrator-only print driver installation can take precedence over the Point and Print update prompt."),
        ("18.7.11", "18.7.12", "Both Point and Print controls share the Restricted enable value. Keep that field consistent across both prompt settings."),
        ("18.10.93.2.1", "18.10.93.2.2", "The scheduled install day requires the automatic update mode that uses an install schedule.")
    ];

    public static GpoConflictInfo[] Related(string control, string domain, string scope) => Relationships
        .Select(pair => Matches(control,pair.Left) ? (pair.Right,pair.Message) : Matches(control,pair.Right) ? (pair.Left,pair.Message) : default)
        .Where(pair => pair.Item1 is not null)
        .Select(pair => new GpoConflictInfo("Warning","RELATED_CONTROL",pair.Message!,Scope:scope,Domain:domain,RelatedControl:pair.Item1))
        .ToArray();

    private static bool Matches(string id,string pattern) => pattern.EndsWith('*')
        ? id.StartsWith(pattern[..^1],StringComparison.Ordinal)
        : id==pattern;
}
