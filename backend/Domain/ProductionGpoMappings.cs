using System.Reflection;
using System.Text.Json;

namespace GpoRemediator.Domain;

public sealed record GpoMappingItem(
    string? Section = null,
    string? Key = null,
    string? Name = null,
    string Type = "String",
    string[]? Value = null,
    string? Guid = null,
    string? State = null,
    int? Mask = null);

public sealed record GpoRuleMapping(
    string Id,
    string ControlId,
    string Title,
    string Category,
    string Level,
    string Automation,
    string Handler,
    GpoMappingItem[] Items,
    string Recommended,
    string Scope,
    bool RequiresInput,
    string? InputType,
    string? InputLabel,
    string? InputDefault,
    bool AllowValueOverride,
    int? Minimum,
    int? Maximum,
    int? Suggested,
    string? Unit,
    string? Comparator,
    bool DomainPolicySensitive,
    bool RequiresGpUpdate,
    bool RequiresRestart,
    string[] Warnings,
    string Source)
{
    public bool Writable => string.Equals(Automation, "Automated", StringComparison.OrdinalIgnoreCase) && !string.Equals(Handler, "Manual", StringComparison.OrdinalIgnoreCase);

    public string DesiredDisplay(GpoSelection selection)
    {
        if (RequiresInput) return selection.CustomValue?.Trim() ?? "";
        if (AllowValueOverride) return selection.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (Handler == "AdvancedAudit")
        {
            if (Items.Length == 1) return Items[0].State ?? Items[0].Mask?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "<not configured>";
            return string.Join("; ", Items.Select(x => $"{x.Name ?? x.Guid}={x.State ?? x.Mask?.ToString(System.Globalization.CultureInfo.InvariantCulture)}"));
        }
        if (Items.Length == 1)
        {
            var values = Items[0].Value ?? [];
            return values.Length switch { 0 => "<blank>", 1 => values[0], _ => string.Join(", ", values) };
        }
        return string.Join("; ", Items.Select(x => $"{x.Name ?? x.Key ?? x.Guid}={string.Join(",", x.Value ?? [])}"));
    }
}

public sealed record GpoMappingCatalogMeta(string SchemaVersion, string Benchmark, string GeneratedFrom,
    int Mapped, int ManualOrBlocked, int TotalUnique, string Notes);
public sealed record GpoMappingCatalog(GpoMappingCatalogMeta Meta, GpoRuleMapping[] Mappings);

public static class ProductionGpoMappings
{
    private static readonly Lazy<GpoMappingCatalog> CatalogLazy = new(Load, true);
    public static GpoMappingCatalog Catalog => CatalogLazy.Value;
    public static GpoRuleMapping[] Settings => Catalog.Mappings;

    public static GpoRuleMapping Require(string id) => Settings.SingleOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase))
        ?? throw new PolicyException("GPO_SETTING_UNSUPPORTED", "This CIS control does not have a validated production mapping.");

    public static void Validate(GpoSelection selection)
    {
        var mapping = Require(selection.Setting);
        if (!mapping.Writable)
            throw new PolicyException("GPO_MANUAL_ONLY", "This CIS control is not classified as Automated in the imported CIS v4.0.0 catalog. It remains read-only and requires manual review.");
        if (!Guid.TryParse(selection.GpoId, out _)) throw new PolicyException("GPO_SELECTION_REQUIRED", "Select a GPO from the discovered list.");
        if (selection.Refresh is not ("None" or "Pdc" or "Scope")) throw new PolicyException("GPO_OPTIONS_INVALID", "Invalid policy refresh option.");
        if (selection.AccountScope is not ("Domain" or "LocalComputers")) throw new PolicyException("GPO_OPTIONS_INVALID", "Invalid target scope option.");
        if (string.IsNullOrWhiteSpace(selection.ScopeDn) || selection.ScopeDn.Length > 2048 || selection.ScopeDn.IndexOfAny(['\r','\n','\0']) >= 0)
            throw new PolicyException("GPO_SCOPE_REQUIRED", "Select a discovered domain or OU.");

        if (mapping.AllowValueOverride)
        {
            if (mapping.Minimum is int min && selection.Value < min || mapping.Maximum is int max && selection.Value > max)
                throw new PolicyException("GPO_VALUE_INVALID", $"{mapping.Title}: supported range {mapping.Minimum}–{mapping.Maximum} {mapping.Unit}.");
        }
        if (mapping.RequiresInput)
        {
            var value = selection.CustomValue ?? "";
            if (string.IsNullOrWhiteSpace(value)) throw new PolicyException("GPO_CUSTOM_VALUE_REQUIRED", mapping.InputLabel ?? "A value is required for this control.");
            if (value.Length > 4096 || value.IndexOf('\0') >= 0) throw new PolicyException("GPO_CUSTOM_VALUE_INVALID", "The supplied value is too long or contains an invalid character.");
            if (mapping.ControlId is "2.3.1.4" or "2.3.1.5")
            {
                if (value.Length > 256 || value.IndexOfAny(['\r','\n','\\','/','[',']',':',';','|','=','+','*','?','<','>','"',',']) >= 0)
                    throw new PolicyException("ACCOUNT_NAME_INVALID", "Use a valid Windows account name without path, delimiter, or control characters.");
            }
        }
        else if (!string.IsNullOrEmpty(selection.CustomValue))
            throw new PolicyException("GPO_CUSTOM_VALUE_NOT_ALLOWED", "This control uses a fixed benchmark mapping and does not accept a custom value.");
    }

    private static GpoMappingCatalog Load()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = assembly.GetManifestResourceNames().SingleOrDefault(x => x.EndsWith("gpo-production-mappings.json", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Production GPO mapping registry is not embedded in the application.");
        using var stream = assembly.GetManifestResourceStream(name) ?? throw new InvalidOperationException("Production GPO mapping registry cannot be read.");
        var catalog = JsonSerializer.Deserialize<GpoMappingCatalog>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Production GPO mapping registry is invalid.");
        ValidateCatalog(catalog);
        return catalog;
    }

    private static void ValidateCatalog(GpoMappingCatalog catalog)
    {
        if (catalog.Meta.Benchmark != "CIS Benchmark v4.0.0" || catalog.Meta.TotalUnique != 405 || catalog.Mappings.Length != 405)
            throw new InvalidOperationException("Production GPO mapping registry benchmark/count contract is invalid.");
        if (catalog.Mappings.Select(x => x.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 405)
            throw new InvalidOperationException("Production GPO mapping registry contains duplicate control IDs.");
        var allowedHandlers = new HashSet<string>(StringComparer.Ordinal) { "SecurityTemplate", "Registry", "RegistrySet", "AdvancedAudit" };
        if (catalog.Mappings.Any(x => !allowedHandlers.Contains(x.Handler) || x.Items.Length == 0))
            throw new InvalidOperationException("Production GPO mapping registry contains an unsupported or empty handler mapping.");
        var writable = catalog.Mappings.Count(x => x.Writable);
        if (writable != 401 || catalog.Meta.Mapped != 401 || catalog.Meta.ManualOrBlocked != 4)
            throw new InvalidOperationException("Production GPO mapping registry writable/read-only counts are invalid.");
        var blocked = catalog.Mappings.Where(x => !x.Writable).Select(x => x.Id).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        var expectedBlocked = new[] { "1.2.3", "18.10.43.10.1", "18.10.43.10.2", "2.3.11.6" }.OrderBy(x => x, StringComparer.Ordinal).ToArray();
        if (!blocked.SequenceEqual(expectedBlocked, StringComparer.Ordinal))
            throw new InvalidOperationException("Production GPO mapping registry manual/read-only control set changed unexpectedly.");
        if (catalog.Mappings.Any(x => x.DomainPolicySensitive && (x.Scope != "Domain" || !(x.ControlId.StartsWith("1.1.") || x.ControlId.StartsWith("1.2.")))))
            throw new InvalidOperationException("Production GPO mapping registry contains an invalid domain-policy-sensitive control.");
        foreach (var mapping in catalog.Mappings)
        {
            foreach (var item in mapping.Items)
            {
                if (mapping.Handler is "Registry" or "RegistrySet")
                {
                    if (string.IsNullOrWhiteSpace(item.Key) || string.IsNullOrWhiteSpace(item.Name))
                        throw new InvalidOperationException($"Registry mapping {mapping.Id} is missing key/value name.");
                    var expectedRoot = mapping.Scope == "User" ? "HKCU\\" : "HKLM\\";
                    if (!item.Key.StartsWith(expectedRoot, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException($"Registry mapping {mapping.Id} uses a scope-incompatible registry hive.");
                }
                else if (mapping.Handler == "SecurityTemplate" && (string.IsNullOrWhiteSpace(item.Section) || string.IsNullOrWhiteSpace(item.Key)))
                    throw new InvalidOperationException($"Security-template mapping {mapping.Id} is incomplete.");
                else if (mapping.Handler == "AdvancedAudit" && (!Guid.TryParse(item.Guid, out _) || item.Mask is < 1 or > 3))
                    throw new InvalidOperationException($"Advanced-audit mapping {mapping.Id} is invalid.");
            }
        }
    }
}
