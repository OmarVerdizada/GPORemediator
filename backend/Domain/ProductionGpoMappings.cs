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
    int? Mask = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? Comparator = null);

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

    public static GpoRuleMapping Effective(GpoSelection selection)
    {
        var mapping=Require(selection.Setting);
        if(!mapping.Writable && !string.IsNullOrWhiteSpace(selection.ReviewContext))
        {
            if(selection.ReviewContext.Trim().Length<10||selection.ReviewContext.Length>2048||selection.ReviewContext.Contains('\0'))
                throw new PolicyException("CONTROL_REVIEW_REQUIRED","Record the reviewed OS support, server roles and approved principal exceptions (10–2048 characters).");
            if(selection.ItemValues is null)
                throw new PolicyException("CONTROL_REVIEW_REQUIRED","Explicitly approve every policy field for this reviewed control.");
            mapping=mapping with{Automation="Automated",Handler=mapping.Handler=="Manual"?"SecurityTemplate":mapping.Handler,
                Source=mapping.Source+" | explicit environment review",
                Warnings=[..mapping.Warnings.Where(w=>!w.Contains("automatic writes remain blocked",StringComparison.OrdinalIgnoreCase)&&!w.Contains("Auto-write is disabled",StringComparison.OrdinalIgnoreCase)),
                    "ENVIRONMENT_REVIEW: "+selection.ReviewContext.Trim(),"Reviewed execution uses explicit operator values. OS/role compatibility and runtime enforcement still require endpoint evidence; do not disable Defender tamper protection."]};
        }
        // Account policies linked below the domain configure member computers'
        // local accounts. They never change passwords/lockout for domain users.
        if(mapping.DomainPolicySensitive && selection.AccountScope=="LocalComputers")
            mapping=mapping with{Scope="Computer",DomainPolicySensitive=false,
                Warnings=[..mapping.Warnings.Where(w=>!w.StartsWith("Domain user password/lockout policy must use",StringComparison.Ordinal)),"LOCAL_ACCOUNTS_ONLY: This OU policy affects local accounts on member computers. Domain users require domain-root policy or fine-grained password policies for users/global groups."]};
        if(selection.ItemValues is null)return mapping;
        if(!mapping.Writable)throw new PolicyException("GPO_MANUAL_ONLY","This control requires manual review.");
        if(mapping.RequiresInput||selection.ItemValues.Length!=mapping.Items.Length)
            throw new PolicyException("GPO_CUSTOM_VALUES_INVALID","Supply one value list per policy field; organization inputs use CustomValue.");
        var items=mapping.Items.Select((item,index)=>{
            var values=selection.ItemValues[index];
            if(values is null||values.Length>256||values.Any(v=>v is null||v.Length>4096||v.Contains('\0'))||values.Sum(v=>v.Length)>65536)
                throw new PolicyException("GPO_CUSTOM_VALUES_INVALID","A policy value list is invalid or too large.");
            var type=item.Type.ToUpperInvariant();
            if(type is not ("MULTISTRING" or "PRINCIPALS")&&values.Length!=1)
                throw new PolicyException("GPO_CUSTOM_VALUES_INVALID","This policy field requires exactly one value.");
            if(mapping.Handler=="AdvancedAudit"){
                if(!int.TryParse(values[0],out var mask)||mask<0||mask>3)throw new PolicyException("GPO_VALUE_INVALID","Audit mask must be 0, 1, 2 or 3.");
                return item with{Mask=mask,State=new[]{"No Auditing","Success","Failure","Success and Failure"}[mask],Comparator="=="};
            }
            if(type=="DWORD"){
                if(!uint.TryParse(values[0],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var number))throw new PolicyException("GPO_VALUE_INVALID","DWORD requires an unsigned 32-bit integer.");
                values=[number.ToString(System.Globalization.CultureInfo.InvariantCulture)];
            }else if(type=="INTEGER"){
                if(!int.TryParse(values[0],out var number)||number<0||number>65535)throw new PolicyException("GPO_VALUE_INVALID","Security policy requires an integer from 0 to 65535.");
                values=[number.ToString(System.Globalization.CultureInfo.InvariantCulture)];
            }else if(type=="PRINCIPALS"){
                if(values.Any(v=>string.IsNullOrWhiteSpace(v)||v.Length>256||v.IndexOfAny(['\r','\n'])>=0))throw new PolicyException("GPO_CUSTOM_VALUES_INVALID","Enter one account/group or SID per line.");
                values=values.Select(v=>v.Trim()).ToArray();
            }
            return item with{Value=values,Comparator=type is "DWORD" or "INTEGER"?"==":"exact"};
        }).ToArray();
        return mapping with{Items=items,AllowValueOverride=false,RequiresInput=false,Comparator=null,
            Source=mapping.Source+" | operator-selected values",
            Warnings=[..mapping.Warnings,"CUSTOM_VALUES: These are operator-selected values, not a CIS benchmark compliance assertion."]};
    }

    public static void ValidateTarget(GpoRuleMapping mapping,GpoScope scope,GpoSelection selection)
    {
        if(mapping.DomainPolicySensitive && scope.Kind!="Domain")
            throw new PolicyException("PASSWORD_SCOPE_MISMATCH","Domain account policy requires the domain root. For a computer OU choose local computer accounts; for selected AD users use fine-grained password policy.");
        if(!mapping.DomainPolicySensitive && scope.Kind is not ("OU" or "Domain"))
            throw new PolicyException("GPO_SCOPE_REQUIRED","Select a discovered OU or domain.");
        if(Require(selection.Setting).DomainPolicySensitive && selection.AccountScope=="LocalComputers" && scope.Kind!="OU")
            throw new PolicyException("LOCAL_ACCOUNT_OU_REQUIRED","Choose a computer OU for local account policy.");
    }

    public static void Validate(GpoSelection selection)
    {
        var mapping = Effective(selection);
        if (!mapping.Writable)
            throw new PolicyException("GPO_MANUAL_ONLY", "This CIS control is not classified as Automated in the imported CIS v4.0.0 catalog. It remains read-only and requires manual review.");
        if (!Guid.TryParse(selection.GpoId, out _)) throw new PolicyException("GPO_SELECTION_REQUIRED", "Select a GPO from the discovered list.");
        if (selection.Refresh is not ("None" or "Pdc" or "Scope")) throw new PolicyException("GPO_OPTIONS_INVALID", "Invalid policy refresh option.");
        if (selection.AccountScope is not ("Domain" or "LocalComputers" or "Users")) throw new PolicyException("GPO_OPTIONS_INVALID", "Invalid target scope option.");
        if (string.IsNullOrWhiteSpace(selection.ScopeDn) || selection.ScopeDn.Length > 2048 || selection.ScopeDn.IndexOfAny(['\r','\n','\0']) >= 0)
            throw new PolicyException("GPO_SCOPE_REQUIRED", "Select a discovered domain or OU.");
        if (!string.IsNullOrWhiteSpace(selection.EndpointScopeDn) && (selection.EndpointScopeDn.Length > 2048 || selection.EndpointScopeDn.IndexOfAny(['\r','\n','\0']) >= 0))
            throw new PolicyException("ENDPOINT_SCOPE_INVALID", "Select a discovered endpoint OU.");
        if (!string.IsNullOrWhiteSpace(selection.VerificationUser) && (selection.VerificationUser.Length > 256 || selection.VerificationUser.IndexOfAny(['\r','\n','\0']) >= 0))
            throw new PolicyException("VERIFICATION_USER_INVALID", "Enter a valid DOMAIN\\user or user@domain identity.");
        if (mapping.Scope == "User")
        {
            if (selection.AccountScope != "Users") throw new PolicyException("GPO_SCOPE_TYPE_MISMATCH", "This control requires a user policy scope.");
            if (selection.Refresh == "Pdc") throw new PolicyException("USER_REFRESH_TARGET_INVALID", "User policy cannot be refreshed on the PDC unless the user has a session there. Choose an endpoint OU or wait for the normal user policy cycle.");
            if (selection.Refresh == "Scope" && string.IsNullOrWhiteSpace(selection.EndpointScopeDn))
                throw new PolicyException("ENDPOINT_SCOPE_REQUIRED", "Choose the computer OU that contains the user session endpoints.");
        }
        else
        {
            if (mapping.DomainPolicySensitive && selection.AccountScope != "Domain") throw new PolicyException("GPO_SCOPE_TYPE_MISMATCH", "This control requires the domain account-policy scope.");
            if (mapping.DomainPolicySensitive && !selection.FirstLink) throw new PolicyException("DOMAIN_POLICY_PRIORITY_REQUIRED", "A domain password/lockout GPO must be enabled at link order 1 on the domain root so the requested policy is effective.");
            if (mapping.DomainPolicySensitive && selection.Refresh == "Scope") throw new PolicyException("DOMAIN_REFRESH_SCOPE_INVALID", "Domain account policy has no computer OU refresh scope. Refresh the PDC or wait for the normal policy cycle.");
            if (!mapping.DomainPolicySensitive && selection.AccountScope != "LocalComputers") throw new PolicyException("GPO_SCOPE_TYPE_MISMATCH", "This control requires a computer policy scope.");
            if (!mapping.DomainPolicySensitive && selection.Refresh == "Pdc") throw new PolicyException("PDC_REFRESH_SCOPE_INVALID", "This computer policy targets the selected computer OU, not the PDC. Use scope computers or the normal cycle.");
            if (!string.IsNullOrWhiteSpace(selection.EndpointScopeDn) || !string.IsNullOrWhiteSpace(selection.VerificationUser))
                throw new PolicyException("USER_TARGET_NOT_ALLOWED", "Endpoint OU and verification user are only valid for user-scoped policy.");
        }

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
        var allowedHandlers = new HashSet<string>(StringComparer.Ordinal) { "SecurityTemplate", "Registry", "RegistrySet", "AdvancedAudit", "Manual" };
        if (catalog.Mappings.Any(x => !allowedHandlers.Contains(x.Handler) || x.Items.Length == 0))
            throw new InvalidOperationException("Production GPO mapping registry contains an unsupported or empty handler mapping.");
        var writable = catalog.Mappings.Count(x => x.Writable);
        if (writable != 394 || catalog.Meta.Mapped != 394 || catalog.Meta.ManualOrBlocked != 11)
            throw new InvalidOperationException("Production GPO mapping registry writable/read-only counts are invalid.");
        var blocked = catalog.Mappings.Where(x => !x.Writable).Select(x => x.Id).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        var expectedBlocked = new[] { "1.2.3", "18.10.43.10.1", "18.10.43.10.2", "2.3.11.6", "2.2.6", "2.2.16", "2.2.31", "2.2.33", "2.2.36", "2.2.39", "2.2.45" }.OrderBy(x => x, StringComparer.Ordinal).ToArray();
        if (!blocked.SequenceEqual(expectedBlocked, StringComparer.Ordinal))
            throw new InvalidOperationException("Production GPO mapping registry manual/read-only control set changed unexpectedly.");
        if (catalog.Mappings.Any(x => x.DomainPolicySensitive && (x.Scope != "Domain" || !(x.ControlId.StartsWith("1.1.") || x.ControlId.StartsWith("1.2.")))))
            throw new InvalidOperationException("Production GPO mapping registry contains an invalid domain-policy-sensitive control.");
        if (catalog.Mappings.Count(x => x.Scope == "User") != 12 || catalog.Mappings.Count(x => x.Scope == "Domain") != 8 || catalog.Mappings.Count(x => x.Scope == "Computer") != 385)
            throw new InvalidOperationException("Production GPO mapping registry user/computer/domain scope counts changed unexpectedly.");
        if (catalog.Mappings.Any(x => x.Scope == "User" && x.Handler is not ("Registry" or "RegistrySet")))
            throw new InvalidOperationException("User-scoped controls must use a reviewed HKCU registry handler.");
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
