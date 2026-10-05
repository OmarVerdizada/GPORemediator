using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GpoRemediator.Domain;

public record GpoLink(string Target, int Order, bool Enforced, bool Enabled);
public record AuditEvent(long Id, string Event, string Operator, string? JobId, string? ControlId, string? GpoId,
    string Details, string CreatedAt, string PreviousHash, string Hash);
public record SetupConfigRequest(string Urls, string Domain, string DomainController, string[] ApprovedGpoIds,
    string[] AuthorizedOus, string[] AllowedHosts, string[] AllowedOperators, string BackupPath, bool AutoRestart = true,
    string[]? Remediators = null, string[]? Auditors = null, string[]? Viewers = null);
public record WriteModeRequest(bool Enable, string Confirmation, bool AutoRestart = true);
public record SetupConfigView(string Urls, string Domain, string DomainController, string[] ApprovedGpoIds,
    string[] AuthorizedOus, string[] AllowedHosts, string[] AllowedOperators, string BackupPath, bool EnableWrites,
    string ConfigPath, bool Exists, string[] Remediators, string[] Auditors, string[] Viewers);

public sealed class PolicyException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class PolicyValues
{
    public static string Now() => DateTimeOffset.UtcNow.ToString("O");

    public static string Hash<T>(T value)
    {
        var json = JsonDefaults.Serialize(value);
        var bytes = Encoding.UTF8.GetBytes(json);
        try
        {
            return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
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
