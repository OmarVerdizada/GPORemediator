using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// The dedicated share owns authentication for receipts. Deploy a request directory
// writable only by the publisher and a separate result directory for each machine.
internal sealed class EndpointRefreshQueue(string? root, string? certificateThumbprint, IReadOnlyDictionary<string,string>? receiptThumbprints = null)
{
    private sealed record Request(string Id, string Computer, string Action, string ExpiresAt, EndpointProbeTarget? Probe = null);
    private sealed record Envelope(string Payload, string Signature);
    private sealed record Receipt(string Id, string Computer, string State, long? DurationMs);
    private sealed record ProbeReceipt(string Id, string Computer, string State, DateTimeOffset ReadAt, string? Actual, string? Message);

    public bool Enabled => !string.IsNullOrWhiteSpace(root);
    public bool VerificationEnabled => Enabled && receiptThumbprints?.Count > 0;

    private string? ReceiptThumbprint(string computer) => receiptThumbprints?
        .FirstOrDefault(e=>e.Key.Equals(computer,StringComparison.OrdinalIgnoreCase)).Value;

    private string DirectoryFor(string computer, string purpose)
    {
        if (root is null || !Regex.IsMatch(root, @"^\\\\[a-zA-Z0-9.-]+\\[^\\]+(?:\\[^\\]+)*$") ||
            root.Split('\\').Any(x => x is "." or "..") ||
            !Regex.IsMatch(computer, @"\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\z"))
            throw new InvalidOperationException("Endpoint queue configuration is invalid.");
        return Path.Combine(root, computer.ToLowerInvariant(), purpose);
    }

    private void Publish(Request request, DateTimeOffset expires)
    {
        var requests = DirectoryFor(request.Computer, "requests");
        var results = DirectoryFor(request.Computer, "results");
        if (!Directory.Exists(requests) || !Directory.Exists(results))
            throw new InvalidOperationException("Endpoint queue folders are not enrolled.");
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var now = DateTime.UtcNow;
        using var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint ?? "", false)
            .OfType<X509Certificate2>().FirstOrDefault(c=>c.HasPrivateKey && c.NotBefore.ToUniversalTime() <= now
                && c.NotAfter.ToUniversalTime() >= expires.UtcDateTime);
        using var key = certificate?.GetRSAPrivateKey();
        if (key is null || key.KeySize < 2048) throw new CryptographicException("A valid RSA publisher key is unavailable.");
        var payload = Encoding.UTF8.GetBytes(JsonDefaults.Serialize(request));
        var signature = key.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var envelope = JsonDefaults.Serialize(new Envelope(Convert.ToBase64String(payload), Convert.ToBase64String(signature)));
        if (envelope.Length > 32768) throw new InvalidOperationException("Endpoint request is too large.");
        var path = Path.Combine(requests, request.Id + ".json");
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, envelope);
        File.Move(temporary, path);
    }

    public GpoRefreshResult Enqueue(GpoRefreshResult target)
    {
        try
        {
            var requests = DirectoryFor(target.Computer, "requests");
            var results = DirectoryFor(target.Computer, "results");
            if (!Directory.Exists(requests) || !Directory.Exists(results))
                return target with { State = "FAILED", Message = "Endpoint worker is not enrolled. No request was queued." };
            var now = DateTimeOffset.UtcNow;
            var id = Guid.NewGuid().ToString("N");
            var expires = now.AddDays(1);
            Publish(new Request(id,target.Computer.ToLowerInvariant(),"RefreshComputerPolicy",expires.ToString("O")),expires);
            return target with { State = "SCHEDULED", ScheduledAt = now.ToString("O"), WorkerRequestId = id, WorkerExpiresAt = expires,
                Message = "Queued for the endpoint worker. The request expires in 24 hours. Start time depends on the next endpoint check-in." };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException or InvalidOperationException)
        {
            return target with { State = "FAILED", Message = "Endpoint queue publication could not be confirmed. Inspect the configured share and signing key before retrying." };
        }
    }

    public GpoEndpointCheck Verify(GpoEndpointCheck target, GpoEndpointCheck? previous)
    {
        if (target.WorkerProbe is not { } probe) return target;
        target = target with { WorkerProbe = null };
        var pin = ReceiptThumbprint(target.Hostname);
        if (string.IsNullOrWhiteSpace(pin))
            return target with { State = "UNAVAILABLE", Message = "This endpoint has no pinned worker evidence certificate." };
        try
        {
            if (previous is { State: "PENDING", WorkerRequestId: { } savedId, WorkerExpiresAt: { } savedExpiry } &&
                Guid.TryParseExact(savedId,"N",out _))
            {
                var path = Path.Combine(DirectoryFor(target.Hostname,"results"),savedId+".json");
                if (File.Exists(path))
                {
                    var receipt = ReadProbeReceipt(path,pin);
                    if (receipt.Id != savedId || !string.Equals(receipt.Computer,target.Hostname,StringComparison.OrdinalIgnoreCase) ||
                        receipt.ReadAt > DateTimeOffset.UtcNow.AddMinutes(2) || receipt.ReadAt < savedExpiry.AddMinutes(-5).AddSeconds(-30) ||
                        receipt.ReadAt > savedExpiry.AddMinutes(2))
                        return target with { State = "UNAVAILABLE", Message = "The signed worker evidence did not match this request or its measurement window." };
                    if (receipt.State != "STARTED")
                    {
                        if (receipt.State is not ("VERIFIED" or "MISMATCH" or "OBSERVED" or "UNAVAILABLE" or "PENDING") ||
                            receipt.State is "VERIFIED" or "MISMATCH" && receipt.Actual is not { Length: > 0 and <= 4096 })
                            return target with { State = "UNAVAILABLE", Message = "The signed evidence had no usable endpoint measurement." };
                        return target with { State = receipt.State, WorkerReadAt = receipt.ReadAt,
                            ActualValue = receipt.Actual is { Length: <= 4096 } ? receipt.Actual : null,
                            Message = receipt.Message is { Length: > 0 and <= 2048 } ? receipt.Message : "The endpoint worker returned signed evidence." };
                    }
                }
                if (DateTimeOffset.UtcNow < savedExpiry)
                    return previous;
            }
            var id = Guid.NewGuid().ToString("N");
            var expires = DateTimeOffset.UtcNow.AddMinutes(5);
            Publish(new Request(id,target.Hostname.ToLowerInvariant(),"VerifyPolicySnapshot",expires.ToString("O"),probe),expires);
            return target with { State = "PENDING", WorkerRequestId = id, WorkerExpiresAt = expires,
                Message = "Read-only check queued. Re-verify reads the signed result when the worker responds." };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or CryptographicException or ArgumentException or InvalidOperationException or FormatException)
        {
            return target with { State = "UNAVAILABLE", Message = "The endpoint evidence queue or signature could not be validated." };
        }
    }

    private static ProbeReceipt ReadProbeReceipt(string path,string pin)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length is <= 0 or > 16384) throw new InvalidOperationException("Invalid evidence length.");
        var envelope = JsonSerializer.Deserialize<Envelope>(stream,JsonDefaults.Options) ?? throw new JsonException();
        var payload = Convert.FromBase64String(envelope.Payload);
        var signature = Convert.FromBase64String(envelope.Signature);
        using var store = new X509Store(StoreName.TrustedPeople,StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        using var certificate = store.Certificates.Find(X509FindType.FindByThumbprint,pin,false)
            .OfType<X509Certificate2>().FirstOrDefault();
        using var key = certificate?.GetRSAPublicKey();
        if (key is null || key.KeySize < 2048 || !key.VerifyData(payload,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1))
            throw new CryptographicException("Invalid endpoint evidence signature.");
        var receipt = JsonSerializer.Deserialize<ProbeReceipt>(payload,JsonDefaults.Options) ?? throw new JsonException();
        if (certificate is null || receipt.ReadAt.UtcDateTime < certificate.NotBefore.ToUniversalTime() ||
            receipt.ReadAt.UtcDateTime > certificate.NotAfter.ToUniversalTime())
            throw new CryptographicException("Worker certificate was invalid at measurement time.");
        return receipt;
    }

    public GpoRefreshResult Read(GpoRefreshResult result)
    {
        if (result.WorkerRequestId is not { } id || !Guid.TryParseExact(id, "N", out _) || result.State is "COMPLETED" or "FAILED") return result;
        if (!Enabled) return result with { Message = "Endpoint queue configuration is unavailable. Worker status could not be read." };
        try
        {
            var path = Path.Combine(DirectoryFor(result.Computer, "results"), id + ".json");
            if (File.Exists(path))
            {
                using var stream = File.OpenRead(path);
                if (stream.Length is > 0 and < 4096)
                {
                    var receipt = JsonSerializer.Deserialize<Receipt>(stream, JsonDefaults.Options);
                    if (receipt is not null && receipt.Id == id && string.Equals(receipt.Computer,result.Computer,StringComparison.OrdinalIgnoreCase))
                    {
                        if (receipt.State == "COMPLETED" && receipt.DurationMs is >= 0 and <= 180000)
                            return result with { State = "COMPLETED", ComputerRefreshDurationMs = receipt.DurationMs, Message = "The endpoint worker confirmed gpupdate completion. Re-verify the effective policy separately." };
                        if (receipt.State == "FAILED")
                            return result with { State = "FAILED", Message = "The endpoint worker reported a refresh failure or timeout." };
                        if (receipt.State == "STARTED" && result.WorkerExpiresAt?.AddMinutes(3) <= DateTimeOffset.UtcNow)
                            return result with { State = "FAILED", Message = "The worker accepted the request but did not report completion. Check the endpoint before retrying." };
                        if (receipt.State == "STARTED")
                            return result with { State = "STARTED", Message = "The worker accepted the request. Completion is pending." };
                    }
                }
                return result with { Message = "The endpoint receipt did not match the queued request." };
            }
            return result.WorkerExpiresAt <= DateTimeOffset.UtcNow
                ? result with { State = "FAILED", Message = "The request expired before the endpoint worker acknowledged it." }
                : result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or InvalidOperationException)
        {
            return result with { Message = "Endpoint worker status could not be read. The saved request is retained." };
        }
    }
}
