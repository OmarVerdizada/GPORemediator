using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// The dedicated share owns authentication for receipts. Deploy a request directory
// writable only by the publisher and a separate result directory for each machine.
internal sealed class EndpointRefreshQueue(string? root, string? certificateThumbprint)
{
    private sealed record Request(string Id, string Computer, string Action, string ExpiresAt);
    private sealed record Envelope(string Payload, string Signature);
    private sealed record Receipt(string Id, string Computer, string State, long? DurationMs);

    public bool Enabled => !string.IsNullOrWhiteSpace(root);

    private string DirectoryFor(string computer, string purpose)
    {
        if (root is null || !Regex.IsMatch(root, @"^\\\\[a-zA-Z0-9.-]+\\[^\\]+(?:\\[^\\]+)*$") ||
            root.Split('\\').Any(x => x is "." or "..") ||
            !Regex.IsMatch(computer, @"\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\z"))
            throw new InvalidOperationException("Endpoint queue configuration is invalid.");
        return Path.Combine(root, computer.ToLowerInvariant(), purpose);
    }

    public GpoRefreshResult Enqueue(GpoRefreshResult target)
    {
        try
        {
            var requests = DirectoryFor(target.Computer, "requests");
            var results = DirectoryFor(target.Computer, "results");
            if (!Directory.Exists(requests) || !Directory.Exists(results))
                return target with { State = "FAILED", Message = "Endpoint worker is not enrolled. No request was queued." };
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var now = DateTimeOffset.UtcNow;
            using var key = store.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint ?? "", false)
                .OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey && c.NotBefore.ToUniversalTime() <= now.UtcDateTime
                    && c.NotAfter.ToUniversalTime() >= now.AddDays(1).UtcDateTime)
                ?.GetRSAPrivateKey();
            if (key is null || key.KeySize < 2048)
                return target with { State = "FAILED", Message = "A valid RSA endpoint-queue signing key is unavailable." };
            var id = Guid.NewGuid().ToString("N");
            var expires = now.AddDays(1);
            var payload = Encoding.UTF8.GetBytes(JsonDefaults.Serialize(new Request(id, target.Computer.ToLowerInvariant(), "RefreshComputerPolicy", expires.ToString("O"))));
            var signature = key.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var path = Path.Combine(requests, id + ".json");
            var temporary = path + ".tmp";
            File.WriteAllText(temporary, JsonDefaults.Serialize(new Envelope(Convert.ToBase64String(payload), Convert.ToBase64String(signature))));
            File.Move(temporary, path);
            return target with { State = "SCHEDULED", ScheduledAt = now.ToString("O"), WorkerRequestId = id, WorkerExpiresAt = expires,
                Message = "Queued for the endpoint worker. The request expires in 24 hours. Start time depends on the next endpoint check-in." };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException or InvalidOperationException)
        {
            return target with { State = "FAILED", Message = "Endpoint queue publication could not be confirmed. Inspect the configured share and signing key before retrying." };
        }
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
