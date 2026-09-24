using System.Diagnostics;
using System.Text;
using System.Text.Json;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// No command text, credentials, or executable path can be supplied by the browser.
internal sealed class WindowsPowerShellExecutor(ILogger logger)
{
    private static readonly HashSet<string> Operations = ["environment", "resolveTarget", "preflight", "analyze", "inspect", "backup", "apply", "verifyGpo", "verifyScope", "refresh", "verifyRsop", "verifyEndpoint", "restart", "restore", "verifyRollback"];

    public async Task<T> RunAsync<T>(string operation, object configuration, object payload, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PolicyException("WINDOWS_REQUIRED", "Real execution requires a domain-connected Windows management host.");
        var pilot = new[] { "discover", "passwordRead", "passwordApply", "passwordRollback", "passwordReadiness" }.Contains(operation);
        if (!pilot && !Operations.Contains(operation)) throw new PolicyException("OPERATION_DENIED", "The requested Windows operation is not supported.");
        var script = Path.Combine(AppContext.BaseDirectory, "PowerShell", pilot ? "Invoke-PasswordPilot.ps1" : "Invoke-PolicyOperation.ps1");
        if (!File.Exists(script)) throw new PolicyException("SCRIPT_MISSING", "Publish the bundled PowerShell directory with the backend.");
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script }) start.ArgumentList.Add(argument);
        using var process = new Process { StartInfo = start };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(4));
        try
        {
            process.Start();
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.StandardInput.WriteAsync(JsonDefaults.Serialize(new { operation, configuration, payload }).AsMemory(), timeout.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
            var output = await stdout;
            _ = await stderr; // Never log raw command output: it may include domain information.
            if (output.Length > 8_000_000) throw new PolicyException("RESPONSE_TOO_LARGE", "Windows operation returned too much data; narrow the authorized scope.");
            JsonDocument document;
            try { document = JsonDocument.Parse(output); }
            catch (JsonException)
            {
                throw new PolicyException("POWERSHELL_TRANSPORT", "PowerShell returned no valid structured response. Check script execution policy/signing and management-host event logs.");
            }
            using (document)
            {
                var root = document.RootElement;
                if (!root.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
                    throw new PolicyException(root.TryGetProperty("code", out var code) ? code.GetString()! : "WINDOWS_OPERATION_FAILED",
                        root.TryGetProperty("message", out var message) ? message.GetString()! : "The Windows operation failed.");
                if (process.ExitCode != 0) throw new PolicyException("POWERSHELL_EXIT", "Windows operation exited abnormally; inspect management-host logs.");
                return root.GetProperty("data").Deserialize<T>(JsonDefaults.Options)
                       ?? throw new PolicyException("EMPTY_RESPONSE", "Windows operation returned an empty result.");
            }
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            if (ct.IsCancellationRequested) throw;
            throw new PolicyException("WINDOWS_TIMEOUT", "Windows operation exceeded four minutes. A remote operation may still finish; inspect current policy before retrying a write.");
        }
        catch (PolicyException ex)
        {
            logger.LogWarning("Windows operation {Operation} failed with {Code}", operation, ex.Code);
            throw;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
        {
            throw new PolicyException("POWERSHELL_START_FAILED", "Unable to start Windows PowerShell 5.1. Check installation and service-account execution rights.");
        }
    }
}
