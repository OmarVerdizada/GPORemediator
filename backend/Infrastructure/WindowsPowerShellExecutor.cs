using System.Diagnostics;
using System.Text;
using System.Text.Json;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// Fixed bundled scripts only. Optional GPO credentials travel over redirected stdin, never argv or logs.
internal sealed class WindowsPowerShellExecutor(ILogger logger)
{
    public async Task<T> RunAsync<T>(string operation, object configuration, object payload, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PolicyException("WINDOWS_REQUIRED", "Real execution requires a domain-connected Windows management host.");
        var gpo = new[] {"gpoInventory","gpoReadiness","gpoPreview","gpoApply","gpoRollback","gpoVerify"}.Contains(operation);
        if (!gpo) throw new PolicyException("OPERATION_DENIED", "Only the production GPO workflow is exposed by the Windows executor.");
        var script = Path.Combine(AppContext.BaseDirectory, "PowerShell", "Invoke-GpoWorkflow.ps1");
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
        var operationTimeout = operation switch
        {
            "gpoApply" or "gpoRollback" => TimeSpan.FromMinutes(16),
            "gpoPreview" or "gpoVerify" => TimeSpan.FromMinutes(10),
            _ when gpo => TimeSpan.FromMinutes(6),
            _ => TimeSpan.FromMinutes(4)
        };
        timeout.CancelAfter(operationTimeout);
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
            throw new PolicyException("WINDOWS_TIMEOUT", $"Windows operation exceeded its {operationTimeout.TotalMinutes:0}-minute safety timeout. A remote operation may have partially completed; inspect the recorded state before retrying a write.");
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
