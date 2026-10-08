using System.Diagnostics;
using System.Text;
using System.Text.Json;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// Fixed bundled scripts only. Optional GPO credentials travel over redirected stdin, never argv or logs.
public sealed class WindowsPowerShellExecutor(ILogger<WindowsPowerShellExecutor> logger)
{
    public async Task<T> RunAsync<T>(string operation, object configuration, object payload, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PolicyException("WINDOWS_REQUIRED", "Real execution requires a domain-connected Windows management host.");
        var gpo = new[] {"gpoInventory","gpoReadiness","gpoPreview","gpoApply","gpoRollback","gpoVerify","gpoRefresh"}.Contains(operation);
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
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", script }) start.ArgumentList.Add(argument);
        using var process = new Process { StartInfo = start };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var operationTimeout = operation switch
        {
            "gpoApply" or "gpoRollback" => TimeSpan.FromMinutes(16),
            "gpoPreview" or "gpoVerify" => TimeSpan.FromMinutes(10),
            "gpoRefresh" => TimeSpan.FromMinutes(12),
            "gpoInventory" or "gpoReadiness" => TimeSpan.FromSeconds(90),
            _ when gpo => TimeSpan.FromMinutes(6),
            _ => TimeSpan.FromMinutes(4)
        };
        timeout.CancelAfter(operationTimeout);
        var clock=Stopwatch.StartNew();
        var started=false;
        try
        {
            process.Start();
            started=true;
            var stdout = ReadOutputAsync(process.StandardOutput,8_000_000,timeout.Token);
            var stderr = DrainAsync(process.StandardError,timeout.Token);
            await process.StandardInput.WriteAsync(JsonDefaults.Serialize(new { operation, configuration, payload }).AsMemory(), timeout.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
            var output = await stdout;
            await stderr; // Never log raw command output: it may include domain information.
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
                var result=root.GetProperty("data").Deserialize<T>(JsonDefaults.Options)
                       ?? throw new PolicyException("EMPTY_RESPONSE", "Windows operation returned an empty result.");
                logger.LogInformation("Windows operation {Operation} completed in {ElapsedMs} ms",operation,clock.ElapsedMilliseconds);
                return result;
            }
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            if (ct.IsCancellationRequested) throw;
            throw new PolicyException("WINDOWS_TIMEOUT", $"Windows operation exceeded its {operationTimeout.TotalSeconds:0}-second safety timeout. Check DC reachability and Kerberos/WinRM. A remote operation may have partially completed; inspect the recorded state before retrying a write.");
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
        finally
        {
            if(started&&!process.HasExited) { try { process.Kill(entireProcessTree:true); } catch(InvalidOperationException) { } }
        }
    }
    private static async Task<string> ReadOutputAsync(StreamReader reader,int limit,CancellationToken ct)
    {
        var output=new StringBuilder();var buffer=new char[4096];bool exceeded=false;int read;
        while((read=await reader.ReadAsync(buffer.AsMemory(),ct))>0)
        {
            if(output.Length+read<=limit&&!exceeded)output.Append(buffer,0,read);
            else exceeded=true; // Continue draining to avoid blocking the child on a full pipe.
        }
        if(exceeded)throw new PolicyException("RESPONSE_TOO_LARGE","Windows operation returned too much data; narrow the authorized scope.");
        return output.ToString();
    }
    private static async Task DrainAsync(StreamReader reader,CancellationToken ct)
    {
        var buffer=new char[4096];while(await reader.ReadAsync(buffer.AsMemory(),ct)>0) { }
    }
}
