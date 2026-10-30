using System.Diagnostics;
using System.Text;
using System.Text.Json;
using GpoRemediator.Domain;

namespace GpoRemediator.Infrastructure;

// Fixed bundled scripts only. Optional GPO credentials travel over redirected stdin, never argv or logs.
public sealed class WindowsPowerShellExecutor(ILogger<WindowsPowerShellExecutor> logger)
{
    public async Task<T> RunAsync<T>(string operation, object configuration, object payload, CancellationToken ct,Action<string>? progress=null,Action<GpoLiveCheck>? checkProgress=null)
    {
        if (!OperatingSystem.IsWindows()) throw new PolicyException("WINDOWS_REQUIRED", "Real execution requires a domain-connected Windows management host.");
        var gpo = new[] {"gpoExplain","gpoInventory","gpoReadiness","gpoPreview","gpoApply","gpoRollback","gpoRollbackInspect","gpoVerify","gpoRefresh"}.Contains(operation);
        if (!gpo) throw new PolicyException("OPERATION_DENIED", "Only the production GPO workflow is exposed by the Windows executor.");
        var trustedScript = Path.Combine(AppContext.BaseDirectory, "PowerShell", "Invoke-GpoWorkflow.ps1");
        BundledAssets.VerifyScripts(Path.GetDirectoryName(trustedScript)!);
        if (!File.Exists(trustedScript)) throw new PolicyException("SCRIPT_MISSING", "Publish the bundled PowerShell directory with the backend.");
        // Per-GPO, per-domain launchers are isolated and verified against the compiled product.
        // Inventory/readiness still use the common read-only bootstrap (no selected GPO yet).
        var script = GpoScriptWorkspaces.SelectScript(operation, configuration, payload, trustedScript);
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
            "gpoExplain" or "gpoPreview" or "gpoRollbackInspect" or "gpoVerify" => TimeSpan.FromMinutes(10),
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
            string? lastStage=null;
            var stdout = ReadOutputAsync(process.StandardOutput,8_000_000,timeout.Token,phase=>{lastStage=phase;progress?.Invoke(phase);},checkProgress);
            var stderr = ReadErrorSummaryAsync(process.StandardError,timeout.Token);
            await process.StandardInput.WriteAsync(JsonDefaults.Serialize(new { operation, configuration, payload }).AsMemory(), timeout.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
            var output = await stdout;
            var errorHint=await stderr; // Classifications only; never persist or expose raw stderr.
            JsonDocument document;
            try { document = JsonDocument.Parse(output); }
            catch (JsonException)
            {
                throw TransportError(process.ExitCode,lastStage,output.Length,errorHint);
            }
            using (document)
            {
                var root = document.RootElement;
                if(root.ValueKind!=JsonValueKind.Object||!root.TryGetProperty("ok",out var ok)||ok.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    throw new PolicyException("POWERSHELL_PROTOCOL","PowerShell returned an invalid response envelope. No successful result was accepted.");
                if (!ok.GetBoolean())
                    throw new PolicyException(root.TryGetProperty("code", out var code) ? code.GetString()! : "WINDOWS_OPERATION_FAILED",
                        root.TryGetProperty("message", out var message) ? message.GetString()! : "The Windows operation failed.");
                if (process.ExitCode != 0) throw new PolicyException("POWERSHELL_EXIT", "Windows operation exited abnormally; inspect management-host logs.");
                if(!root.TryGetProperty("data",out var data))throw new PolicyException("POWERSHELL_PROTOCOL","PowerShell returned no operation data. No successful result was accepted.");
                T result;
                try{result=data.Deserialize<T>(JsonDefaults.Options)??throw new PolicyException("EMPTY_RESPONSE","Windows operation returned an empty result.");}
                catch(JsonException){throw new PolicyException("POWERSHELL_PROTOCOL","PowerShell returned operation data with an invalid format. No successful result was accepted.");}
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
    internal static async Task<string> ReadOutputAsync(StreamReader reader,int limit,CancellationToken ct,Action<string>? progress=null,Action<GpoLiveCheck>? checkProgress=null)
    {
        var output=new StringBuilder();var pending=new StringBuilder();var buffer=new char[4096];bool exceeded=false;int read,total=0;
        string? framedResult=null;bool duplicateResult=false;
        void Line(){
            var line=pending.ToString().TrimEnd('\r');pending.Clear();
            if(line.StartsWith("GPO_STAGE:",StringComparison.Ordinal)){
                var phase=line[10..];
                if(phase.Length<=64&&System.Text.RegularExpressions.Regex.IsMatch(phase,"^[A-Z_]+$"))progress?.Invoke(phase);
            }else if(line.StartsWith("GPO_CHECK:",StringComparison.Ordinal)){
                // Only bounded, product-owned evidence crosses the progress channel.
                if(line.Length>8192)return;
                try{
                    var check=JsonSerializer.Deserialize<GpoLiveCheck>(line[10..],new JsonSerializerOptions{PropertyNameCaseInsensitive=true});
                    if(check is not null && check.Phase is "GPO" or "LINK" or "REPLICATION" or "DOMAIN" or "ENDPOINT" &&
                       check.State is "CHECKING" or "VERIFIED" or "MISMATCH" or "UNAVAILABLE" or "PENDING" &&
                       check.Subject is {Length:<=256} && check.Message is {Length:<=2048} && check.ActualValue is null or {Length:<=4096})
                        checkProgress?.Invoke(check with{CheckedAt=PolicyValues.Now()});
                }catch(JsonException){ }
            }else if(line.StartsWith("GPO_RESULT:",StringComparison.Ordinal)){
                if(framedResult is not null)duplicateResult=true;
                else framedResult=line[11..];
            }else output.Append(line);
        }
        while((read=await reader.ReadAsync(buffer.AsMemory(),ct))>0){
            if(total>limit-read){exceeded=true;pending.Clear();continue;}
            total+=read;if(exceeded)continue;
            for(var i=0;i<read;i++){if(buffer[i]=='\n')Line();else pending.Append(buffer[i]);}
        }
        if(!exceeded&&pending.Length>0)Line();
        if(exceeded)throw new PolicyException("RESPONSE_TOO_LARGE","Windows operation returned too much data; narrow the authorized scope.");
        if(duplicateResult)throw new PolicyException("POWERSHELL_PROTOCOL","PowerShell returned more than one final response. No result was accepted; inspect the recorded operation before retrying a write.");
        // Existing structured launchers remain readable. New launchers always
        // frame the result, so ordinary stdout cannot corrupt the JSON document.
        return framedResult??output.ToString();
    }
    internal static async Task<string> ReadErrorSummaryAsync(StreamReader reader,CancellationToken ct)
    {
        var prefix=new StringBuilder();var buffer=new char[4096];int count;
        while((count=await reader.ReadAsync(buffer.AsMemory(),ct))>0){if(prefix.Length<32768)prefix.Append(buffer,0,Math.Min(count,32768-prefix.Length));}
        var text=prefix.ToString();
        if(System.Text.RegularExpressions.Regex.IsMatch(text,"PSSecurityException|AuthorizationManagerCheckFailed|running scripts is disabled|not digitally signed",System.Text.RegularExpressions.RegexOptions.IgnoreCase))return "SCRIPT_POLICY_BLOCKED";
        if(System.Text.RegularExpressions.Regex.IsMatch(text,"ParserError|ParseException|UnexpectedToken|MissingEndCurlyBrace",System.Text.RegularExpressions.RegexOptions.IgnoreCase))return "SCRIPT_PARSE_ERROR";
        return text.Length==0?"NO_STDERR":"UNCLASSIFIED_STDERR";
    }
    internal static PolicyException TransportError(int exitCode,string? lastStage,int responseLength,string hint)
    {
        var detail=$"Exit code: {exitCode}; last stage: {lastStage??"not received"}; response characters: {responseLength}; stderr: {hint}.";
        return hint switch{
            "SCRIPT_POLICY_BLOCKED"=>new("POWERSHELL_POLICY_BLOCKED","Windows blocked the bundled PowerShell script under the management host execution/signing policy. Review script signing and downloaded-file blocking. "+detail),
            "SCRIPT_PARSE_ERROR"=>new("POWERSHELL_SCRIPT_PARSE","Windows PowerShell could not parse the installed script. Install the complete matching release and verify its file hashes. "+detail),
            _=>new("POWERSHELL_TRANSPORT","PowerShell ended without a valid structured response. No successful operation is established. Inspect the retained operation and management-host PowerShell event logs before retrying a write. "+detail)
        };
    }
}
