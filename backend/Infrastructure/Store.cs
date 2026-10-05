using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using GpoRemediator.Domain;
using Microsoft.Data.Sqlite;

namespace GpoRemediator.Infrastructure;

public sealed class Store : IDisposable
{
    private readonly SqliteConnection db;
    private readonly object gate = new();
    private static readonly HashSet<string> Tables = ["gpo_plans", "gpo_runs", "gpo_evidence"];
    public Store(string path)
    {
        if (path != ":memory:") Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource=path, ForeignKeys=true, Pooling=false }.ToString()); db.Open();
        Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA wal_autocheckpoint=1000;");
        Execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL); INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);");
        Execute("CREATE TABLE IF NOT EXISTS deployment(key TEXT PRIMARY KEY,value TEXT NOT NULL);");
        foreach (var table in Tables)
            Execute($"CREATE TABLE IF NOT EXISTS {table}(id TEXT PRIMARY KEY, state TEXT, data TEXT NOT NULL, updated_at TEXT NOT NULL);");
        Execute("""
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,operator TEXT NOT NULL,job_id TEXT,control_id TEXT,gpo_id TEXT,details TEXT NOT NULL,created_at TEXT NOT NULL,previous_hash TEXT NOT NULL,hash TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'Audit events are append-only'); END;
            CREATE INDEX IF NOT EXISTS ix_gpo_runs_state_updated ON gpo_runs(state,updated_at DESC);
            CREATE INDEX IF NOT EXISTS ix_audit_operator_created ON audit(operator,created_at DESC);
            """);
    }
    private SqliteCommand Command(string sql, params (string, object?)[] parameters)
    {
        var command = db.CreateCommand(); command.CommandText = sql;
        foreach (var (key, value) in parameters) command.Parameters.AddWithValue(key, value ?? DBNull.Value);
        return command;
    }
    public void Execute(string sql, params (string, object?)[] parameters)
    { lock (gate) { using var command = Command(sql, parameters); command.ExecuteNonQuery(); } }
    public void BindExecutionMode(string mode)
    {
        lock(gate)
        {
            // The production workflow is isolated by database file (windows.db/setup.db).
            // Legacy pre-production/job tables may exist after an in-place upgrade and must not
            // prevent the real GPO workflow from opening its own durable store.
            Execute("INSERT OR IGNORE INTO deployment(key,value) VALUES('execution_mode',$mode)",("$mode",mode));
            using var command=Command("SELECT value FROM deployment WHERE key='execution_mode'");
            if((string?)command.ExecuteScalar()!=mode) throw new InvalidOperationException("Execution mode does not match the database. Use a separate database for each provider.");
        }
    }

    public int RecoverInterruptedGpoRuns()
    {
        lock(gate)
        {
            var recovered=0;
            foreach(var run in List<GpoWorkflowRun>("gpo_runs").Where(r=>GpoWorkflowRules.IsActive(r.Result.State)))
            {
                var result=run.Result with
                {
                    State="REVIEW_REQUIRED",
                    Message="The previous service process ended while this operation was active. Do not replay Apply. Run read-only Verify and inspect the recorded DC manifest/backup before recovery."
                };
                Put("gpo_runs",run.Id,run with{Result=result,UpdatedAt=PolicyValues.Now()},result.State);
                Audit("GPO_INTERRUPTED_RECOVERED",run.Plan.Actor,jobId:run.Id,controlId:run.Plan.Selection.Setting,gpoId:run.Plan.Selection.GpoId,details:new{previousState=run.Result.State,recoveredState=result.State});
                recovered++;
            }
            return recovered;
        }
    }
    private static string Table(string table) => Tables.Contains(table) ? table : throw new ArgumentException("Invalid table");
    public void Put<T>(string table, string id, T data, string? state = null) => Execute(
        $"INSERT INTO {Table(table)}(id,state,data,updated_at) VALUES($id,$state,$data,$at) ON CONFLICT(id) DO UPDATE SET state=$state,data=$data,updated_at=$at",
        ("$id", id), ("$state", state), ("$data", JsonDefaults.Serialize(data)), ("$at", PolicyValues.Now()));
    public T? Get<T>(string table, string id)
    {
        lock (gate) { using var command = Command($"SELECT data FROM {Table(table)} WHERE id=$id", ("$id", id));
            var data = command.ExecuteScalar() as string; return data is null ? default : JsonDefaults.Deserialize<T>(data); }
    }
    public T Require<T>(string table, string id) where T : class => Get<T>(table, id) ?? throw new PolicyException("NOT_FOUND", $"{table} object was not found.");
    public T[] List<T>(string table)
    {
        lock (gate) { using var command = Command($"SELECT data FROM {Table(table)} ORDER BY updated_at DESC,id"); using var reader = command.ExecuteReader();
            var items = new List<T>(); while (reader.Read()) items.Add(JsonDefaults.Deserialize<T>(reader.GetString(0))); return items.ToArray(); }
    }
    public int CountActiveGpoRuns()
    {
        lock(gate)
        {
            using var command=Command("SELECT COUNT(*) FROM gpo_runs WHERE UPPER(state) IN ('APPLYING','VERIFYING','REFRESHING','ROLLBACKING','ROLLING_BACK')");
            return Convert.ToInt32(command.ExecuteScalar());
        }
    }
    public GpoWorkflowRun[] GpoRunsForActor(string actor,int limit=200)
    {
        lock(gate)
        {
            using var command=Command("SELECT data FROM gpo_runs WHERE json_extract(data,'$.plan.actor')=$actor COLLATE NOCASE ORDER BY updated_at DESC,id LIMIT $limit",("$actor",actor),("$limit",Math.Clamp(limit,1,500)));
            using var reader=command.ExecuteReader(); var items=new List<GpoWorkflowRun>();
            while(reader.Read()) items.Add(JsonDefaults.Deserialize<GpoWorkflowRun>(reader.GetString(0)));
            return items.ToArray();
        }
    }
    public void Audit(string eventName, string operatorName, string? jobId = null, string? controlId = null, string? gpoId = null, object? details = null)
    {
        lock (gate)
        {
            using var previousCommand = Command("SELECT hash FROM audit ORDER BY id DESC LIMIT 1");
            var previous = previousCommand.ExecuteScalar() as string ?? "GENESIS";
            var at = PolicyValues.Now(); var safe = Redactor.Clean(JsonDefaults.Serialize(details ?? new { }));
            var hash = PolicyValues.Hash(new { eventName, operatorName, jobId, controlId, gpoId, details=safe, at, previous });
            Execute("INSERT INTO audit(event,operator,job_id,control_id,gpo_id,details,created_at,previous_hash,hash) VALUES($e,$o,$j,$c,$g,$d,$a,$p,$h)",
                ("$e",eventName),("$o",operatorName),("$j",jobId),("$c",controlId),("$g",gpoId),("$d",safe),("$a",at),("$p",previous),("$h",hash));
        }
    }
    public AuditEvent[] AuditEvents(int? limit=null)
    {
        lock (gate) { var sql=limit is null?"SELECT id,event,operator,job_id,control_id,gpo_id,details,created_at,previous_hash,hash FROM audit ORDER BY id":"SELECT id,event,operator,job_id,control_id,gpo_id,details,created_at,previous_hash,hash FROM (SELECT * FROM audit ORDER BY id DESC LIMIT $limit) ORDER BY id";
            using var command = limit is null?Command(sql):Command(sql,("$limit",Math.Clamp(limit.Value,1,1000)));
            using var r=command.ExecuteReader(); var list=new List<AuditEvent>();
            while(r.Read()) list.Add(new(r.GetInt64(0),r.GetString(1),r.GetString(2),r.IsDBNull(3)?null:r.GetString(3),r.IsDBNull(4)?null:r.GetString(4),r.IsDBNull(5)?null:r.GetString(5),r.GetString(6),r.GetString(7),r.GetString(8),r.GetString(9))); return list.ToArray(); }
    }
    public bool AuditIntegrity()
    {
        string previous="GENESIS";
        foreach(var e in AuditEvents()) { var hash=PolicyValues.Hash(new {eventName=e.Event,operatorName=e.Operator,jobId=e.JobId,controlId=e.ControlId,gpoId=e.GpoId,details=e.Details,at=e.CreatedAt,previous});
            if(e.PreviousHash!=previous || e.Hash!=hash) return false; previous=e.Hash; } return true;
    }
    public void Dispose() => db.Dispose();
}

public static partial class Redactor
{
    [GeneratedRegex("(?i)(password|passwd|pwd|access[_-]?token|refresh[_-]?token|secret|securestring|authorization)([\\\"'\\s]*[:=][\\\"'\\s]*)([^\\\"'\\s,;}]+)")]
    private static partial Regex Secrets();
    [GeneratedRegex(@"(?i)Bearer\s+[a-z0-9._~+/=-]+")]
    private static partial Regex Bearer();
    public static string Clean(string value)
    {
        try
        {
            var node=System.Text.Json.Nodes.JsonNode.Parse(value);
            void Scrub(System.Text.Json.Nodes.JsonNode? item)
            {
                if(item is System.Text.Json.Nodes.JsonObject obj)
                    foreach(var key in obj.Select(p=>p.Key).ToArray())
                    {
                        if(Regex.IsMatch(key,@"(?i)^(password|passwd|pwd|access[_-]?token|refresh[_-]?token|secret|securestring|authorization)$")) obj[key]="[REDACTED]";
                        else if(obj[key] is System.Text.Json.Nodes.JsonValue val && val.TryGetValue<string>(out var text)) obj[key]=CleanText(text);
                        else Scrub(obj[key]);
                    }
                else if(item is System.Text.Json.Nodes.JsonArray array)
                    for(var index=0;index<array.Count;index++)
                        if(array[index] is System.Text.Json.Nodes.JsonValue value && value.TryGetValue<string>(out var text)) array[index]=CleanText(text);
                        else Scrub(array[index]);
            }
            Scrub(node); return node?.ToJsonString()??value;
        }
        catch(System.Text.Json.JsonException) { return CleanText(value); }
    }
    private static string CleanText(string value)
    {
        value=Bearer().Replace(value,"Bearer [REDACTED]");
        value=Regex.Replace(value,"(?i)(password|passwd|pwd|secret|securestring)(\\s*[:=]\\s*)(\"[^\"]*\"|'[^']*')","$1$2[REDACTED]");
        return Secrets().Replace(value,"$1$2[REDACTED]");
    }
}
