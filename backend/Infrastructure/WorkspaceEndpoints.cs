using System.Net;
using System.Text;
using GpoRemediator.Domain;
using GpoRemediator.Services;

namespace GpoRemediator.Infrastructure;

public static class WorkspaceEndpoints
{
    private static string Actor(HttpContext context)=>context.User.Identity?.Name??"";
    private static string Token(HttpContext context)=>context.Request.Cookies["GpoRemediator.GpoConnection"]??"";
    public static void MapWorkspace(WebApplication app){
        app.MapGet("/api/workflows",(HttpContext ctx,WorkspaceWorkflows jobs)=>jobs.List(Actor(ctx)));
        app.MapGet("/api/workflows/{id}",(string id,HttpContext ctx,WorkspaceWorkflows jobs)=>jobs.Get(id,Actor(ctx)));
        app.MapGet("/api/batches",(HttpContext ctx,WorkspaceWorkflows jobs)=>jobs.Batches(Actor(ctx)));
        app.MapGet("/api/batches/{id}",(string id,HttpContext ctx,WorkspaceWorkflows jobs,Store store)=>{
            var batch=jobs.Batches(Actor(ctx)).SingleOrDefault(x=>x.Id==id)??throw new PolicyException("NOT_FOUND","Batch not found.");
            return new{batch,plans=batch.PlanIds.Select(op=>store.Require<GpoWorkflowPlan>("gpo_plans",op))};
        });
        app.MapPost("/api/workflows/preview",(PreviewSubmission request,HttpContext ctx,WorkspaceWorkflows jobs)=>{
            var job=jobs.Preview(request.RequestId,request.Batch,Token(ctx),Actor(ctx));return Results.Accepted("/api/workflows/"+job.Id,job);
        });
        app.MapPost("/api/workflows/scan",(ScanRequest request,HttpContext ctx,WorkspaceWorkflows jobs)=>{
            var job=jobs.Scan(request,Token(ctx),Actor(ctx));return Results.Accepted("/api/workflows/"+job.Id,job);
        });
        foreach(var action in new[]{"apply","rollback","verify","refresh"}){
            var operation=action;
            app.MapPost("/api/workflows/"+operation,(WorkflowRequest request,HttpContext ctx,WorkspaceWorkflows jobs)=>{
                var job=jobs.Start(operation,request,Token(ctx),Actor(ctx));return Results.Accepted("/api/workflows/"+job.Id,job);
            });
        }
        app.MapGet("/api/workflows/{id}/report",(string id,HttpContext ctx,WorkspaceWorkflows jobs,Store store)=>{
            var job=jobs.Get(id,Actor(ctx));
            var ids=job.CompletedIds.Concat(job.PlanIds).Concat(job.CurrentOperationId is {} current?[current]:Array.Empty<string>()).Distinct().ToArray();
            var runs=ids.Select(op=>store.Get<GpoWorkflowRun>("gpo_runs",op)).OfType<GpoWorkflowRun>().ToArray();
            var plans=ids.Select(op=>store.Get<GpoWorkflowPlan>("gpo_plans",op)).OfType<GpoWorkflowPlan>().ToArray();
            var payload=new{schemaVersion="2.0",product="GPO Remediator",generatedAt=job.UpdatedAt,job,runs,plans};
            if(ctx.Request.Query["format"]=="json")return Results.Json(new{payload,integrityHash=PolicyValues.Hash(payload)});
            return Results.Content(Report(job,runs,plans,PolicyValues.Hash(payload)),"text/html; charset=utf-8");
        });
    }
    private static string Report(WorkflowJob job,GpoWorkflowRun[] runs,GpoWorkflowPlan[] plans,string hash){
        static string E(object? value)=>WebUtility.HtmlEncode(value?.ToString()??"—");
        static string Source(GpoValueSource? source,string? value,GpoChoice? recorded=null)=>value is null?"—":E(source is null?(recorded is null?"—":$"{recorded.Name} ({recorded.Id})"):$"{source.GpoName} ({source.GpoId})");
        var html=new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>GPO operation report</title><style>body{font:14px system-ui;margin:32px;color:#172033}table{border-collapse:collapse;width:100%;margin:16px 0;table-layout:fixed}td,th{padding:10px;border:1px solid #bbc3d1;text-align:left;overflow-wrap:anywhere}h2{margin-top:32px}small,pre{overflow-wrap:anywhere;white-space:pre-wrap}@media print{body{margin:0;font-size:10pt}tr{break-inside:avoid}.print-help{display:none}}</style></head><body><h1>GPO Remediator · Operation report</h1><p class=\"print-help\">Use your browser's Print → Save as PDF to export this report. Publication does not prove effective compliance.</p>");
        html.Append($"<p>Workflow: {E(job.Id)} · {E(job.Action)} · {E(job.State)}</p><p>Operator: {E(job.Actor)}<br>Created: {E(job.CreatedAt)}<br>Updated: {E(job.UpdatedAt)}</p><p>{E(job.Message)}</p><p>Change reference: {E(job.Consent.ChangeReference)} · Approver reference: {E(job.Consent.ApprovedBy)}</p>");
        foreach(var plan in plans){
            var run=runs.FirstOrDefault(x=>x.Id==plan.Id);var link=plan.Preview.ExistingLink;var actual=run?.Result.CurrentLink;
            var observedLink=actual is null?"Not measured":$"Enabled={actual.Enabled}, order={actual.Order}, enforced={actual.Enforced}";
            html.Append($"<h2>{E(plan.Selection.Setting)} · {E(plan.Preview.Gpo.Name)}</h2><p>GPO: {E(plan.Selection.GpoId)}<br>Scope: {E(plan.Selection.ScopeDn)}<br>DC: {E(plan.DomainController)}<br>Execution identity: {E(plan.ExecutionUser)}</p><table><tr><th>Field</th><th>Before</th><th>Approved / recorded result</th></tr><tr><td>Value</td><td>{E(plan.Preview.PreviousValue)}</td><td>{E(plan.Preview.DesiredValue)} / observed: {E(run?.Result.CurrentValue)}</td></tr><tr><td>Link</td><td>{E(link is null?"Absent":$"Enabled={link.Enabled}, order={link.Order}, enforced={link.Enforced}")}</td><td>Intent: enable; {E(plan.Selection.FirstLink?"first priority":"preserve existing order, or append a new link")}<br>Observed: {E(observedLink)}</td></tr></table>");
            html.Append($"<p>Before source GPO: {Source(plan.Preview.PreviousValueSource,plan.Preview.PreviousValue,plan.Preview.Gpo)}<br>Current source GPO: {Source(run?.Result.CurrentValueSource,run?.Result.CurrentValue,plan.Preview.Gpo)}</p>");
            if(plan.Preview.DomainPolicy is { } beforeDomain)html.Append($"<p>AD {E(beforeDomain.Property)} before: {E(beforeDomain.Value)}; requested: {E(beforeDomain.DesiredValue)}; server: {E(beforeDomain.DomainController)}</p>");
            if(run?.Result.DomainPolicy is { } actualDomain)html.Append($"<p>Actual AD {E(actualDomain.Property)}: {E(actualDomain.Value)}; requested: {E(actualDomain.DesiredValue)}; server: {E(actualDomain.DomainController)}</p>");
            if(run is not null){
                html.Append($"<p>Result: {E(run.Result.State)} · {E(run.Result.Message)}<br>Backup: {E(run.Result.BackupId)} · {E(run.Result.BackupDirectory)}<br>Effective result: {E(run.Result.EffectiveStatus)}<br>Replication: {E(run.Result.Verification?.ReplicationConverged)}</p><table><tr><th>Observed stage</th><th>Started UTC</th><th>Ended UTC</th></tr>");
                foreach(var stage in run.Stages??[])html.Append($"<tr><td>{E(stage.Phase)}</td><td>{E(stage.StartedAt)}</td><td>{E(stage.FinishedAt)}</td></tr>");
                html.Append("</table><h3>Independent verification stages</h3><table><tr><th>Stage</th><th>Status</th><th>Evidence limits</th></tr>");
                foreach(var stage in run.Result.VerificationStages)html.Append($"<tr><td>{E(stage.Stage)}</td><td>{E(stage.Status)}</td><td>{E(stage.Evidence)}</td></tr>");
                html.Append("</table><table><tr><th>Endpoint</th><th>State</th><th>Evidence</th></tr>");
                foreach(var check in run.Result.EndpointChecks??[])html.Append($"<tr><td>{E(check.Hostname)}</td><td>{E(check.State)}</td><td>{E(check.ActualValue)} · {E(check.Message)}</td></tr>");
                foreach(var check in run.Result.RefreshResults)html.Append($"<tr><td>{E(check.Computer)}</td><td>{E(check.State)}</td><td>{E(check.Message)}</td></tr>");
                html.Append("</table>");
            }
            html.Append($"<p>Warnings: {E(string.Join("; ",plan.Preview.Warnings))}</p>");
        }
        if(job.ScanRows is not null){html.Append("<h2>Read-only scan</h2><table><tr><th>Control</th><th>State</th><th>Current / desired</th><th>Source GPO</th><th>Evidence</th></tr>");foreach(var row in job.ScanRows)html.Append($"<tr><td>{E(row.ControlId)}</td><td>{E(row.State)}</td><td>{E(row.CurrentValue)} / {E(row.DesiredValue)}</td><td>{Source(row.CurrentValueSource,row.CurrentValue)}</td><td>{E(row.Message)}</td></tr>");html.Append("</table>");}
        html.Append($"<p><small>Canonical JSON payload SHA-256: {E(hash)}. Download the JSON report from this endpoint with ?format=json for integrity verification. This hash is not a publisher signature.</small></p></body></html>");return html.ToString();
    }
}
public record PreviewSubmission(string RequestId,BatchPreviewRequest Batch);
