namespace GpoRemediator.Domain;

public record BatchPreviewRequest(GpoSelection[] Selections, bool Pilot = false, int PilotLimit = 10, string? PilotSourceId = null);
public record BatchPlan(string Id, string Actor, string CreatedAt, string[] PlanIds, bool Pilot, int PilotLimit, string? PilotSourceId);
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public record WorkflowRequest(string RequestId, string[] PlanIds, GpoConsent Consent, string Refresh = "None", int[]? VerificationDelays = null, string? BatchId = null, string? SourceWorkflowId = null);
public record ScanRequest(string RequestId, GpoSelection Target, string[] Controls);
public record ScanRow(string ControlId, string State, string? CurrentValue, string? DesiredValue, string Message, string CheckedAt, string? PlanId = null, GpoValueSource? CurrentValueSource = null);
public record WorkflowJob(string Id, string Actor, string Action, string State, string CreatedAt, string UpdatedAt,
    string[] PlanIds, string[] CompletedIds, string Refresh, int[] VerificationDelays, GpoConsent Consent,
    string RequestHash, string Message, string? BatchId = null, string? SourceWorkflowId = null,
    string? NextCheckAt = null, string? StartedAt = null, string? FinishedAt = null, ScanRow[]? ScanRows = null,
    GpoSelection? ScanTarget = null, string[]? ScanControls = null, GpoSelection[]? Selections = null,
    bool Pilot = false, int PilotLimit = 10, string? PilotSourceId = null, string? CurrentOperationId = null);

public static class WorkspaceRules
{
    public static bool Active(string state)=>state is "QUEUED" or "RUNNING";
    public static bool Published(GpoWorkflowRun run)=>run.Result.State is "PUBLISHED" or "NO_CHANGE" && run.Result.GpoPublished && run.Result.LinkVerified;
    public static void ValidateSchedule(int[] schedule){
        if(schedule.Length>3||schedule.Any(x=>x<60||x>900)||!schedule.SequenceEqual(schedule.Distinct().Order()))
            throw new PolicyException("INVALID_REQUEST","Choose up to three distinct increasing verification delays between 60 and 900 seconds.");
    }
    public static void ValidatePilot(GpoWorkflowPlan plan,int limit){
        var impact=plan.Preview.Impact;var affected=impact?.AffectedObjects;
        if(limit<1||limit>20||!plan.Selection.ScopeDn.StartsWith("OU=",StringComparison.OrdinalIgnoreCase)||plan.Preview.Scope.Kind=="Domain"||
            plan.Preview.Gpo.Protected||affected is null||affected.Truncated||affected.Computers<1||affected.Computers>limit||
            impact!.ExistingLinkScopes.Any(scope=>!scope.Equals(plan.Selection.ScopeDn,StringComparison.OrdinalIgnoreCase)))
            throw new PolicyException("PILOT_SCOPE_UNSAFE","Pilot requires a dedicated unprotected GPO, one OU, a complete inventory of 1–20 computers, and no links outside that OU.");
    }
}
