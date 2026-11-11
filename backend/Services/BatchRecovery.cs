using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;

namespace GpoRemediator.Services;

internal static class BatchRecovery
{
    public static WorkflowJob? Source(Store store,string actor,string operationId) => store.List<WorkflowJob>("workflow_jobs")
        .FirstOrDefault(job=>job.Action=="apply"&&job.PlanIds.Length>1&&job.Actor.Equals(actor,StringComparison.OrdinalIgnoreCase)&&job.CompletedIds.Contains(operationId));

    public static (string Target,GpoRollbackAnchor Anchor) Resolve(Store store,WorkflowJob source,string? single)
    {
        if(source.Action!="apply"||WorkspaceRules.Active(source.State)||source.State=="VERIFY_SCHEDULED")
            throw new PolicyException("ROLLBACK_NOT_AVAILABLE","Wait for the batch to finish before restoring a snapshot.");
        var changed=source.CompletedIds.Select(id=>store.Require<GpoWorkflowRun>("gpo_runs",id))
            .Where(run=>!string.IsNullOrEmpty(run.Result.BackupId)).ToArray();
        if(changed.Length==0)throw new PolicyException("ROLLBACK_NOT_AVAILABLE","The batch has no completed backups.");
        static bool Restored(GpoWorkflowRun run)=>run.BatchStepRestored||run.Result.State is "ROLLED_BACK" or "BATCH_ROLLED_BACK";
        static string Fingerprint(GpoWorkflowRun run)=>run.Result.PostFingerprint??throw new PolicyException("ROLLBACK_VERSION_UNKNOWN","The batch write has no completed fingerprint. Re-verify its publication before restoring it.");
        var remaining=changed.TakeWhile(run=>!Restored(run)).ToArray();
        if(changed.Skip(remaining.Length).Any(run=>!Restored(run)))
            throw new PolicyException("BATCH_ROLLBACK_ORDER","The batch has out-of-order recovery records. Review its saved snapshots before another rollback.");
        if(remaining.Length==0){
            if(single is null&&changed[0].Result.State=="ROLLED_BACK"&&changed.Skip(1).Any(run=>run.Result.State=="BATCH_ROLLED_BACK"))
                return (changed[0].Id,new(changed[0].Plan,Fingerprint(changed[0]),[changed[0].Plan]));
            throw new PolicyException("ROLLBACK_NOT_AVAILABLE","Every changed control in the batch already has a restored snapshot.");
        }
        var latest=remaining[^1];
        if(single is not null&&single!=latest.Id)
            throw new PolicyException("BATCH_ROLLBACK_ORDER",$"Restore {latest.Plan.Selection.Setting} next, or use Rollback batch. Individual snapshots are restored in reverse order to preserve the earlier changes.");
        var reference=changed.Length==remaining.Length?latest:changed[remaining.Length];
        return (single??remaining[0].Id,new(reference.Plan,Fingerprint(reference),single is null?remaining.Select(run=>run.Plan).ToArray():null,
            RestoredFromFingerprint:reference.Id==latest.Id?null:Fingerprint(latest)));
    }
}
