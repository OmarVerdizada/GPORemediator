using GpoRemediator.Domain;
namespace GpoRemediator.Services;
public interface IWorkflowOperations
{
    void ValidateConnection(string token,string actor);
    GpoWorkflowPlan ValidateSubmission(string id,string operation,GpoConsent consent,string token,string actor);
    Task<GpoWorkflowPlan> PreviewAsync(string token,string actor,GpoSelection selection,CancellationToken ct,bool requireWriteAccess=true);
    Task<GpoWorkflowRun> ExecuteAsync(string id,string operation,GpoConsent consent,string token,string actor,string? workflowId=null,GpoRollbackAnchor? rollbackAnchor=null);
}
