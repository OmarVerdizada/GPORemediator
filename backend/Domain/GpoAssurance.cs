namespace GpoRemediator.Domain;

public record GpoAssuranceStage(string Stage,string Status,string Evidence);

// Evidence claims, independent of the operation outcome. Never infer processing
// completion, applicability, or runtime enforcement from a stored policy value.
public static class GpoAssurance
{
    public static bool EffectiveVerified(GpoWorkflowResult r)
    {
        if(!r.GpoPublished || !r.LinkVerified || r.Verification?.ReplicationConverged!=true)return false;
        if(r.EffectiveStatus=="DOMAIN_VALUE_MATCHES_ON_SELECTED_DC")return true;
        var checks=r.EndpointChecks??[];
        if(checks.Length==0 || checks.Any(x=>x.State!="VERIFIED"))return false;
        return r.EffectiveStatus=="VERIFIED_ON_SAMPLE" || r.EffectiveStatus=="VERIFIED_ON_ALL_TARGETS" &&
            r.EndpointCoverage is {Complete:true} coverage && coverage.Total>0 && coverage.Checked==coverage.Total &&
            checks.Select(x=>x.Hostname).Distinct(StringComparer.OrdinalIgnoreCase).Count()==coverage.Total;
    }

    public static GpoAssuranceStage[] Stages(GpoWorkflowResult r)
    {
        var checks=r.EndpointChecks??[];
        var processing=r.RefreshResults.Length==0?"NOT_TESTED":r.RefreshResults.All(x=>x.State=="FAILED")?"FAILED":r.RefreshResults.Any(x=>x.State=="FAILED")?"PARTIAL_SUCCESS":
            r.RefreshResults.All(x=>x.State=="COMPLETED")?"GPUPDATE_COMPLETED":
            r.RefreshResults.Any(x=>x.State=="STARTED")?"GPUPDATE_STARTED":r.RefreshResults.All(x=>x.State=="SCHEDULED")?"GPUPDATE_SCHEDULED":"INSUFFICIENT_EVIDENCE";
        var endpoint=checks.Any(x=>x.State=="MISMATCH")?"ENDPOINT_MISMATCH":
            checks.Length>0&&checks.All(x=>x.State=="VERIFIED")&&(r.EndpointCoverage is null||r.EndpointCoverage is {Complete:true} coverage&&checks.Length==coverage.Total)?"ENDPOINT_VERIFIED":
            r.EffectiveStatus=="DOMAIN_VALUE_MATCHES_ON_SELECTED_DC"?"ENDPOINT_VERIFIED":"INSUFFICIENT_EVIDENCE";
        return [
            new("GPO_CONFIGURATION",r.GpoPublished?"GPO_APPLIED":"NOT_VERIFIED","Selected GPO content and local AD/SYSVOL versions; rollback restores a snapshot rather than the requested mapping."),
            new("GPO_APPLICABILITY",r.LinkVerified?"INSUFFICIENT_EVIDENCE":"NOT_VERIFIED","A direct link is checked. Effective Read/Apply permissions, WMI, nested inheritance and winning GPO require target RSoP evidence."),
            new("AD_SYSVOL_REPLICATION",r.Verification is null?"NOT_TESTED":r.Verification.ReplicationConverged?(r.Verification.EvidenceVersion=="2.0-content"?"VERIFIED":"INSUFFICIENT_EVIDENCE"):"REPLICATION_PENDING","Current probes compare accessible DC content, versions and both CSE halves. Legacy version-only records do not prove content convergence. Unreachable/truncated sets remain pending."),
            new("CLIENT_PROCESSING",processing,"Invoke-GPUpdate records task scheduling only. COMPLETED requires a successful remote gpupdate process exit; endpoint value equality alone does not prove this refresh processed."),
            new("ENDPOINT_CONFIGURATION",endpoint,"Only inspected endpoint values or selected-DC account values are evidence. New plans check every pinned endpoint; legacy plans retain sample coverage. Matching configuration does not prove the selected GPO won or that restart/logon/service/tamper prerequisites are satisfied.")
        ];
    }
    public static string[] Diagnose(GpoWorkflowResult r)
    {
        var notes=new List<string>();
        if(!r.GpoPublished)notes.Add("Check selected domain/DC/GPO, mapping storage/type, write authority, CSE metadata and local AD/SYSVOL versions.");
        if(!r.LinkVerified)notes.Add("Check selected target OU/domain, direct link enablement and priority.");
        if(r.Verification?.ReplicationConverged!=true)notes.Add("Inspect per-DC replication evidence; unavailable probes and equal versions alone are not content convergence.");
        if(r.RefreshResults.Any(x=>x.State=="FAILED"))notes.Add("Inspect endpoint WinRM/Kerberos or task-scheduler/RPC access and per-host gpupdate exit/deadline results; a failed refresh is not proof of policy processing.");
        if((r.EndpointChecks??[]).Any(x=>x.State=="MISMATCH"))notes.Add("Run the control-specific native check and gpresult/RSoP on that endpoint; inspect winning GPO, filtering, audit override, OS applicability and restart/logon/service requirements.");
        if(!(r.EndpointChecks??[]).Any())notes.Add("No endpoint sample exists. Select an authorized endpoint/user session and run read-only verification.");
        notes.Add("These are diagnostic candidates, not established root causes. Collect target RSoP and GroupPolicy Operational events for attribution and processing evidence.");
        return notes.ToArray();
    }
}
