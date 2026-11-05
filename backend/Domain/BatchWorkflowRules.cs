namespace GpoRemediator.Domain;

// Batch-only planning. Ordinary single-control plans retain their existing path.
public static class BatchWorkflowRules
{
    public static string Refresh(GpoWorkflowPlan plan,string requested)=>requested!="Auto"?requested:
        ProductionGpoMappings.Effective(plan.Selection).DomainPolicySensitive?"Pdc":"Scope";

    public static GpoWorkflowPlan[] RefreshGroups(IEnumerable<GpoWorkflowPlan> plans,string requested)=>plans
        .GroupBy(p=>new{Refresh=Refresh(p,requested),Scope=ProductionGpoMappings.Effective(p.Selection).Scope,
            p.Selection.ScopeDn,p.Selection.EndpointScopeDn,p.Selection.VerificationUser})
        .Select(g=>g.Last()).ToArray();

    public static GpoWorkflowPlan[] Order(GpoWorkflowPlan[] plans)
    {
        var domain=plans.Where(p=>p.Preview.DomainPolicy is not null).ToArray();
        string? Final(string property)=>domain.FirstOrDefault(p=>p.Preview.DomainPolicy!.Property==property)?.Preview.DomainPolicy!.DesiredValue;
        var duration=Final("LockoutDuration");var window=Final("LockoutObservationWindow");
        foreach(var plan in plans.Where(p=>p.Preview.Dependency is not null))
        {
            var dependency=plan.Preview.Dependency!;
            var related=plans.SingleOrDefault(p=>p.Selection.Setting==dependency.Setting);
            if(related?.Preview.DomainPolicy?.Property!=dependency.Property)
                throw new PolicyException(dependency.Code,$"Control {plan.Selection.Setting}: {dependency.Message}");
            if(dependency.Property=="LockoutDuration")duration??=dependency.CurrentValue;
            if(dependency.Property=="LockoutObservationWindow")window??=dependency.CurrentValue;
        }
        if(duration is not null&&window is not null&&double.Parse(duration,System.Globalization.CultureInfo.InvariantCulture)>0&&
            double.Parse(duration,System.Globalization.CultureInfo.InvariantCulture)<double.Parse(window,System.Globalization.CultureInfo.InvariantCulture))
            throw new PolicyException("DOMAIN_LOCKOUT_DEPENDENCY","The selected batch would leave duration below the reset-counter window. Review the selected values; no writes were performed.");
        var ordered=new List<GpoWorkflowPlan>();var remaining=plans.ToList();
        while(remaining.Count>0)
        {
            var ready=remaining.FirstOrDefault(p=>(p.Preview.Dependency is null||ordered.Any(done=>done.Selection.Setting==p.Preview.Dependency.Setting))&&
                !(p.Preview.DomainPolicy is {Property:"LockoutThreshold",DesiredValue:not "0"}&&remaining.Any(other=>other.Preview.DomainPolicy?.Property is "LockoutDuration" or "LockoutObservationWindow")));
            if(ready is null)throw new PolicyException("BATCH_DEPENDENCY_CYCLE","The selected controls have unresolved dependencies. Review their values before applying.");
            remaining.Remove(ready);
            if(ready.Preview.Dependency is {} dependency)ready=ready with{Preview=ready.Preview with{Dependency=null,
                Warnings=[..ready.Preview.Warnings,$"BATCH_DEPENDENCY: {dependency.Setting} is approved earlier in this batch before {ready.Selection.Setting}. Apply will re-check the live prerequisite; no related setting is inferred."]}};
            ordered.Add(ready);
        }
        return ordered.ToArray();
    }
}
