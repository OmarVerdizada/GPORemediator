using GpoRemediator.Domain;
using GpoRemediator.Infrastructure;

namespace GpoRemediator.Services;

/// <summary>
/// Serializes privileged lifecycle changes and real GPO mutations.  It is deliberately
/// process-local; the worker also takes a durable per-GPO file lock on the selected DC.
/// </summary>
public sealed class OperationGate(Store store)
{
    private readonly object gate = new();
    private bool maintenance;
    private bool operation;

    public bool Maintenance { get { lock (gate) return maintenance; } }
    public bool OperationActive { get { lock (gate) return operation; } }

    public void BeginOperation(Action action)
    {
        lock (gate)
        {
            if (maintenance) throw new PolicyException("SERVICE_STOPPING", "The service is stopping, restarting, or saving configuration.");
            if (operation) throw new PolicyException("GPO_OPERATION_BUSY", "Another privileged GPO operation is active. Wait for it to finish.");
            operation = true;
            try { action(); }
            catch { operation = false; throw; }
        }
    }

    public void EndOperation()
    {
        lock (gate) operation = false;
    }

    public void BeginMaintenance(Action action)
    {
        lock (gate)
        {
            if (maintenance) throw new PolicyException("SERVICE_STOPPING", "The service is already stopping, restarting, or saving configuration.");
            if (operation || store.List<GpoWorkflowRun>("gpo_runs").Any(r => IsActive(r.Result.State)))
                throw new PolicyException("GPO_OPERATION_BUSY", "A GPO operation is active. Wait for it to finish before changing service state or configuration.");
            maintenance = true;
            try { action(); }
            catch { maintenance = false; throw; }
        }
    }

    public void EndMaintenance()
    {
        lock (gate) maintenance = false;
    }

    private static bool IsActive(string state) => state.EndsWith("ING", StringComparison.OrdinalIgnoreCase);
}
