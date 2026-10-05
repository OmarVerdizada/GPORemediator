# Production modules

GPO Remediator uses a single production workflow.

1. `backend/Domain/ProductionGpoMappings.cs` loads and validates the embedded CIS v4.0.0 mapping registry.
2. `backend/Services/GpoWorkflowService.cs` owns connection, preview, apply, verify, refresh, replan, evidence and rollback orchestration.
3. `backend/Infrastructure/WindowsPowerShellExecutor.cs` exposes only the fixed GPO workflow operations.
4. `backend/PowerShell/Invoke-GpoWorkflow.ps1` transports the request to the pinned writable DC over Kerberos/WinRM.
5. `backend/PowerShell/GpoWorkflow.Worker.ps1` performs live AD/GPO discovery, preview, Backup-GPO, write, link, verification, gpupdate scheduling and rollback.
6. `backend/PowerShell/SecurityTemplate.psm1` safely edits security-template content used by mapped CIS controls.
7. `backend/Infrastructure/Store.cs` stores durable GPO plans, execution records, evidence and append-only audit data.

The production application exposes only the Windows GPO workflow; obsolete Password Pilot, adapter-registry and general-purpose PowerShell execution surfaces are not included.
