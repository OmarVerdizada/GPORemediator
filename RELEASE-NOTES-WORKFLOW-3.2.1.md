# GPO Remediator 3.2.1

- Read-only discovery retains every GPO and OU returned by the delegated account, even after a production change boundary is narrowed. Apply, Rollback and Refresh independently enforce the configured GPO and scope allowlists. Plans outside that boundary show the authorization action.
- Changing a target-form field no longer replaces the submit button during blur. The old plan and approval are invalidated in place; the next click prepares the current selection, including CIS 1.2.1.
- Completed rollback operations expose an explicit `gpupdate /force` action. Choose PDC or scope computers, restricted to configured allowed hosts and at most 100 scope computers. The worker checks the restored content, extension and link snapshot before and after refresh. It refreshes both policy halves after a full GPO restore, retains rollback state and reports each target's outcome. Refresh scheduling does not prove endpoint convergence.
- Well-known IIS and Hyper-V group SIDs resolve without requiring those roles on the execution host.

## Validation

Run `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File scripts/Test-GpoMappings.ps1 -ReportPath work/mapping-test-results.json` and `dotnet run --project scripts/WorkflowRegression/WorkflowRegression.csproj -c Release`.

Offline Windows PowerShell 5.1 tests execute the worker's actual mapping functions using isolated policy files and mocked GroupPolicy/directory commands: 401 automated controls passed write/read-back, repeat execution, endpoint recipe and applicable numeric-bound tests; 4 non-automated controls are excluded from writes. Refresh target selection, host restrictions, size limit and rollback drift rejection passed. Backend tests cover 2,406 control/refresh/priority combinations, blocked manual controls, full discovery and explicit write authorization. Browser testing confirms the first-click 1.2.1 preview after editing the value and the rollback refresh selector, using fixture responses.

These tests do not contact Active Directory. Live Kerberos/WinRM, GPMC publication, SYSVOL replication, endpoint refresh and effective-policy acceptance still require a test domain.
