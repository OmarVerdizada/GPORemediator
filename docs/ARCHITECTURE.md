# Architecture and security boundaries

The static browser application and ASP.NET Core API share an origin. The browser sends typed requests describing catalog controls, target hostnames, approved target selections, preview identifiers and execution options. It cannot submit PowerShell, registry paths, arbitrary expected values or credentials for execution. The packaged frontend has no production Node/npm/pnpm dependency.

## Bootstrap and automation plane

The operator-facing entry point is `GpoRemediator.cmd`. Its PowerShell orchestrator is a local bootstrapper, not a browser-exposed command runner. It verifies source/build fingerprints, provisions a project-local .NET 8 SDK only when a backend rebuild is necessary, copies the dependency-free static UI into the runtime frontend, checks or installs RSAT through a narrowly scoped UAC helper, starts the application, and handles controlled restart markers emitted by validated setup/write-mode API actions. Browser requests cannot choose commands for the bootstrapper.

The UI automates only typed server-side operations: environment readiness, target inventory/scan, source analysis, approved GPO selection, preview, dry run, configuration save and guarded write-mode changes. The write gate deliberately stays separate from Apply; enabling writes does not remove backup, freshness, scope, RSoP, endpoint or rollback checks. HTTPS certificate trust is not auto-created: Windows mode requires an administrator-provisioned valid certificate in `LocalMachine\My` for the configured management DNS name.

## Separation of concerns

`BenchmarkControl` owns policy metadata and applicability. `AdapterRegistry` selects a dedicated user-right adapter or an approved registry-backed adapter. Unsupported technologies and domain account policies fail closed before an apply job is created. `IWindowsPolicyProvider` separates orchestration from Windows/AD operations. Its mock implementation provides durable demonstration state; its Windows implementation delegates to predefined PowerShell operations through one executor.

The sample catalog is original demonstration data with one operator-supplied CIS mapping. Core execution consumes the same benchmark-agnostic model regardless of the source pack. Importing full licensed benchmark exports and scanner findings is an extension boundary, not an implemented MVP integration.

SQLite stores controls, targets, findings, analyses, previews, jobs, backups and mock policy state as distinct entity tables, with relational job-step, verification and audit tables. Individual entity documents are JSON, rather than one shared application-state blob. This makes job status durable across browser refreshes while keeping a narrow storage abstraction suitable for replacing SQLite later.

## Workflow and truthful results

1. Look up control metadata and resolve the target.
2. Analyze applicable GPOs and source confidence. `NOT_DEFINED` and `AMBIGUOUS` are actionable results; neither authorizes silently selecting an unrelated GPO.
3. Select a detected, explicitly approved existing, or dedicated remediation GPO. An undefined policy defaults to a dedicated strategy.
4. Calculate a preview, including old/new values, links, filtering, affected population, restart behavior and backup availability. Unknown impact stays unknown. Broad impact requires explicit acknowledgement.
5. Validate the preview and permissions again before applying. Back up before the first write.
6. Apply through the policy-specific adapter, verify the stored GPO setting and its effective scope, and optionally refresh policy.
7. Verify RSoP, then endpoint state, then benchmark compliance. Only verified compliance becomes `COMPLIANT`/`PASS`.
8. Preserve the job, backup, verification records and append-oriented audit trail for review or explicit rollback.

Dry run creates a preview/audit record in the application's database, but performs no AD, SYSVOL, GPO or endpoint policy writes. `writes: 0` describes policy writes, not the absence of audit persistence. Mock mode is a separate simulated execution provider; an apply in mock mode changes only the simulated state.

Skipping policy refresh does not certify endpoint compliance. A required restart without authorization becomes `CHANGE_APPLIED_RESTART_REQUIRED`. An unavailable or not-yet-effective policy can remain verification pending. A successful PowerShell exit code, GPO write, or refresh request alone is never sufficient for `PASS`.

## Privilege and scope

Mock mode is intended for loopback development. Real execution requires server-side host, OU and GPO allowlists, a configured domain controller, and Windows authentication. User requests do not widen these allowlists. Both default domain GPOs are protected. Account policy is routed to a manual domain-wide/PSO/local-account review because OU policy selection is not a safe domain password-policy workflow.

The Windows process identity should have read permissions for AD and relevant GPOs, edit permissions only on approved remediation GPOs, permissions to read resultant policy and perform approved remote refresh/verification operations, and access to the configured backup location. Provisioning and linking can be delegated separately. Windows Integrated Authentication identifies the caller; it does not imply that all PowerShell operations impersonate that caller.

The API requires a session CSRF token on mutation and rejects a foreign origin. Validation rejects noncatalog controls, malformed hostnames, unsupported selections and GPOs outside approval boundaries. The executor passes a structured payload to a fixed script instead of interpolating browser input into executable PowerShell. Passwords are not part of the browser API or persistent credential model. Diagnostic text and audit details are redacted.

## Backup, rollback and audit

Backup metadata binds the snapshot to job, GPO GUID, control, operator, target/scope and timestamp. Provider-internal backup data is omitted from API job responses. Rollback requires explicit acknowledgement, checks the post-write version, restores the snapshot and verifies the restored state. Full-GPO restoration can affect more than the selected control, so a conflicting later edit must stop the automated rollback.

Audit events carry operator/resource identifiers, timestamp, previous-event hash and event hash. SQLite triggers reject application-level update/delete, and integrity verification detects altered payloads or hash links. A privileged database/file administrator can still replace or truncate the database; externally anchored or immutable audit storage is needed for stronger production assurances.

## Production acceptance boundary

Real Windows integration is implemented behind the same provider contract, but a disconnected development host cannot prove domain behavior. Validate the real service identity, approved OU/GPO scope, RSoP interpretation, GPO security-template preservation, AD and SYSVOL versions, replication, remote refresh, endpoint observation and rollback in a disposable domain before operational use. See `WINDOWS-PROVIDER.md` for the concrete provider behavior and current restrictions.
