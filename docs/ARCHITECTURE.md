# Production architecture

## Server-owned workflows (3.7.0)

`WorkspaceWorkflows` is a hosted coordinator backed by SQLite workflow and batch records and a bounded in-memory channel. `/api/workflows/*` returns an accepted job that can be inspected after the browser closes. Production endpoint role metadata and CSRF checks protect submission; delegated sessions and write/scope checks also run in the execution service. Per-GPO reservations prevent local writes from interleaving across batch steps. Later batch plans are freshly previewed and must match the preceding fingerprint and reviewed control values before execution. A whole-batch restore uses the first snapshot and validates the last completed write fingerprint.

Worker phase messages are streamed through a bounded parser and persisted with server-observed timestamps. Read-only scan uses preview operations; scheduled verification runs independently of the queue. Durable records contain approvals and results, not connection tokens. On service restart, privileged work is marked for review and is never replayed. See [3.7.0 operation rules and limits](../RELEASE-NOTES-WORKFLOWS-3.7.0.md).

GPO Remediator is a local-only Windows management application. The browser UI binds to `127.0.0.1`; it does not expose a LAN listener and does not require an HTTPS certificate in this release.

## Runtime path

`GpoRemediator.cmd` launches the PowerShell bootstrapper. A matching packaged runtime is reused. If the backend source generation changed or repair is requested, the launcher verifies and installs the bundled self-contained runtime archive with its source fingerprint and production marker. Normal starts do not rebuild or download dependencies.

The .NET 10 ASP.NET Core service requires Windows Negotiate authentication for the actual browser caller. Each account must match exactly one configured role; unknown or ambiguous membership is denied. Endpoint metadata declares mutation privileges independently of route casing or trailing slashes. Recovery Setup accepts only the Windows account that launched the service. Exact Origin, JSON and antiforgery checks protect mutations; the workflow service independently enforces the write gate and explicit GPO/OU boundary.

The launcher applies private Windows DACLs to application state and runtime, rejecting junctions and symbolic links. Data Protection keys use current-user Windows DPAPI. The backend serves embedded frontend assets and compares PowerShell files with hashes of its embedded copies before execution. The launcher compares the installed runtime with the verified release archive. These checks detect file alteration; publisher authenticity still requires a trusted distribution channel and future code signing. See `SECURITY.md` for remaining boundaries.

## AD execution boundary

The management application opens a Kerberos PowerShell remoting session to the configured writable domain controller. The selected DC must provide the ActiveDirectory and GroupPolicy PowerShell modules. The local management host does not need RSAT for the production GPO workflow.

Browser input never selects arbitrary scripts or commands. The only Windows executor entry points are inventory, readiness, preview, apply, rollback, verify and refresh. Credentials are passed through redirected stdin into a short-lived encrypted in-memory session and are never persisted.

## Remediation model

The embedded CIS Benchmark v4.0.0 catalog contains 405 controls. The production mapping registry covers all 405 controls: 401 Automated controls are server-writable and 4 Manual/Unspecified controls are read-only. Mappings dispatch to one of four handlers: SecurityTemplate, Registry, RegistrySet or AdvancedAudit.

Every write follows the same lifecycle: validate selection, preflight, read current state, compare against the benchmark, create a full GPO backup, recheck plan fingerprint, acquire a per-GPO lock, write only when required, link/enable the selected target, verify publication and link state, optionally schedule gpupdate, record evidence and release the lock. A compliant current value produces a no-change result rather than rewriting the GPO.

## Safety and recovery

Preview fingerprints GPO metadata, policy content, links and permissions. Apply rejects stale plans. A durable manifest is written on the selected DC before the backup/write sequence and records phase transitions. Interrupted in-flight operations are recovered as `REVIEW_REQUIRED`; writes are never automatically replayed.

Rollback restores the complete GPO backup and previous link state only when the recorded post-write fingerprint still matches. External changes block automatic rollback and require review.

Verification distinguishes publication from effective policy. It checks GPO content/link state, AD/SYSVOL versions across domain controllers and a bounded endpoint sample where a safe probe is available. Unknown or unavailable effective state remains Pending/Unavailable rather than being reported as compliant.
