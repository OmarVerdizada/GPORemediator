# Production architecture

GPO Remediator is a local-only Windows management application. The browser UI binds to `127.0.0.1`; it does not expose a LAN listener and does not require an HTTPS certificate in this release.

## Runtime path

`GpoRemediator.cmd` launches the PowerShell bootstrapper. A matching packaged runtime is reused. If the backend source generation changed or repair is requested, the launcher verifies and installs the bundled self-contained runtime archive with its source fingerprint and production marker. Normal starts do not rebuild or download dependencies.

The ASP.NET Core service enforces loopback access, an operator allowlist, CSRF/origin checks, a write-mode gate and one process-level privileged-operation gate. The desktop console defaults to `OperatorAuthentication: LocalLauncher`: local browser requests use the Windows identity that launched the backend, without a browser Windows Security prompt. Local users with access to the console share that operator identity; installations requiring separate browser identities can select `OperatorAuthentication: Windows` to retain Negotiate authentication. Explicit delegated credentials are still required for AD execution. Real GPO work is delegated only to the bundled production workflow.

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
