# GPO Remediator — Production Acceptance Checklist

This release is intentionally local-only (`http://127.0.0.1:5080`). The remaining acceptance work must be executed on a domain-connected Windows management host against a disposable test GPO/OU before production use.

## 1. First start / build
- Extract to a new folder; do not overlay an older release.
- Run `GpoRemediator.cmd`.
- Confirm the one-time backend build completes. If a .NET 8 SDK is already installed, it is reused; otherwise the launcher provisions a project-local SDK once.
- Confirm subsequent starts show `Packaged local-only runtime: ready` and do not rebuild or download the SDK.
- Confirm an incomplete configuration opens Setup instead of falling back to a simulation mode.

## 2. Local transport and authentication
- Confirm the UI answers only on `127.0.0.1/localhost` and cannot be reached from another host.
- Confirm Windows mode requires an authenticated Windows operator in `AllowedOperators`.
- Confirm mutation APIs reject missing/incorrect Origin and anti-forgery tokens.
- Confirm the delegated execution password is not present in files, logs, process arguments, audit rows, or browser storage.

## 3. Environment readiness
Using a writable test DC, verify the readiness screen reports real results for:
- Kerberos/WinRM remote session to the selected DC.
- DNS resolution.
- Active Directory query.
- GroupPolicy and ActiveDirectory PowerShell modules on the selected DC.
- SYSVOL availability.
- Backup repository write access.
- AD replication metadata (warning-only where appropriate).

## 4. Read-only discovery and preview
- Connect with the intended execution account.
- Confirm GPO and domain/OU discovery matches GPMC/ADUC.
- Select a low-impact mapped control and a dedicated test GPO/OU.
- Confirm Preview performs no write.
- Compare current/desired values with GPMC.
- Confirm impact analysis reports direct links, inheritance, enforced links, WMI/security filtering warnings, and affected-object inventory where available.

## 5. Idempotency / comparator behavior
For Account Policy tests use a disposable domain lab only.
- If a current value already satisfies `>=` or `<=` CIS semantics more strictly than the default desired value, confirm Apply returns `NO_CHANGE` and does not weaken the value.
- Confirm an already exact-compliant registry/audit/security-template value returns `NO_CHANGE` without creating a new write transaction.
- Confirm a stale preview is rejected if the GPO changes after Preview.

## 6. Real Apply transaction
On a disposable GPO:
- Enable writes only after readiness passes.
- Provide Change/Ticket ID and Approver.
- Apply one mapped control.
- Confirm a full `Backup-GPO` exists before the content write.
- Confirm the DC transaction manifest exists and records phase, operation ID, mapping/control, approval metadata, pre/post fingerprints, and backup ID.
- Confirm only the selected setting changes.
- Confirm the selected link is created/enabled as planned and unrelated links/filters are unchanged.

## 7. Verification
- Confirm GPO content read-back matches the intended compliant state.
- Confirm AD `versionNumber` and SYSVOL `GPT.INI` versions are checked per DC.
- Confirm replication is reported as converged/pending rather than assumed.
- If `gpupdate` was requested, confirm bounded scheduling results are recorded per target.
- For computer-scoped registry/security/audit controls, confirm sample endpoint effective verification matches the target state.
- Confirm user-scoped policy is reported `PENDING` unless a concrete user/session verification target exists; never accept a false green status.

## 8. Concurrency and interruption
- Start an Apply against the same GPO from a second process/session and confirm the per-GPO lock rejects the conflicting write.
- Kill/restart the service during a disposable test operation. Confirm any `*ING` local run is recovered as `REVIEW_REQUIRED` and is not automatically replayed.
- Confirm recovery guidance requires Verify/manifest inspection before retrying.

## 9. Rollback
- Roll back a completed disposable operation.
- Confirm rollback refuses if the post-Apply fingerprint no longer matches (external change conflict).
- Confirm `Restore-GPO` restores the snapshot and the previous link state.
- Confirm rollback verification and audit/evidence records are updated.

## 10. Audit / evidence
- Verify the append-only audit chain reports integrity valid.
- Export evidence for the test operation and compare control, before/desired/effective state, GPO, scope, operator, execution account, backup, approval, replication and endpoint verification to the real environment.
- Confirm no secret is present in exported evidence.

## Exit criteria
Production acceptance is complete only after the above checks pass in the organization's own AD topology, including at least one multi-DC replication test and one successful rollback. The package deliberately does not claim those environment-specific tests have been completed by the build environment.
