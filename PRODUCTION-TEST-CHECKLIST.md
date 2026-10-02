# GPO Remediator — Production acceptance checklist

Complete this checklist on a domain-connected Windows management host against a disposable test GPO and test OU before production rollout.

## 1. Package and startup

- Extract the release into a new folder; do not overlay an older release.
- Run `GpoRemediator.cmd`.
- Confirm the verified self-contained runtime installs from the local `release` archive without downloading or compiling anything.
- Confirm a second launcher instance is rejected or routed to the existing service.
- Confirm the backend binds only to loopback.

## 2. Setup and service lifecycle

- Save Domain and writable DC once.
- Confirm Setup hands off to Windows / AD mode with one controlled restart.
- Confirm service PID/state changes are reflected in the UI.
- Confirm a Windows startup failure preserves `windows-startup-error.log` and opens recovery Setup instead of discarding diagnostics.
- Confirm an unexpected Windows-service exit is recovered only by the documented bounded recovery policy.

## 3. Authentication and scope

- Confirm the Web UI uses the configured Windows operator/RBAC role.
- Confirm delegated GPO credentials are supplied separately and are absent from files, logs, browser storage, process arguments, audit rows, and evidence exports.
- Confirm wildcard GPO/OU scope can be used only for read-only discovery.
- Confirm the change gate cannot become active while `ApprovedGpoIds` or `AuthorizedOus` contains `*` or is empty.
- Create a read-only preview and confirm 3.1.1 automatically narrows wildcard discovery scope to that exact GPO GUID + OU/domain DN before enabling the write gate. Manual scope editing should not be required for the normal remediation flow.

## 4. Environment readiness

Verify the readiness screen reports real results for:

- Kerberos/WinRM session to the selected writable DC;
- DNS resolution and AD query;
- ActiveDirectory and GroupPolicy/GPMC modules;
- SYSVOL availability;
- backup repository write access;
- Windows Time source;
- AD replication metadata.

A DC with `Free-running System Clock` or `Local CMOS Clock` must surface a visible Windows Time warning. If Kerberos/WinRM is already proven, the warning alone no longer blocks a test remediation, but production acceptance should not be signed off until the PDC/NTP source is corrected.

## 5. Discovery and preview

- Connect with the intended delegated execution account.
- Confirm GPO and OU discovery matches GPMC/AD.
- Select a low-impact mapped control and disposable GPO/OU.
- Confirm Preview performs no write.
- Confirm the plan records current value, desired value, selected GPO, target DN, link state, conflicts, affected objects, execution identity, and warnings.
- Modify the GPO externally after Preview and confirm the stale plan is rejected.

## 6. Change-gate transition

- Prepare a plan and enable the gate.
- Confirm scope narrowing is persisted without an intermediate restart, then exactly one managed restart occurs when the write gate is enabled.
- Confirm the plan/selection/approval fields survive the restart.
- Confirm the delegated password must be re-entered exactly once.
- Confirm `GET /api/service` reports `writesEnabled=true` after restart.
- If it does not, confirm the UI blocks automatic reactivation instead of looping.

## 7. Apply transaction

- Apply one mapped control.
- Confirm a complete `Backup-GPO` exists before the policy write.
- Confirm the operation manifest records operation ID, mapping/control, approval reference, backup ID, pre/post fingerprints, and final phase.
- Confirm only the selected setting changes.
- Confirm the selected GPO link is created/updated as planned without silently changing Enforced/security/WMI filtering.
- Force an immediate read-back mismatch in a disposable lab and confirm the manifest phase is `VERIFY_MISMATCH`, not `PUBLISHED`.

## 8. Verification and refresh

- Confirm AD and SYSVOL version read-back on the selected DC.
- Confirm multi-DC convergence is shown as converged/pending rather than assumed.
- Confirm Apply does not run gpupdate automatically.
- When Refresh is explicitly requested, confirm bounded target scheduling is recorded per endpoint.
- Confirm endpoint verification distinguishes VERIFIED, MISMATCH, PENDING, and UNAVAILABLE.

## 9. Interruption and concurrency

- Start a conflicting operation against the same GPO and confirm the lock rejects it.
- Interrupt a disposable Apply after backup and confirm the manifest/evidence requires Verify/review rather than replay.
- Restart the local service during a test operation and confirm active local runs recover as review-required, not silently successful.

## 10. Rollback

- Roll back a completed disposable operation.
- Confirm rollback refuses when the current post-Apply fingerprint no longer matches because of an external change.
- Confirm `Restore-GPO` restores the backup and the previous link state.
- Confirm rollback verification compares the pre-change GPO content, extensions, and target link state.

## 11. Audit and evidence

- Confirm the audit hash chain validates.
- Export evidence and verify operator, execution account, control, GPO, target, before/desired/current state, backup ID, approval reference, verification, replication, and endpoint results.
- Confirm no credential or secret appears in evidence.

## Exit criteria

Production acceptance is complete only after the full Apply → Verify → Refresh (when selected) → Rollback chain passes in the organization's own AD topology, including a multi-DC replication test.

## Identity separation regression

- Confirm the Windows account opening the UI appears only in one Web UI role after launcher normalization.
- Enter the delegated DC/GPO execution account only on Dashboard; confirm it is not inserted into Web UI RBAC.
- Save Settings with the same legacy Web UI account typed in multiple role fields and confirm 3.1.1 de-duplicates it instead of returning `DUPLICATE_ROLE_MEMBER`.
