# GPO Remediator — CIS Benchmark v4.0.0

Local enterprise remediation console for controlled Windows Group Policy changes. The product embeds the operator-supplied CIS Benchmark v4.0.0 catalog, lets an operator choose a control, discovered GPO and target scope, then runs a guarded preview/apply/verify/rollback workflow against a pinned writable domain controller.

## Current production-backend scope

- 405 unique CIS v4 controls in the UI/catalog.
- 401 controls classified `Automated` in the imported catalog have server-authoritative mappings.
- Four catalog `Manual/Unspecified` controls remain intentionally read-only: `1.2.3`, `2.3.11.6`, `18.10.43.10.1`, `18.10.43.10.2`.
- Generic handlers: Security Template, Registry Policy, Registry Set and Advanced Audit Policy.
- No simulation fallback and no SecHard API integration. The operator selects the CIS control directly in the product.

## Start

1. Extract the release into a new folder.
2. Run `GpoRemediator.cmd`.
3. On first run, Setup opens if Windows/AD configuration does not exist. Domain, current operator and a likely logon DC are detected without RSAT where Windows exposes them; values remain editable.
4. Save the exact AD DNS domain, writable DC FQDN, local backup path and allowed Windows operator(s).
5. The launcher restarts into Windows mode.
6. In the main workspace connect an execution account (for the current pilot rollout this can be the DC/domain administrative account). Its password is held only in a short-lived encrypted in-memory session and is never persisted.
7. Run real AD readiness, choose a mapped control, GPO and scope, then Preview before enabling writes.

The web endpoint is local-only: `http://127.0.0.1:5080`. TLS/certificates are intentionally not required in this release because Kestrel rejects non-loopback access.

## Production transaction

`Control → Target → Preview/Preflight → Approval → Backup-GPO → Write → Link → Read-back → Optional gpupdate → Verify`

Safety properties include:

- server-authoritative mapping/value validation;
- domain-sensitive Account Policy enforcement at the domain root and Default Domain Policy;
- environment and selection preflight;
- impact/conflict analysis for inheritance, direct/effective links, security filtering and WMI filtering;
- stale-plan, stale-mapping and GPO fingerprint rejection;
- process-wide privileged-operation gate plus per-GPO remote lock;
- full `Backup-GPO` before a write plus a durable DC-side transaction manifest;
- idempotent `NO_CHANGE` result when policy/link already satisfies the requested state;
- comparator-aware Account Policy checks that do not weaken a stricter compliant value;
- AD/SYSVOL GPO version verification across discovered DCs;
- bounded `gpupdate` scheduling;
- effective sample verification for supported computer-scoped handlers;
- conflict-aware full snapshot rollback;
- append-only SHA-256-chained audit and evidence export.

## Handler behavior

### Security Template
Used for password/lockout policy, User Rights Assignment and selected security-template settings. Principal assignments are resolved to SIDs before writing. GPO security extension metadata and the computer version are updated explicitly.

### Registry / Registry Set
Uses GroupPolicy cmdlets against the selected GPO, with HKLM/HKCU scope enforced by the server mapping registry. Browser-supplied arbitrary registry keys or values are not accepted.

### Advanced Audit
Writes the standard UTF-8 `Machine\Microsoft\Windows NT\Audit\audit.csv`, maintains the official Audit Configuration CSE/tool extension pair, updates the computer GPO version, and verifies effective endpoint masks with `auditpol /r` when a concrete endpoint can be reached.

## Verification semantics

A successful GPO write is not treated as proof of endpoint compliance. The result distinguishes publication/link verification, replication convergence, gpupdate scheduling and effective endpoint evidence. User-scoped controls remain `PENDING` for effective RSoP unless a concrete user/session verification target exists; the tool does not manufacture a green result.

## Rollback

Rollback uses the `Backup-GPO` snapshot created by the same operation and restores the previous direct link state. If the GPO/link fingerprint changed after Apply, automatic rollback is blocked rather than overwriting a later administrator change.

## Build behavior

A packaged runtime starts without SDK downloads. This source generation changes the backend, so the first start of this release may perform one one-time .NET 8 publish if the final runtime marker is absent. If .NET 8 SDK is already installed it is reused; otherwise a project-local SDK is provisioned. Subsequent normal starts use the packaged runtime directly.

The local management host does **not** auto-install RSAT. The production worker runs over Kerberos PowerShell remoting on the selected writable DC and validates the `ActiveDirectory` and `GroupPolicy` modules there.

## Acceptance

Run `PRODUCTION-TEST-CHECKLIST.md` against a disposable test GPO/OU in the organization's own Windows/AD lab before production rollout. Static package validation is not a substitute for real AD/SYSVOL/replication/RSoP testing.
