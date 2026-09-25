# Production backend release notes

## Scope freeze
No new product feature was added in this backend pass. The work hardens the existing CIS v4 remediation workflow so the next step is Windows/AD acceptance testing.

## Backend architecture
- Server-authoritative CIS v4 mapping registry: 405 catalog controls, 401 catalog-marked Automated controls with handlers, four catalog Manual/Unspecified controls intentionally read-only.
- Generic handlers: Security Template, Registry Policy, multi-value Registry Set and Advanced Audit Policy.
- Mapping validation fails closed at startup if counts, IDs, handler shape, scope or audit metadata are inconsistent.
- Account Policy mappings are domain-sensitive and constrained to Default Domain Policy/domain root.
- Read → compare → plan → backup → write → link → verify transaction model.
- Comparator-aware idempotency prevents weakening already stricter compliant Account Policy values.

## Safety and recovery
- Production Windows executor accepts only the GPO workflow operations; legacy pilot/general script dispatch is no longer reachable and only the three production PowerShell files are published.
- Registry-policy reads treat the stable GroupPolicy "not found" result as Not Configured but fail closed on other read/transport errors.
- Advanced Audit CSV reads/writes use structured CSV-safe handling, official extension metadata and numeric endpoint mask verification.
- Real Windows/AD writes only; Setup mode remains configuration-only.
- Local-only web transport on `127.0.0.1` for this release.
- Exact-origin + antiforgery mutation protection and Windows Integrated Authentication/allowlist in Windows mode.
- Delegated execution credential is short-lived, encrypted in process memory and never persisted.
- Full `Backup-GPO` before writes, remote transaction manifest, stale-plan/mapping/fingerprint rejection, process operation gate and per-GPO remote lock.
- Interrupted local runs recover to `REVIEW_REQUIRED`; no automatic replay of a privileged write.
- Rollback requires an intact backup/post-write fingerprint and refuses to overwrite later external changes.

## Verification
- GPO content/link read-back.
- AD and SYSVOL version checks across discovered DCs.
- Replication status is explicit; pending convergence is not reported as success.
- Optional bounded `gpupdate` scheduling.
- Effective sample verification for computer registry, security-template and advanced-audit mappings; user-scoped verification remains pending without a concrete user/session target.
- Audit/evidence includes endpoint checks and backend verification metadata.

## Bootstrap
- Normal startup does not rebuild or download SDK once this backend generation has been built.
- Local management host no longer auto-installs RSAT; GroupPolicy/ActiveDirectory modules are validated on the pinned writable DC where the worker executes.
- If Windows configuration/startup fails, launcher opens safe Setup mode; there is no simulation fallback.

## Remaining work
The source release intentionally omits the stale pre-production runtime so the first Windows start must publish this exact backend generation once. After that, only environment-specific acceptance remains: compile/publish on Windows if this source generation has not been built yet, then execute `PRODUCTION-TEST-CHECKLIST.md` against a disposable domain test GPO/OU before production rollout.
