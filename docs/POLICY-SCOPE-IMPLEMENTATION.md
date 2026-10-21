# Scope validation and remediation safety (14 October 2026)

**Base:** main @ `05a47408d0bb3c2d5087613291210811b2930665`, CIS Windows Server benchmark v4.0.0.

## How each of the 405 controls is classified

The reproducible `scripts/Audit-PolicyScopes.py` reads the server-authoritative catalog and imported CIS rule IDs/titles. For every control it records: CIS section, title, declared scope, handler, policy hive or secedit privilege/audit GUID, configured principals, activation state, and potential role exception. This is a **static mapping audit**, not a live domain proof.

- **Section 1:** eight **Domain account** policies (operator-selected active GPO, domain root, link order 1). `1.2.3` is a guided **Computer** exception for the local built-in Administrator.
- **Section 2:** 103 **Computer** policies. All 37 `2.2.*` User Rights Assignment records write `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` -> `[Privilege Rights]`. The names of the principals do NOT turn these into User Configuration policies.
- **Section 5:** one **Computer** policy (service start).
- **Section 9:** 23 **Computer** firewall policies (HKLM).
- **Section 17:** 27 **Computer** advanced audit policies.
- **Section 18:** 230 **Computer** administrative template policies (HKLM).
- **Section 19:** 12 **User** administrative template policies (HKCU); link to user OU. Optional immediate refresh needs an endpoint computer OU and a matching session user.

## Critical control corrections

- `2.2.12` changes `SeSystemTimePrivilege` / **Change the system time**, not Debug programs.
- `2.2.20` changes `SeDebugPrivilege` / **Debug programs**. Both target **computers**.
- A GPO configured or linked successfully is **not proof** an endpoint/user has applied it. Verify winning policy using `gpresult /scope computer /r`, `gpresult /scope user /r` and effective `secedit /export /mergedpolicy`, `auditpol` or registry as appropriate.
- GPO Apply/Read security filtering, WMI filters, blocked inheritance, OU mismatch, competing GPO and replication can prevent application. A gpupdate command schedules refresh; it does not certify compliance.

## Conservative 7-control role-exception gate

Auto-write is disabled for `2.2.6`, `2.2.16`, `2.2.31`, `2.2.33`, `2.2.36`, `2.2.39`, `2.2.45` because generic user-right principal lists can disrupt IIS, SQL Server, AD FS or Exchange. Recipes and recommended values remain visible read-only. Complete role inventory, required SID determination and scoped approval before adding validated automated handlers.

## What remains to validate on Windows AD

The Linux/offline patch package cannot execute Windows GPMC, ActiveDirectory, WinRM, `secedit`, `auditpol`, domain joining or real GPResult. Run the existing project CI tests on Windows/.NET 10, then pilot one policy per processing family in a disposable domain with rollback. Confirm per-host OS/roles/ADMX versions, security filtering, site/OU linkage and effective evidence. Do not deploy blanket GPO changes to a DC or production server OU without that pilot.

## How to generate every control's audit entry

`python scripts/Audit-PolicyScopes.py` writes `work/policy-scope-audit.csv` and `work/policy-scope-summary.md` in the repository root. Re-run after every change. It enforces 405 unique IDs, HKCU/Scope consistency, `2.2` privileges under Computer, domain root scope, and role-sensitive controls not being silently auto-enabled.
