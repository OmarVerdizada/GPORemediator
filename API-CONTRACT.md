# GPO Remediator API contract — production backend

Version 3.17.3: with the production write gate already enabled and an explicit configured boundary, a successful write-access/readiness Preview may return `writeAuthorized: true` for an additional discovered GPO/scope pair. The exact GPO/OU/endpoint-OU grant belongs only to the current delegated connection, is memory-only, and does not modify saved configuration or require restart. Read-only scans grant nothing. Mutation validation checks the actual connection grant or configured boundary, not a client-supplied authorization flag; consent and native write checks still apply. Disconnect/expiry/restart removes grants. Existing plans for a target outside the configured boundary may require a fresh write-access Preview after reconnecting.

Live checks also accept phase `REFRESH` for per-host refresh opening/completion/failure. These frames are distinct from actual endpoint values. Privilege-right endpoint verification uses current local LSA assignments; failed LSA reads remain unverified and are not replaced with security-export equality.

All endpoints are local-only and served from the same origin. In Windows mode the request must also pass Windows Integrated Authentication; there is no application role or operator allowlist. Non-GET API requests require the exact Origin and `X-CSRF-Token` returned by `/api/session`.

`GET /api/v1/health/live` returns the API contract version and the running product assembly version. `GET /api/v1/health/ready` reports process readiness and mode.

## Session / setup

- `GET /api/session` — mode, CSRF token, service/setup state.
- `GET /api/setup/discover` — read-only local Windows hints for AD DNS suffix, logon DC, operator and default backup path. No AD write.
- `GET /api/setup/config` — masked/non-secret saved setup values.
- `POST /api/setup/config` — save domain/DC/backup/operator config, force writes disabled, optionally request controlled restart.
- `POST /api/setup/write-mode` — enable/disable privileged writes. Enabling requires real GPO readiness.

## Execution connection

- `POST /api/gpo/connect` — authenticate a short-lived execution credential and discover real GPO/scope inventory. Password is transport-only and never persisted.
- `POST /api/gpo/disconnect` — zero/remove execution session.
- `GET /api/gpo/inventory` — cached discovered GPO/domain/OU inventory for the connected execution account.
- `POST /api/gpo/discover` — refresh inventory read-only.
- `GET /api/gpo/readiness` — real environment readiness using the connected execution account.

## Catalog / workflow

- `GET /api/gpo/settings` — server-authoritative CIS mapping metadata. The client must not invent registry keys/desired values.
- `POST /api/gpo/preview` — validated read-only plan. Request uses discovered GPO/scope IDs plus control ID and approved option fields.
- `POST /api/gpo/{planId}/apply` — requires `APPLY`, impact acknowledgment and a Change/Ticket ID; the operator-entered approver reference is optional. A protected built-in GPO additionally requires protected acknowledgment. Write mode must be enabled.
- `POST /api/gpo/{planId}/verify` — read-only verification of an existing/no-change operation.
- `POST /api/gpo/{planId}/rollback` — requires `ROLLBACK` and write mode; restores only when backup/post-write fingerprint safety checks pass.
- `GET /api/gpo/history` — current operator's workflow runs.
- `GET /api/gpo/{planId}/evidence` — evidence object with integrity hash, approval, backup and verification metadata.

## Audit / product metadata

- `GET /api/audit` — append-only audit events plus chain integrity state.
- `GET /api/settings` — benchmark/handler/safety-pipeline product metadata.

## State rules

`Preview` expires after 10 minutes. Mapping hash, environment context and GPO/link fingerprint are revalidated before Apply. A write interruption is never automatically replayed; durable/local recovery moves ambiguous runs to `REVIEW_REQUIRED`. `NO_CHANGE` means the mapped value and required direct link already satisfy the plan and no new backup/write was created.

For account-policy controls, AccountScope=LocalComputers with a discovered computer OU resolves to local-account policy; AccountScope=Domain requires the domain root and FirstLink=true. These intents have different mapping hashes and verification behavior. The access-only probe checks the selected objects independently of unfinished policy input values. Native worker errors include their failed stage; post-backup interrupted writes retain the manifest and do not become success results.

An OU may contain both users and computers. The control mapping determines which policy half is processed. The UI defaults user-session endpoint targeting to the selected scope; an optional endpoint override supports users signing in elsewhere.

Preview adds `previousValueSource`, results add `currentValueSource`, and scan rows add `currentValueSource`. Each source is `{gpoId,gpoName}` or null when no configured value was read. These identify the selected GPO's stored value, not the winning endpoint policy. Evidence exports include both sources.

The asynchronous `/api/workflows/apply` and `/api/workflows/refresh` chains include read-only effective verification. An endpoint mismatch ends the workflow with `NEEDS_REVIEW`; unavailable, incomplete or unconverged evidence ends with `CHECKS_INCOMPLETE`. Configured convergence checks remain scheduled until the final check. Publication and refresh scheduling alone are not effective-policy success. Snapshot rollback refresh schedules both computer and signed-in user policies and retains `ROLLED_BACK` separately from refresh results.

Version 3.16.8 adds nullable `domainPolicy` to previews, results and evidence: `{property,value,desiredValue,domainController}`. For the eight mapped AD domain-account settings, preview pins the effective AD value. Apply checks exact domain-attribute write authority, captures before/after AD snapshots in the protected manifest, synchronizes the approved property using the ActiveDirectory cmdlet, and requires read-back. An already-matching GPO with a differing AD value is not `NO_CHANGE`. OU local-account selections do not perform this domain write. Rollback refuses external AD drift and restores only the captured AD property; older GPO-only snapshots have no inferred AD restore value. Known AD mismatches return `ENDPOINT_MISMATCH` and a measured check containing the actual numeric value.

Version 3.16.9 adds optional `liveChecks` to operation history: `{phase,state,subject,actualValue,message,checkedAt}[]`. Phases are GPO/LINK/REPLICATION/DOMAIN/ENDPOINT; events are server-timestamped, bounded and streamed separately from the worker result. Existing workflow/history GET polling observes these checks without resubmitting a verification or performing refresh. CHECKING is an in-flight observation, not a successful measurement. Preview `previousValue` remains the selected GPO’s stored value; non-domain target values are not measured by Preview. `existingLink` describes the selected direct link, independently of inherited links and winning policy.

Version 3.17.0 removes the dedicated `/api/password-policies` endpoints and FGPP execution operations. The eight domain-account GPO controls and their AD read-back remain supported. The Workflow center page is retired, while `/api/workflows` and batch recovery APIs remain server-owned infrastructure for approved jobs and historical recovery. Existing database records and DC backup files are not deleted. The frontend polls job/history APIs through a small single-operation monitor.
