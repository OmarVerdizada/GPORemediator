# GPO Remediator API contract — production backend

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
