# GPO Remediator API contract — production backend

All endpoints are local-only and served from the same origin. In Windows mode the request must also pass Windows Integrated Authentication and the configured operator allowlist. Non-GET API requests require the exact Origin and `X-CSRF-Token` returned by `/api/session`.

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
- `POST /api/gpo/{planId}/apply` — requires `APPLY`, impact acknowledgment, Change/Ticket ID and Approver; protected default GPO additionally requires protected acknowledgment. Write mode must be enabled.
- `POST /api/gpo/{planId}/verify` — read-only verification of an existing/no-change operation.
- `POST /api/gpo/{planId}/rollback` — requires `ROLLBACK` and write mode; restores only when backup/post-write fingerprint safety checks pass.
- `GET /api/gpo/history` — current operator's workflow runs.
- `GET /api/gpo/{planId}/evidence` — evidence object with integrity hash, approval, backup and verification metadata.

## Audit / product metadata

- `GET /api/audit` — append-only audit events plus chain integrity state.
- `GET /api/settings` — benchmark/handler/safety-pipeline product metadata.

## State rules

`Preview` expires after 10 minutes. Mapping hash, environment context and GPO/link fingerprint are revalidated before Apply. A write interruption is never automatically replayed; durable/local recovery moves ambiguous runs to `REVIEW_REQUIRED`. `NO_CHANGE` means the mapped value and required direct link already satisfy the plan and no new backup/write was created.
