## Current release: selected-user password pilot

The current UI and write API support only the six password settings via a new PSO for one selected test user. GPO remediation below is historical architecture retained for future phases; scan and legacy write endpoints are disabled. See [PASSWORD-PILOT.md](docs/PASSWORD-PILOT.md) and README.md for the current workflow.

New endpoints (same origin + CSRF required for POST):

- GET /api/setup/discover — cached read-only management environment detection.
- GET /api/password/settings — six supported settings, ranges and editable suggestions.
- POST /api/password/plan — {user, setting, value}; exact selected-user preview, zero AD writes.
- POST /api/password/{planId}/apply — {confirmation: "APPLY"}; backup, create/assign PSO, resultant verification.
- GET /api/password/history — durable execution records, including before/after snapshots and recovery state.
- POST /api/password/{planId}/rollback — {confirmation: "ROLLBACK"}; remove only that unchanged pilot PSO and verify previous effective policy.

# Internal API contract

Same-origin ASP.NET Core 8 + React API. JSON camelCase, enums UPPER_SNAKE_CASE. Mutation endpoints require the session CSRF token and exact same `Origin`. Windows mode additionally requires HTTPS + Windows Integrated Authentication + operator allowlist.

## Session / inventory

- `GET /api/session` → `{mode,operator,csrfToken,identityStrategy,realModeEnabled}`
- `GET /api/dashboard` → `{findings,jobs,mode}`
- `GET /api/controls` → `BenchmarkControl[]`
- `GET /api/findings/{id}` → finding + control + target + latest source analysis
- `POST /api/findings` → manual finding (manual asserted values never establish verified PASS)

## Service lifecycle

- `GET /api/service` → `{mode,processId,stopping,managed,writesEnabled,activeJobs}`. `writesEnabled` is the effective running configuration, not a pending saved file.
- `POST /api/service/stop {}` and `POST /api/service/restart {}` → `202 {action,accepted:true}`. Available only when started with the product launcher. Same-origin, CSRF, and Windows operator authentication rules apply.
- Lifecycle and automatic setup restarts refuse active jobs with `JOB_BUSY`; after acceptance, new apply/verify/rollback jobs receive `SERVICE_STOPPING`. The launcher restarts only when a validated restart marker exists.
- Stopping leaves the web page disconnected. Starting again requires the desktop panel. No unauthenticated remote start endpoint is exposed.

## Automated discovery / planning

- `GET /api/automation/readiness` → `EnvironmentReadiness`
- `POST /api/automation/scan {hostname,profile:"Auto"|"MemberServer"|"DomainController"|"Workstation"}` → `TargetScanResult`; read-only endpoint verification, auto-create/update FAIL findings
- `POST /api/findings/{id}/safe-plan {}` → `SafePlanResult`; source analysis + safe GPO choice + preview + preflight + dry run, `writes:0`

## Manual remediation workflow

- `POST /api/findings/{id}/analyze {}` → `PolicySourceAnalysis`
- `POST /api/findings/{id}/preview {selection}` → `{impact,preflight}`
- `POST /api/findings/{id}/dry-run {previewId}` → `{dryRun:true,writes:0,impact,preflight}`
- `POST /api/findings/{id}/apply {previewId,options}` → remediation job (`202`)
- `GET /api/jobs` → jobs
- `GET /api/jobs/{id}` → job + steps + redacted backup metadata + verifications
- `POST /api/jobs/{id}/verify {}` → queued verification (`202`)
- `POST /api/jobs/{id}/rollback {acknowledge:true}` → queued verified rollback (`202`)

## Product setup automation

- `GET /api/setup/config` → sanitized local Windows setup view. If `appsettings.Local.json` was changed while the current process is running, this endpoint reads the file rather than returning only stale startup configuration.
- `POST /api/setup/config` → validates URL/domain/DC/GPO/OU/host/operator/backup allowlists, saves Windows config with `EnableWrites=false`, optionally writes a controlled launcher restart marker.
- `POST /api/setup/write-mode {enable,confirmation,autoRestart}` → Windows mode only. Enabling requires readiness PASS and exact `ENABLE WRITES`; disabling requires `DISABLE WRITES`. Change is persisted for the next process and normally triggers controlled restart.
- `GET /api/settings` → current mode, identity strategy, production requirements, supported adapters and limitations.

The UI never submits PowerShell source or arbitrary commands. Backend PowerShell execution is restricted to the fixed operation allowlist implemented in `WindowsPowerShellExecutor` / `Invoke-PolicyOperation.ps1`.
