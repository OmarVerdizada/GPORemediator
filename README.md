# GPO Remediator 3.17.2

3.17.2 frames native PowerShell results independently of module stdout, forwards dictionary-shaped live checks, removes the ten-character review minimum and places stored GPO values with their source in the primary plan comparison. See [release notes](docs/RELEASE-3.17.2.md).

3.17.1 explains user/computer/domain targeting before OU selection, improves reviewed-control forms, separates fresh plan steps from recorded results, and surfaces interrupted-operation errors with recovery guidance. See [release notes](docs/RELEASE-3.17.1.md).

3.17.0 streamlines the workspace: one catalog hierarchy, a compact live dashboard, fewer appearance controls, and no Favorites, command palette, Impact graph, Workflow center page or Password policies feature. The server job runner still owns Apply, Verify, Refresh and rollback. See [release notes](docs/RELEASE-3.17.0.md).

3.16.9 streams real verification stages and per-host evidence into the control screen, distinguishes stored GPO settings from an unverified OU value, and fixes compact navigation. See [release notes](docs/RELEASE-3.16.9.md) and [cleanup recommendations](docs/CLEANUP-RECOMMENDATIONS.md).

3.16.8 synchronizes approved domain account settings with the effective AD policy, snapshots those properties for guarded rollback, and replaces the crowded result page with an actual-versus-requested comparison. See [release notes](docs/RELEASE-3.16.8.md).

3.16.7 simplifies mixed OU targeting, shows configured-value GPO sources, verifies effective endpoint values after Apply/Refresh, and fixes rollback refresh. See [release notes](docs/RELEASE-3.16.7.md).

3.16.6 reviews all 405 imported mapping sources for Windows Server 2019, corrects ASR and Remote Encryption feature identities, and rejects stale/unknown source records. See [release notes](docs/RELEASE-3.16.6.md), [per-control source review](docs/mapping-audit/3.16.6/README.md), and [deployment instructions](docs/ASSURANCE-AND-UPDATES.md). Configuration-source review does not certify the original CIS PDF binding or live policy enforcement.

3.14.4 accepts the standard SYSVOL rights created by GPMC **Edit settings** delegation (`Read & execute`, `Write`, and `Delete child`) without requiring per-file Modify/Delete. The publisher retains atomic replacement where available and uses a flushed in-place write after the durable backup/manifest when standard GPMC ACLs do not permit `ReplaceFile`. See [release notes](docs/RELEASE-3.14.4.md).

3.14.3 preserves the administrator-managed backup repository ACL across application restarts and normalizes each control to a compatible domain/OU target. Domain account controls now select the domain root automatically while keeping the OU inventory visible as read-only context. See [changes and upgrade instructions](docs/RELEASE-3.14.3.md).

Target visibility and access update (2026-10-20): all discovered GPOs/OUs remain visible. Incompatible controls get a separate explanation; remediation planning checks effective GPO, SYSVOL and required link access and displays targeted delegation steps when blocked. Read-only scans remain available without edit delegation. See [target access and guidance](docs/TARGET-ACCESS-2026-10-20.md).

Endpoint targeting update (2026-10-20): Settings can automatically discover enabled computers in the selected OU and child OUs, without entering each host. Explicit host lists remain available. Existing lists keep their restriction until the operator selects automatic targeting. See [OU targeting and DC fields](docs/ENDPOINT-TARGETING-2026-10-20.md).

Authentication update (2026-10-20): application operator roles and account allowlists have been removed. Sign in with a user from the configured AD domain. GPO operations use only that credential, and AD enforces its permissions. Windows identity is retained for session binding and audit context. See [authentication changes](docs/AUTHENTICATION-2026-10-20.md).

Responsiveness maintenance (2026-10-19) reduces background rendering, preserves text selections and allows rollback inspection to finish within the server deadline. The portable Windows runtime is rebuilt. See [changes and validation](docs/RESPONSIVENESS-2026-10-19.md).

3.14.2 provides an English interface and documentation, migrates old language preferences, and fixes light/dark theme consistency and mobile settings layout. See [changes and upgrade instructions](docs/RELEASE-3.14.2.md) and the [user guide](USER-GUIDE.md).

The full source and synthetic audit is in [docs/audit/FULL_PROJECT_AUDIT.md](docs/audit/FULL_PROJECT_AUDIT.md), with one evidence-bounded row for all 405 controls. This release fixes the shared auditpol argument, numeric bounds, active firewall verification, replication content checks, stale evidence and refresh result handling. Five independent assurance stages distinguish stored configuration, applicability, replication, client processing and sampled endpoint configuration. **Live AD enforcement and unrestricted production readiness remain unverified; no live AD GPO was modified during this audit.**

Developers can reproduce the individually logged checks with `scripts/Invoke-FullAuditTests.ps1`, then generate the audit inventory using `python scripts/Build-FullAuditReport.py --evidence work/audit/final`. Test fixture results must not be presented as live Windows/AD validation.

One Windows / Active Directory application combines the Studio interface, visual GPO/OU selection, reporting, diagnostics, HMAC audit protection and domain/GPO script isolation in one source tree. Install the complete package; separate ZIP patches are unnecessary.

The integrated release combines the six-wave Studio UI with the cumulative targeting, reliability, reporting, security and domain/GPO isolation updates. The catalog contains **405 controls: 394 automated mappings and 11 manual/review-only controls**. Seven role-sensitive user-right controls remain blocked from automatic writes. Four of the eleven controls have dedicated offline English guides; the other seven display role-specific review warnings.

3.11.1 clarifies `gpupdate /force` as a separate confirmed operation, exposes the same action after a completed rollback, and adds a copyable mapping-specific PowerShell check beneath every endpoint result. It also records an intentional stop marker before the backend exits so the Windows launcher does not misclassify a requested shutdown as a startup failure.

Start with `GpoRemediator.cmd`. The included `release/GpoRemediator-runtime-win-x64.zip` is rebuilt from this source; operators need no SDK or Node.js. Developers use `Build-Portable.ps1`, then `scripts/Validate-Source.ps1 -IncludeBrowser` (.NET 10, Python, Node.js and Playwright required).

Canonical folders: `backend/` for server and trusted PowerShell, `frontend/source/` for editable UI, generated `frontend/dist/`, `scripts/` for tooling and regressions, `security/` for signing and security checks, `docs/` for operational documentation, and `release/` for the self-contained runtime. Patch installers and backup trees are excluded.

See [3.11 integration and validation](docs/INTEGRATION-3.11.0.md) for provenance, fixes and test limits. Local build and simulated workflow tests do not certify a live AD deployment; effective policy, replication and rollback still require a disposable domain pilot.

## Earlier releases

3.10.0 adds first-class user-policy targeting: user OU, endpoint OU, verification identity, user-only gpupdate and exact HKCU evidence are handled separately. It also consolidates authentication into one sign-in surface and enforces the reviewed 385 computer / 12 user / 8 domain scope contract. See [the remediation audit](docs/REMEDIATION-AUDIT.md) for the complete 405-control review.

The application uses one domain-account sign-in to open the workspace and connect to AD. The duplicate dashboard password form is removed; expiry/disconnect returns to the same sign-in screen. Startup still requires explicit sign-in, and Application roles were removed in the 2026-10-20 authentication update. It retains compact colored dashboard metrics and supplemental review guidance for empty policy categories. At 3.10, the catalog contained 401 automated mappings and four guided controls; 3.11 applies the conservative 394/11 boundary above.

3.7.1 provides offline English remediation guides for the four blocked controls, with local/central policy paths, read commands, guarded operator-run Defender backup/apply/rollback examples and honest verification limits. The catalog remains 401 automatic GPO mappings plus four guided controls. See [guided procedures and execution boundaries](docs/GUIDED-REMEDIATION.md).

3.7.0 adds server-managed operations, live observed phases, read-only scans, reviewed batches, verified pilot promotion, scheduled checks, recovery and HTML/print-to-PDF reports. See [workflow release notes](RELEASE-NOTES-WORKFLOWS-3.7.0.md) for use and limits.

3.6.0 hardens the local operator boundary: mandatory Windows authentication, explicit endpoint roles, private Windows state/runtime permissions, DPAPI-protected keys, bounded delegated logins and compiled UI/script integrity checks. The self-contained runtime now uses .NET 10. See [security requirements and limitations](SECURITY.md) and [upgrade notes](RELEASE-NOTES-SECURITY-3.6.0.md). This release also fixes the refresh endpoint so the selected PDC/scope target reaches the worker.

The 3.5.1 workspace adds neutral graphite surfaces, local Geist fonts, comfortable/compact density, three accent palettes, a control-by-control evidence map and accessible GUID/DN/hash copy actions. It builds on the existing navigation, operation tables, audit diagnostics and mobile layouts. See `RELEASE-NOTES-PREMIUM-3.5.1.md`.

Version 3.3.1 introduced the Recipes view, retired in 3.17.0 in favor of one searchable hierarchy. Historical notes: `RELEASE-NOTES-RECIPES-3.3.1.md`.

The redesigned frontend has a current-environment dashboard, clearer catalog statistics, consistent controls and refined mobile/dark layouts. See `RELEASE-NOTES-DESIGN-3.3.0.md`.

The product workspace now includes an actionable dashboard, recent controls, catalog hierarchy/list views, filtered CSV export, operation detail panels, notification access and an English field guide. Operations refresh from recorded server state while being viewed. PowerShell transport uses bounded output buffers, aligned timeouts and structured input validation; rejected stop requests no longer terminate an active operation. See `RELEASE-NOTES-PRODUCT-3.2.0.md` for product improvements and `RELEASE-NOTES-WORKFLOW-3.2.1.md` for discovery, preview and rollback refresh fixes.

> **3.1.3 workflow maintenance:** The delegated execution account is now entered once per active browser workflow, survives the single managed change-gate restart through memory-only tab recovery, and the final preview is automatically regenerated after restart so the first Apply cannot use a stale pre-authorization plan. The password is never written to browser storage or disk.
>
> **3.1.2 startup maintenance:** Windows/AD mode now uses fresh `windows-3.1.2.db` / `setup-3.1.2.db` state stores (older databases are preserved), resolves the Setup→Windows restart-marker race, and creates `startup-diagnosis.json` for early local backend failures. AD/Kerberos/WinRM readiness remains a separate preflight and is not assumed to be the cause of a local service startup failure.


GPO Remediator is a local Windows/Active Directory policy-remediation console for CIS Windows controls. The production package contains a verified self-contained Windows runtime, the operator frontend, the local launcher/control center, and the PowerShell GPO worker. It does not require a .NET SDK, Node.js, pnpm, build tools, or internet access at runtime.

## Start

1. Extract the ZIP into a new folder. Do not overlay an older release folder.
2. Run `GpoRemediator.cmd`.
3. Use the Local Control Center to start the workspace.
4. In Settings, save the AD DNS domain and a writable DC FQDN.
5. Start Windows / AD mode.
6. Use the single sign-in screen with the delegated domain execution account.

The startup console stays attached until the Control Center closes. If startup fails, the error and diagnostic location remain visible; press a key after reviewing them. `GpoRemediator.cmd -Port 5081` opens the panel for an alternate local port.

The UI listens only on `http://127.0.0.1:5080` / `localhost`.

## Persistent state

Application state is stored outside the extracted package:

- configuration: `C:\ProgramData\GpoRemediator\Config\appsettings.Local.json`
- diagnostics and launcher state: `C:\ProgramData\GpoRemediator\State`
- workflow database: `C:\ProgramData\GpoRemediator\Data`
- GPO backups: `C:\ProgramData\GpoRemediator\Backups`
- preserved recovery copies: `C:\ProgramData\GpoRemediator\Recovery`

Do not delete `Backups`, `Data`, or `Recovery` while troubleshooting.


## Windows / AD mode recovery

3.1.2 removes the operator-facing Setup loop. If the browser is running in configuration mode while Domain/DC are already saved, use **Start Windows / AD** on the connection banner. The UI re-saves the canonical configuration and the launcher itself owns the handoff:

`Configuration service → launcher stop → port release → Windows / AD service → readiness`

The launcher also watches a valid configuration save while Setup is healthy. This means the transition no longer depends on the packaged backend successfully terminating itself after a settings save. If Windows mode fails again, the UI surfaces the preserved `startupIssue` and diagnostics instead of silently returning the operator through the same workflow.

3.1.2 uses fresh `setup-3.1.2.db` and `windows-3.1.2.db` stores. Older database files are left untouched in ProgramData; they are not deleted by the upgrade.

## Production change gate

Preview, discovery, readiness, verification, history, and evidence are read-only. Apply and Rollback require the production change gate.

The gate transition is intentionally a controlled restart because ASP.NET configuration is immutable for the lifetime of the running backend process:

1. prepare a read-only plan;
2. enable the change gate;
3. the backend persists `EnableWrites=true` in the canonical ProgramData configuration;
4. the launcher performs one controlled Windows-mode restart;
5. the browser restores the selected control/GPO/scope/plan from session storage;
6. the delegated account is restored from the current tab's memory; a reload or closed tab requires reconnecting;
7. the backend must report `writesEnabled=true` before Apply becomes available.

If the restarted backend does not report the gate as active, the UI blocks automatic reactivation instead of entering an enable/restart/login loop.

### Write-scope safety

Wildcard scope is permitted for read-only discovery, but production writes remain fail-closed. When a read-only preview exists, the UI can narrow the persisted write scope automatically to exactly the selected GPO GUID and selected OU/domain DN before the one controlled write-gate restart. This removes the old manual wildcard-to-GUID configuration loop without making wildcard writes possible.

Web UI identity and execution identity are separate:

- **Windows operator** = authenticated Windows account used to bind the local browser session and record audit context; it has no application role.
- **Domain execution account** = the account entered at sign-in for Kerberos/WinRM/GPO execution. Its password stays in protected memory. The DC validates the account and enforces its AD permissions.

No role or operator list is required. Legacy `Windows.Roles` and `AllowedOperators` values are ignored and removed when the launcher saves canonical configuration. Windows authentication remains mandatory for local session identity in both AD mode and Setup. Initial Setup verifies the current Windows caller password; Windows/AD mode uses the single domain sign-in. Browsers may reuse or prompt for Windows credentials.

## GPO workflow

The execution chain is:

`Connect → Readiness → Preview → Approval → Backup-GPO → Write → Link → Read-back → Verify → optional gpupdate → Evidence / Rollback`

Important behavior:

- a fresh preview is required before Apply;
- a plan expires and is rejected when its live GPO/link fingerprint changes;
- a full `Backup-GPO` snapshot is created before a policy write;
- Apply never runs `gpupdate /force` as an implicit side effect;
- replication and endpoint verification are tracked separately from publication;
- rollback is blocked after external GPO/link changes;
- interrupted/ambiguous write outcomes are recorded for administrator review rather than automatically replayed;
- the durable operation manifest now records `VERIFY_MISMATCH` when immediate post-write read-back fails instead of incorrectly recording `PUBLISHED`.

The backend independently rejects wildcard write authorization, including when it is started without the launcher. Endpoint targeting is applied on the DC during preview and execution: either the selected AD scope or an explicit host list. Missing values differ from explicitly configured empty values, and advanced audit compares numeric masks rather than localized display text. Verification preserves administrator-review states after interrupted publication or rollback, and refresh cannot run against an ambiguous execution.

New evidence exports use schema `1.1`. Their SHA-256 integrity hash covers the serialized export with `integrityHash` set to an empty string, using the backend's canonical JSON serialization. Existing evidence remains immutable.

## Runtime prerequisites

The management host must be domain-connected and use AD DNS. The selected DC must be writable and provide Kerberos, WinRM, LDAP, SYSVOL, the ActiveDirectory module, and GroupPolicy/GPMC.

Windows Time is checked and shown in readiness. If Kerberos/WinRM authentication is already working but the selected DC reports `Free-running System Clock` or `Local CMOS Clock`, 3.1.2 reports a visible **WARN** rather than incorrectly treating that condition alone as proof that the GPO path is unusable. Configure a trusted PDC/NTP source before broad production rollout.

See `CONNECTION-TROUBLESHOOTING.md` for commands and `PRODUCTION-OPERATIONS.md` for production operation and recovery.

## Plan-bound production authorization (3.1.3)

The default `*` entries are intentionally discovery-only. Operators do not need to copy GPO GUIDs or OU DNs into Settings before every change. The production workflow is now:

1. Connect the delegated AD execution account.
2. Select a CIS control, real GPO, and AD scope.
3. Generate the read-only preview.
4. Choose **Authorize this GPO + scope & continue**.
5. The UI persists exactly that GPO GUID and scope DN as the production allowlist, enables the change gate, and performs one managed restart.
6. In the same browser tab, the delegated account is automatically restored from memory-only credential state and a **new final preview** is generated under the active production authorization boundary. No stale pre-restart plan is eligible for Apply.
7. Review the final plan once, enter the change/ticket approval, and Apply. If the page was reloaded/closed, the memory-only credential is intentionally gone and the account is requested once again before the final preview is regenerated.

Settings therefore keeps wildcard discovery read-only and directs production authorization back to the remediation plan instead of asking the operator to enter GUID/OU values manually.

## Frontend development

The backend serves embedded frontend resources. After changing frontend source, rebuild with `Build-Portable.ps1` using the .NET 10 SDK and Node.js; copying files beside the EXE does not update the served UI. The runtime source fingerprint covers both frontend and backend content.

Edit `frontend/source/styles/tokens.css` for theme colors, typography, spacing and radii. Component sources live in `frontend/source/styles/`; `premium.css` defines material, density and accent variants. `premium.js` renders the recorded control map, compact header and copy actions. The unmodified local font files in `frontend/source/fonts/` include their upstream revision and SIL Open Font License. `scripts/Build-Styles.cjs` compiles styles deterministically into the single served `app.css`, retaining selector order and removing exact duplicate blocks. New styles do not use `!important`. Node.js with built-in modules is required only for this developer build step; there are no npm packages or remote runtime assets. `Build-Portable.ps1` compiles CSS before source/dist synchronization.

Shared render components are in `components.js`, preferences in `preferences.js`, catalog rendering in `catalog-view.js`, control/plan rendering in `control-view.js`, and operations/audit rendering in `operation-view.js`. Authentication, mutation guards and API orchestration remain in `workspace.js`. Imported CIS titles, recommendations and descriptions retain the benchmark's English source text; product navigation, labels, guidance and status vocabulary use English.

Run `node scripts/Test-FrontendSystem.cjs`, `node scripts/Test-RecipeWorkspace.cjs`, and `node scripts/Build-Styles.cjs --check` before packaging. Recorded outcomes and automation coverage are not a domain compliance score. Stage animation never invents backup/write/verification completion.
