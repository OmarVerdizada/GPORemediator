# GPO Remediator 3.5.0

The 3.5.0 design system preserves the blue workspace while adding collapsible navigation, two-column domains, an appearance menu, accessible form feedback, compact operation tables, recorded timelines, audit-chain diagnostics and responsive mobile navigation. See `RELEASE-NOTES-SYSTEM-3.5.0.md`.

The new Recipes view lists all controls in numeric order with descriptions, recommended states, automation support and recorded implementation status, even without a domain connection. See `RELEASE-NOTES-RECIPES-3.3.1.md`.

The redesigned frontend has a current-environment dashboard, clearer catalog statistics, consistent controls and refined mobile/dark layouts. See `RELEASE-NOTES-DESIGN-3.3.0.md`.

The product workspace now includes an actionable dashboard, recent controls, catalog hierarchy/list views, filtered CSV export, operation detail panels, notification access and an AZ/EN field guide. Operations refresh from recorded server state while being viewed. PowerShell transport uses bounded output buffers, aligned timeouts and structured input validation; rejected stop requests no longer terminate an active operation. See `RELEASE-NOTES-PRODUCT-3.2.0.md` for product improvements and `RELEASE-NOTES-WORKFLOW-3.2.1.md` for discovery, preview and rollback refresh fixes.

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
6. Connect from Dashboard with the delegated domain execution account.

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

3.1.2 removes the operator-facing Setup loop. If the browser is running in configuration mode while Domain/DC are already saved, use **Windows / AD-ni başlat** on the connection banner. The UI re-saves the canonical configuration and the launcher itself owns the handoff:

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

- **Web UI Administrator / Remediator / Auditor / Viewer** = Windows account used to open and authorize the console.
- **Delegated execution account** = the domain account entered on Dashboard for Kerberos/WinRM/GPO execution. Its password stays in memory and it is never automatically written into the UI role lists.

Legacy configurations that accidentally list one Web UI account in several roles are normalized on launcher startup with precedence `Administrator → Remediator → Auditor → Viewer`.

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

The backend independently rejects wildcard write authorization, including when it is started without the launcher. Host allowlists are applied on the DC during both preview and execution. Missing values differ from explicitly configured empty values, and advanced audit compares numeric masks rather than localized display text. Verification preserves administrator-review states after interrupted publication or rollback, and refresh cannot run against an ambiguous execution.

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

Edit `frontend/source/styles/tokens.css` for theme colors, typography, spacing and radii. Component sources live in `frontend/source/styles/`; `scripts/Build-Styles.cjs` compiles them deterministically into the single served `app.css`, retaining selector order and removing exact duplicate blocks. New styles do not use `!important`. Node.js with built-in modules is required only for this developer build step; there are no npm packages or remote runtime assets. `Build-Portable.ps1` compiles CSS before source/dist synchronization.

Shared render components are in `components.js`, preferences in `preferences.js`, catalog rendering in `catalog-view.js`, control/plan rendering in `control-view.js`, and operations/audit rendering in `operation-view.js`. Authentication, mutation guards and API orchestration remain in `workspace.js`. Imported CIS titles, recommendations and descriptions retain the benchmark's English source text; product navigation, labels, guidance and status vocabulary support AZ/EN.

Run `node scripts/Test-FrontendSystem.cjs`, `node scripts/Test-RecipeWorkspace.cjs`, and `node scripts/Build-Styles.cjs --check` before packaging. Recorded outcomes and automation coverage are not a domain compliance score. Stage animation never invents backup/write/verification completion.
