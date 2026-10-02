# GPO Remediator 3.1.1

GPO Remediator is a local Windows/Active Directory policy-remediation console for CIS Windows controls. The production package contains a verified self-contained Windows runtime, the operator frontend, the local launcher/control center, and the PowerShell GPO worker. It does not require a .NET SDK, Node.js, pnpm, build tools, or internet access at runtime.

## Start

1. Extract the ZIP into a new folder. Do not overlay an older release folder.
2. Run `GpoRemediator.cmd`.
3. Use the Local Control Center to start the workspace.
4. In Settings, save the AD DNS domain and a writable DC FQDN.
5. Start Windows / AD mode.
6. Connect from Dashboard with the delegated domain execution account.

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

3.1.1 removes the operator-facing Setup loop. If the browser is running in configuration mode while Domain/DC are already saved, use **Windows / AD-ni başlat** on the connection banner. The UI re-saves the canonical configuration and the launcher itself owns the handoff:

`Configuration service → launcher stop → port release → Windows / AD service → readiness`

The launcher also watches a valid configuration save while Setup is healthy. This means the transition no longer depends on the packaged backend successfully terminating itself after a settings save. If Windows mode fails again, the UI surfaces the preserved `startupIssue` and diagnostics instead of silently returning the operator through the same workflow.

3.1.1 uses fresh `setup-3.1.1.db` and `windows-3.1.1.db` stores. Older database files are left untouched in ProgramData; they are not deleted by the upgrade.

## Production change gate

Preview, discovery, readiness, verification, history, and evidence are read-only. Apply and Rollback require the production change gate.

The gate transition is intentionally a controlled restart because ASP.NET configuration is immutable for the lifetime of the running backend process:

1. prepare a read-only plan;
2. enable the change gate;
3. the backend persists `EnableWrites=true` in the canonical ProgramData configuration;
4. the launcher performs one controlled Windows-mode restart;
5. the browser restores the selected control/GPO/scope/plan from session storage;
6. the delegated password is entered once again because credentials are never written to disk;
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

## Runtime prerequisites

The management host must be domain-connected and use AD DNS. The selected DC must be writable and provide Kerberos, WinRM, LDAP, SYSVOL, the ActiveDirectory module, and GroupPolicy/GPMC.

Windows Time is checked and shown in readiness. If Kerberos/WinRM authentication is already working but the selected DC reports `Free-running System Clock` or `Local CMOS Clock`, 3.1.1 reports a visible **WARN** rather than incorrectly treating that condition alone as proof that the GPO path is unusable. Configure a trusted PDC/NTP source before broad production rollout.

See `CONNECTION-TROUBLESHOOTING.md` for commands and `PRODUCTION-TEST-CHECKLIST.md` for final acceptance testing.

## Plan-bound production authorization (3.1.1)

The default `*` entries are intentionally discovery-only. Operators do not need to copy GPO GUIDs or OU DNs into Settings before every change. The production workflow is now:

1. Connect the delegated AD execution account.
2. Select a CIS control, real GPO, and AD scope.
3. Generate the read-only preview.
4. Choose **Authorize this GPO + scope & continue**.
5. The UI persists exactly that GPO GUID and scope DN as the production allowlist, then opens the change gate through one managed restart.
6. Reconnect the delegated account once and continue the preserved plan.

Settings therefore keeps wildcard discovery read-only and directs production authorization back to the remediation plan instead of asking the operator to enter GUID/OU values manually.
