# GPO Remediator 3.18.11

## Computer-wide management host

- Adds an optional computer-wide startup service running under LocalSystem. One backend owns the protected ProgramData state and port; every interactive Windows session connects to that same loopback service.
- The launcher now probes the shared service first and opens the UI without reading or rewriting ProgramData. If the installed service is offline, it reports a repairable service error instead of starting a competing backend.
- Browser callers continue to authenticate with Windows Negotiate and remain independently attributed in sessions and audit events.
- Server-side data-protection and audit-integrity keys now use machine-scope DPAPI. The one-time elevated installer migrates the existing audit HMAC key without replacing the audit database and rotates only browser-session protection keys.
- Release installation supports `-MachineService`; its default destination is Program Files and a requested desktop shortcut is placed on the Public Desktop.
- The machine-service migration script uses Windows PowerShell 5.1-compatible sensitive-buffer cleanup on Windows 10 and Windows Server 2019.
- If a legacy audit key belongs to an unavailable DPAPI profile or another computer, an explicit `-InitializeFreshMachineState -ConfirmFreshState PRESERVE_AND_INITIALIZE` recovery keeps the complete former ProgramData state unchanged beside the new state. It never silently discards audit history or keys.
- Backup readiness now states explicitly that the repository lives on the selected domain controller and requires a one-time delegated filesystem ACL there; upgrading the client-side launcher cannot repair remote DC permissions.
- Restores the original visual PowerShell/WPF Local Control Center as the single `GpoRemediator.cmd` entry point. In standard-user machine mode it reads service state and performs Open, Restart and Stop through authenticated loopback APIs without opening protected ProgramData; closing the panel leaves the SYSTEM backend running.
- Native launcher discovery uses bootstrap-safe live/ready health endpoints rather than the browser-confirmed service-details route. A standard operator can no longer fall through to the legacy ProgramData-owned startup path when lifecycle-detail cookies are absent.
- Removes the duplicate top-level Control Center CMD. Administrator-only maintenance remains an internal script instead of a competing daily launcher.
- Production machine-service registration now rejects mutable checkout and user-profile roots by default. The LocalSystem task must run from a verified managed installation (normally under Program Files), preventing a standard user from replacing code that executes as SYSTEM. A conspicuous, explicit confirmation remains available only for isolated development environments.
- Managed installation now copies the machine-service lifecycle dependency into the stable install root before task registration, so `-MachineService` does not depend on files outside the verified release.

## Installation

From an elevated Windows PowerShell window, install a verified release with `Install-GpoRemediator.ps1 ... -MachineService -DesktopShortcut`. Its default destination is the protected `Program Files\GpoRemediator` managed-install root.

Registering a checkout directly as LocalSystem is not a production installation. In an isolated developer VM only, the risk must be accepted explicitly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-MachineService.ps1 `
  -AllowDevelopmentProjectRoot `
  -ConfirmDevelopmentProjectRoot I_ACCEPT_SYSTEM_EXECUTION_FROM_THIS_PATH
```

After the health check succeeds, standard users only open `GpoRemediator.cmd` or `http://127.0.0.1:5080`. They do not receive filesystem access to configuration, audit databases, DPAPI keys or backups.
