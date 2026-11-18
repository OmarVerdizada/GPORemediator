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
- Adds `GpoRemediator-ControlCenter.cmd`, a visible UAC-elevated lifecycle console for the machine-wide backend. Its Start action launches the registered SYSTEM task, while Stop and Restart use the existing safe operation-gated API; it never starts a replacement backend under the interactive administrator.

## Installation

From an elevated Windows PowerShell window, either install a verified release with `Install-GpoRemediator.ps1 ... -MachineService -DesktopShortcut`, or register the checked-out project with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-MachineService.ps1
```

After the health check succeeds, standard users only open `GpoRemediator.cmd` or `http://127.0.0.1:5080`. They do not receive filesystem access to configuration, audit databases, DPAPI keys or backups.
