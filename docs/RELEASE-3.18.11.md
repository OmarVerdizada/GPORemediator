# GPO Remediator 3.18.11

## Computer-wide management host

- Adds an optional computer-wide startup service running under LocalSystem. One backend owns the protected ProgramData state and port; every interactive Windows session connects to that same loopback service.
- The launcher now probes the shared service first and opens the UI without reading or rewriting ProgramData. If the installed service is offline, it reports a repairable service error instead of starting a competing backend.
- Browser callers continue to authenticate with Windows Negotiate and remain independently attributed in sessions and audit events.
- Server-side data-protection and audit-integrity keys now use machine-scope DPAPI. The one-time elevated installer migrates the existing audit HMAC key without replacing the audit database and rotates only browser-session protection keys.
- Release installation supports `-MachineService`; its default destination is Program Files and a requested desktop shortcut is placed on the Public Desktop.
- The machine-service migration script uses Windows PowerShell 5.1-compatible sensitive-buffer cleanup on Windows 10 and Windows Server 2019.

## Installation

From an elevated Windows PowerShell window, either install a verified release with `Install-GpoRemediator.ps1 ... -MachineService -DesktopShortcut`, or register the checked-out project with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-MachineService.ps1
```

After the health check succeeds, standard users only open `GpoRemediator.cmd` or `http://127.0.0.1:5080`. They do not receive filesystem access to configuration, audit databases, DPAPI keys or backups.
