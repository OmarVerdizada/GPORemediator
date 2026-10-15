# 3.12.1: relocated installation sign-in and native service Stop

The sign-in message `GPO_SCRIPT_TAMPERED` is an integrity failure, not an incorrect password. Previous releases generated a launcher containing the installation's absolute bootstrap path in a shared per-domain/GPO directory. Moving or updating the installation changed the expected bytes while leaving that generated launcher in place. A source archive with different line endings could also change the generated template bytes.

Generated launchers now use canonical LF text and a `generated-v2/<SHA256>/` directory beneath the same domain/GPO root. The SHA256 identifies the complete expected launcher, including the bootstrap path. Old entries are preserved and never selected by the new installation. The current entry's launcher and manifest still require exact compiled-content verification; the bundled PowerShell integrity check remains mandatory. No operator credentials or GPO settings are migrated or rewritten.

The native Control Panel and Stop script create a separate authenticated HTTP session. They cannot supply the browser's startup-confirmation cookie. The Administrator-only lifecycle endpoint now allows an authenticated native client before delegated AD sign-in, retaining Windows authentication, configured Administrator authorization, loopback, exact origin, CSRF, launcher-managed and idle-operation gates. GPO operations still require startup confirmation. An active operation still blocks ordinary Stop/Restart.

The client no longer rewrites a stop marker after the backend has accepted and persisted it. This avoids recreating a marker the supervisor already consumed. Stop reports failure rather than success when the registered runtime or launcher remains alive. HTTP 403 and busy responses explain the required action and do not force termination.

## Installing over an affected release

1. Extract the new source ZIP to its own directory on the management host.
2. Stop the old application. If its Stop button remains blocked by the old authentication defect, open elevated PowerShell in the NEW extracted directory and run:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Stop-GpoRemediator.ps1 -Force
   ```

   This is explicit emergency recovery. It may interrupt unfinished work, which requires review after restart. It first sets the supervisor stop marker and waits for exit; if necessary it terminates only the registered runtime after validating its PID, start time and executable path. It does not roll back GPOs or delete state. It is never used by the ordinary Stop button.
3. Close the old Control Panel and any terminal whose current directory is inside the old installation. The Control Panel remains open after stopping the backend so it can be used to start it again; close its window before deleting the directory.
4. Start `GpoRemediator.cmd` from the new directory. Confirm the UI version is **3.12.1**. Existing protected configuration, backups, audit and recovery state remain in ProgramData. No manual deletion of the Scripts, Data or Config directories is required.

## Verification boundary

See `docs/audit/3.12.1-test-results.json` for the dated local regression results. Tests use isolated cache/filesystem, HTTP security and mocked process fixtures; they do not use domain credentials or modify real AD/GPOs. The original full audit's production limitations still apply. Real domain login, clean-host deployment and live GPO lifecycle require validation on the affected host.
