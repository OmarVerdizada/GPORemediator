# GPO Remediator 3.1.2 — startup recovery fix

This maintenance release fixes the Windows / AD startup loop without weakening the write gate.

## Fixed

- Setup → Windows restart markers are now resolved deterministically by the launcher. A transient Setup marker can no longer win the race when a complete canonical Windows configuration is already saved.
- Early Windows backend failures are classified as local runtime, database, configuration, authentication, port, access, timeout, or unknown failures. The launcher no longer assumes Kerberos/WinRM is the startup cause.
- A verified self-contained runtime reinstall is attempted once for early runtime/process failures before falling back to Setup. No SDK or internet download is required.
- SQLite recovery is now fail-closed and evidence-preserving: a small/new database is no longer rotated just because some unrelated startup component failed. Recovery runs only when the captured error actually identifies SQLite/schema state.
- Runtime installation validation now requires the executable, managed assembly, deps/runtimeconfig, appsettings, marker, and all production PowerShell worker files.
- Control Center blocks Windows / AD promotion until Domain, writable DC, and at least one operator are present.
- `startup-diagnosis.json` records the startup category and captured local backend failure alongside the existing logs.

## Safety

- Setup remains configuration-only.
- Writes remain disabled unless the production change gate is explicitly enabled for an authorized GPO/scope.
- Existing databases are preserved on recovery; no failed database is deleted.
- AD/Kerberos/WinRM readiness remains a separate preflight/readiness concern and does not prevent the local Windows-mode web service from starting.
