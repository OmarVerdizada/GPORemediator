# Domain / GPO script isolation

## Directory structure

C:\ProgramData\GpoRemediator\Scripts\<domain-dns-name>\<gpo-guid>\

Each discovered GPO has its own directory containing Invoke-Gpo.ps1 (an entry point bound to the domain and GPO GUID) and scope.json (domain, GPO GUID and script SHA-256 integrity metadata, without credentials).

## Execution model

1. Starting a session synchronizes discovered GPO GUIDs into separate directories. Discover adds new GPOs.
2. Preview, Apply, Verify, Rollback, rollback inspection and Refresh select the entry point matching the requested domain and GPO.
3. The backend compares file content and manifests with the exact expected bytes. Alteration blocks execution. Symlinks and junctions are rejected. DACLs restrict access to the service identity, SYSTEM and Administrators.
4. The per-GPO entry point independently validates the request's domain and GPO GUID.
5. Policy logic remains in the shared trusted engine embedded in the .NET build and checked by SHA-256. Credentials, selected values and request arguments are not written to these directories.
6. Inventory and readiness use the shared read-only bootstrap because they do not target one GPO.

## Boundaries

- File and context separation does not create separate Windows sandboxes, process accounts or AD authentication contexts. AD permissions remain the security boundary.
- The backend supports one active Windows:Domain / Windows:DomainController configuration. Changing domains creates a new directory and retains old directories; it does not add concurrent domain sessions.
- Source changes require rebuilding the Windows .NET 10 backend and packaging the runtime.
- Do not edit generated ProgramData scripts. Install a complete verified release.
- Initial synchronization may take time in domains with thousands of GPOs because it creates files and ACLs.
- Validate deployment in a lab AD environment. Offline tests do not establish live AD or rollback behavior.
