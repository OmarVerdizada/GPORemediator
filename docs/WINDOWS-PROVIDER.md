# Windows / Active Directory execution

Production operations require Windows / AD mode, domain connectivity, AD DNS and a writable DC. Setup/Recovery manages configuration only.

## Execution identities

The web operator uses Windows Integrated Authentication. Domain operations run on the selected DC through Kerberos/WinRM using the signed-in delegated execution account. There is no application role allowlist. The backend service account is not automatically used for GPO execution.

The delegated password remains in memory and reaches the local PowerShell worker through private stdin. It is excluded from browser storage, process arguments, logs, configuration, audit and evidence files. The server owns policy mappings; the browser cannot submit arbitrary scripts or registry commands.

## Requirements and permissions

The selected DC must provide ActiveDirectory and GroupPolicy/GPMC modules, SYSVOL and a writable backup repository. The delegated account needs permission to edit the selected GPO, its SYSVOL content and the target gPLink.

Apply, Rollback and explicit Refresh require the production change gate and authorization for the specific GPO/scope. Wildcards permit read-only discovery only. Required readiness checks must pass.

## Operations and recovery

Generate a fresh preview, review all existing links and impact, and provide a change reference and acknowledgments. Backup-GPO runs before policy changes. Apply does not automatically run gpupdate.

Verify publication, links, replication and endpoint results separately. Do not repeat Apply when its outcome is uncertain. Rollback requires a complete backup and an unchanged post-write fingerprint. See PRODUCTION-OPERATIONS.md.
