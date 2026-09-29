# Data retention

GPO Remediator uses an ephemeral-local-state model.

On a full stop or normal launcher exit it removes:
- local SQLite operation/history/audit databases and WAL/SHM files;
- service state and launcher/server logs under `work`;
- transient worker/test artifacts under `work`;
- temporary local configuration write files.

It intentionally keeps:
- `backend/appsettings.Local.json`, because it contains the operator-approved domain/DC/application configuration and avoids requiring Setup on every start;
- the configured GPO `Backup-GPO` repository, because those snapshots are required for safe rollback/recovery;
- application runtime/toolchain files, which are program files rather than operator data.

Credentials and delegated GPO connection tokens are memory-only and disappear when the process stops.


## Failed bootstrap diagnostics
A normal service stop removes local runtime databases, sessions, temporary files and logs. If the bootstrap/build fails before the service starts, only bounded local diagnostic logs are temporarily retained so the operator can see the failure in the Control Panel; they are removed on the next successful normal stop. AD/DC configuration and DC-side GPO backups remain intentionally persistent.
