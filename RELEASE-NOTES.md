# Production release

The application contains the real Windows/Active Directory GPO workflow and its configuration/recovery console.

- Removed development scenarios, browser harnesses, fixtures, dependency manifests, temporary screenshots and sample account configuration.
- Removed unused legacy remediation models, database methods and creation of obsolete job/password tables. Existing database contents are preserved.
- Removed the executor abstraction introduced solely for fixture injection and an unused legacy Windows-profile helper.
- Release builds exclude debugging symbols. The packaged Windows runtime and checksum are regenerated from current source.
- Production startup, readiness, preview, approval, backup, apply, verification, explicit refresh, evidence and rollback remain available.

See `PRODUCTION-OPERATIONS.md` for operation and recovery procedures.
