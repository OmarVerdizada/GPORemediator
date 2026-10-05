# Data retention

Production state is stored outside the extracted package under `C:\ProgramData\GpoRemediator`:

- `Config`: the saved domain/DC, operator roles and approved authorization boundary.
- `State`: launcher/service state and bounded diagnostics.
- `Data`: durable operation records, evidence, audit chain and data-protection keys.
- `Backups`: the configured GPO backup repository.
- `Recovery`: preserved recovery copies.

Normal service shutdown clears in-memory delegated credentials and sessions. Durable operation, audit and recovery records support interruption recovery and must not be deleted during troubleshooting. DC-side backups and manifests are required for rollback and administrator review.

The source tree/runtime archive contains no saved account credentials or environment-specific configuration. Configuration/recovery mode permits settings changes only; domain operations require Windows / AD mode.
