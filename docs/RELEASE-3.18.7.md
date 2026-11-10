# GPO Remediator 3.18.7

- Apply detects a change to the GPO fingerprint during publication verification and preserves the checkpoint taken immediately after its own writes.
- Rollback re-verification checks the saved restoration fingerprint, including GPO delegation and linked scopes. A later change leaves the original fingerprint available for review.
- `REG_MULTI_SZ` verification preserves list boundaries for GPO, endpoint and rollback reads. A literal pipe and an empty list member retain their original meaning.
- Rollback reports show the restore target, saved link intent and available read-back evidence. Exported evidence retains the original Apply request for audit.
- Removed an unused color alias left in the shared theme palette.
