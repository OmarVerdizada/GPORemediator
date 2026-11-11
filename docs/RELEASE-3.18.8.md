# GPO Remediator 3.18.8

- **18.7.3** records the configured outgoing Print Spooler RPC protocol as an observation. A different or missing value is a mismatch. Confirmation of the active transport requires runtime evidence on the target Windows release.
- **18.7.11 and 18.7.12** include the Point and Print Restrictions enable value. Both controls can share the approved `Restricted=1` in a batch. They preserve the existing trusted-server settings and apply their respective prompts.
- **Single and bulk previews** show competing GPOs that configure different values for the same policy field, together with the known domain and scope. The preview also shows relevant dependencies. An incompatible shared field blocks the batch before any writes.
- **Bulk results** show publication and endpoint evidence per control. Operations supports individual rollback in reverse publication order as well as rollback of the remaining batch. Restore checks the retained snapshot and live fingerprint. The result records endpoint refresh and verification separately.

Use a fresh plan for 18.7.11 and 18.7.12 to review the added policy field. Retained backups remain available for recovery. See [Bulk Apply](BULK-APPLY.md).
