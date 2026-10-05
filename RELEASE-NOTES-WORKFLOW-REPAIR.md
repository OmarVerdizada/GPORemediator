# GPO workflow repair

The complete connect, preview, authorization restart, approval, backup, apply, link, verify, refresh and rollback chain has been repaired and regression tested.

- Keep the supplied 3.1.2 startup recovery and 3.1.3 tab-memory credential recovery fixes.
- Invalidate the old preview during authorization restart and require review of the new final preview. Surface connection/preview failures without repeatedly reconnecting.
- Apply host allowlists once on the DC, consistently across preview and apply.
- Distinguish absent policy values from explicit empty strings and user-right lists.
- Compare advanced-audit numeric masks, independently of display language.
- Record read-back mismatch in the durable operation manifest.
- Preserve ambiguous publication and interrupted rollback states during verification; block endpoint refresh until publication is known to have completed.
- Serialize execution-record reads, verification and mutations per GPO, and always release the operation gate even when persistence fails.
- Enforce explicit production write boundaries in the backend as well as the launcher; require delegated credentials in the PowerShell wrapper.
- Export schema 1.1 evidence with current read-back values and a reproducible hash covering correlation information.
- Remove duplicate host filtering, redundant validation branches and repeated ignore entries. Rebuild the self-contained runtime and its checksum.

Real-domain publication, cross-DC replication and effective endpoint compliance still require the controlled lab acceptance sequence in `PRODUCTION-TEST-CHECKLIST.md`.
