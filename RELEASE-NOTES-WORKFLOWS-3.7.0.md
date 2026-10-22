# GPO Remediator 3.7.0

## Operation center

Open **Workflow center** after connecting a delegated account on Dashboard. Stored work remains available after closing the browser. Windows authentication, roles, antiforgery protection, write authorization and GPO/OU boundaries remain mandatory.

- Review up to 20 distinct controls against one GPO and scope, including previous/desired values, link order, enabled/enforced state, affected computers and warnings. Organization-specific values require input.
- Apply requires the reviewed batch, ticket/reference, impact acknowledgement, protected-policy acknowledgement where applicable, typed APPLY and a final confirmation. Rollback is a separate, explicitly approved operation requiring ROLLBACK.
- Choose no refresh, PDC or scope for `gpupdate /force`. The server runs the approved refresh only after successful publication or restore. A failed refresh preserves the policy/restore result and each target's evidence. The existing `/refresh` endpoint also accepts the selected request-body target.
- Observe actual worker phase markers and timestamps, rather than simulated progress. An interrupted phase keeps an unknown end time.
- Scan up to 405 selected controls without changing policy. Results distinguish COMPLIANT, DIFFERENT and NOT_CHECKED. Manual/input-dependent controls are not silently counted as compliant. GPO content/link matching does not prove effective endpoint compliance.
- Optional read-only checks run 60, 300 and 900 seconds after the chain finishes. The API permits up to three increasing distinct delays from 60 to 900 seconds. Busy checks are skipped and reported as incomplete; pending endpoint evidence remains pending.
- Pilot application requires a dedicated, unprotected GPO linked only to the selected OU, complete computer inventory and a limit of 1–20 computers. PDC refresh is disallowed for a pilot. Promotion creates a new broad-scope preview and requires another Apply approval. The source pilot must have replication convergence and sample endpoint verification within 30 minutes, with the same controls, values and mappings.
- Recovery lists backups, interrupted work and blocking reasons. Batch recovery restores the first full-GPO snapshot using the last completed batch fingerprint as its drift anchor. Individual rollback of a multi-control batch is blocked. External GPO drift blocks restoration; remaining batch writes stop on ambiguous/failed outcomes.
- HTML reports include approvals, policy comparisons, backups, phases, refresh, scan and endpoint evidence. Open the HTML report and use the browser's Print → Save as PDF for PDF export. JSON reports carry a canonical SHA-256 integrity hash; this is not a publisher signature. Native server-side PDF rendering is not included.

## Durability and limits

The server owns accepted operations; closing a browser does not cancel the chain. Records are persisted in SQLite, while delegated credentials/session tokens remain in memory. Request IDs prevent duplicate submissions with the same payload; changing a payload under the same ID is rejected. One worker processes queued jobs and reservations prevent local overlapping writes on the same GPO. Queues are bounded to 16 jobs, with four unfinished jobs per operator.

Service restart does not replay privileged writes or restore credentials. Interrupted writes require review; interrupted previews/scans/follow-up checks require a new connection and explicit resubmission. Reconnect and verify before approving any new write. The release does not automatically roll back a failed Apply.

## Validation

Production HTTP endpoint tests cover authorization, actor isolation, CSRF integration, target selection, idempotency and immediate acceptance. Coordinator tests cover sequencing, batch rebasing/drift, first-snapshot recovery, pilot rules, read-only scan, schedules, restart handling and report integrity. PowerShell fixtures exercise rollback anchors and streamed phases. Browser tests cover explicit confirmation/cancellation, reopening, recovery requests, scan distinctions, escaping and mobile layout.

AD operations in these regressions use controlled fixtures. Live Kerberos, GroupPolicy, replication, endpoint refresh and effective-policy behavior must still be validated in a dedicated AD test environment. The release preserves the 3.6.0 security hardening; it is not an independent penetration test or a guarantee that all vulnerabilities have been eliminated.
