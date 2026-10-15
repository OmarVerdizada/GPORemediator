# 3.12.3: advanced tabs, coherent evidence and repeat rollback

The Advanced tab dropdown was clipped by the control header's hidden overflow and the tab bar's horizontal scrolling. Selecting an advanced tab also forced its details menu to remain open on subsequent renders. The header/tab bar now allow the anchored dropdown to remain visible, selection closes it, and outside click or Escape closes it. Escape returns focus to the summary. Tabs wrap on narrow screens.

Current API assurance stages now render once; the older five-node timeline is retained only for legacy responses without those stages. This avoids presenting direct-link checks as another complete applicability check. The audit endpoint probe's success message now describes a match; mismatch diagnostics appear only for a mismatch.

The operator supplied real endpoint evidence for audit control 17.2.1: its numeric audit setting is 3 (Success and Failure), and the override value is 1. This establishes that the sampled endpoint value now matches. A refresh still marked scheduled is not inconsistent: scheduling telemetry does not establish completion of that particular refresh. Similarly, an active direct link does not establish effective filtering, the winning GPO or target RSoP. These are separate evidence claims.

## Repeated rollback

An operation with a completed backup can now be restored more than once. Each distinct submission requires ROLLBACK confirmation and passes the same authorization, change gate and serialized-operation checks. The service no longer returns the old ROLLED_BACK result without execution. The UI retains the restore form after a successful restore.

The worker records a post-restore fingerprint and attempt count in its protected manifest. A repeated restore must match the last recorded restored state under the GPO write lock. After successful restoration it records the new fingerprint. External changes still block full-GPO restore; this is not permission to overwrite unrelated later changes with an old backup. A legacy restored manifest without the new fingerprint is compared against the full recorded pre-change content, CSE metadata and original link state before migration. Metadata not captured by old releases cannot be independently reconstructed.

Completed batch recovery can also be submitted again using a new request ID. Queued/running recovery remains blocked and request-ID idempotency remains in force. Recovery still uses the first full-GPO backup, with the final publication anchor for the first recovery. Later repeats use the verified restored baseline. Individual records from a multi-control batch must still be restored through Workflow center batch recovery. No Apply replay or redo operation is introduced.

Interrupted/incomplete recovery and detected drift still require review. Backup, audit journal and operation stage records are preserved. Restore affects the entire recorded GPO snapshot and selected link, including their original full scope. No production restore was executed during this repair.

## Upgrade and validation

Stop the old application, extract the new package and launch GpoRemediator.cmd. Confirm version 3.12.3. Existing configuration and backups remain available. Use the operation's rollback form, or the original apply workflow's batch recovery action, for subsequent confirmed restores. Each submission uses a new workflow request ID; resending an identical request ID intentionally returns the original job.

Local verification includes real worker execution against isolated restore fixtures for second/third restores, baseline migration and external drift rejection, asynchronous batch recovery regression, and browser tests for repeated confirmation and advanced dropdown behavior. No credential-based production AD/GPO execution was performed. Dated command results are in `docs/audit/3.12.3-test-results.json`.

During validation, the old frontend contract test initially rejected the newly required repeat-rollback form. Its assertion was updated to require that form while still rejecting active, drifted and batch-child states. An added mobile browser check then detected that the dropdown could extend left of the viewport after wrapping. Mobile positioning was anchored to the tab bar and the actual menu bounds/clickability were re-tested. These intermediate failures are not counted as a passing final suite.
