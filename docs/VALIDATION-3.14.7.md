# 3.14.7 validation

Final result: 47 checks passed, zero failed. Live AD: not run.

The complete audit suite was run; after the final fixes, affected builds/regressions and source/package compatibility were rerun. Machine-readable command results and log hashes are in the accompanying audit command results JSON. These are command-level counts, not counts of live AD operations.

Relevant evidence:

- Control Panel and launcher initialization are parsed from their real entry points and executed against an isolated NTFS tree. Delegated backup Modify survives both. Legacy protected backup descendants inherit it after migration; custom ACLs remain unchanged.
- Native Windows effective access tests cover read-only, standard GPMC rights, deny-over-allow, atomic-write fallback, broad read-only backup access and a root-write/child-denied backup workspace.
- The real worker dispatcher runs Preview, readiness, Backup, Apply, Link, publication verification, explicit refresh scheduling, Rollback and rollback verification against real private files with mocked AD/GPMC/DNS calls. It covers domain and local account security templates, registry, registry sets, advanced audit and user policy. A forced backup denial remains FAILED_SAFE with stage-specific guidance.
- All 394 automatic mappings are exercised by writer/read-back/idempotence and endpoint recipe tests. Eleven guided controls retain their explicit automatic-execution boundary.
- Browser tests click actual GPO/OU selectors and Generate plan for password/local-account, registry, audit, user and organization-input controls. A delayed denial for the same target cannot remove a newer preview. Existing recovery, workflow, targeting and theme browser checks also pass.
- .NET workflow/security regressions, manual procedures, PowerShell 5.1 and frontend syntax, mapping/scope checks, secret scanning, dependency advisory checks and packaged-source fingerprints pass.

No disposable live domain credentials or isolated production pilot were supplied. Native Backup-GPO/Restore-GPO authority, remote delegation, AD/SYSVOL replication, RPC refresh and actual endpoint policy processing still require a live pilot. Synthetic endpoint/GPMC fixtures are not evidence that the selected GPO won on the user's machines.
