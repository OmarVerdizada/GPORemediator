# 3.16.0 — permissions, policy evidence and complete-release updates

The **Access & evidence** workspace connects target permission checks and endpoint policy explanations. Operators can inspect exact GPO/OU/SYSVOL/backup targets and delegated rights, then compare logged per-setting RSoP sources with current native values and recent client processing events. Unknown evidence remains explicit; a matching value never proves its source.

FGPP previews now compare PSO subjects with current enabled OU users and the previous applied snapshot. **Compare current OU membership** creates a fresh unapproved plan; additions/removals still require explicit Apply and native drift checks.

Large operation, audit, GPO and OU lists use bounded pages. Cached OU indexes avoid rebuilding the directory on each search. The complete-release installer validates application manifests and the expected archive hash, preserves external state, refuses to interrupt active jobs and can reactivate a previous compatible version. The installed launcher validates the active release before startup.

A dedicated live-pilot runner covers baseline → preview → backup/apply → completed computer refresh → verification → guarded rollback → endpoint baseline comparison. Rollback computer refresh now completes across bounded pages and retains pinned targets. Pilot controls/targets are constrained and require an explicit command confirmation; credentials are prompted locally.

See [operating and update instructions](ASSURANCE-AND-UPDATES.md) and the [validation record](VALIDATION-3.16.0.md). The live AD environment is separate; **live pilot execution and runtime enforcement were not tested here**.
