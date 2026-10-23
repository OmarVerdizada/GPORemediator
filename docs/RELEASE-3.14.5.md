# 3.14.5 — Delegation and recovery audit

The selected-target preflight now checks `GPT.INI`, the file actually written by the selected handler (`Registry.pol`, `GptTmpl.inf`, or `audit.csv`), and the nearest existing parent directory needed to create or replace that file. Unrelated files in the GPO no longer cause false access denials. Effective Windows ACL checks and AD `allowedAttributesEffective` checks remain in force.

New operation manifests record both machine and user CSE extension metadata. Rollback verification compares both; old user-policy manifests without a recorded user CSE baseline cannot be certified as restored through the legacy snapshot comparison.

Automatic rollback still calls `Restore-GPO`, which restores the GPO ACL as well as settings. The read-only inspection proves drift status, not restore permission. Preview and rollback inspection now say so explicitly. Standard GPMC **Edit settings** may be sufficient for Apply but cannot be treated as proof that `Restore-GPO` will succeed. Pilot an actual Backup → Apply → Rollback cycle on a disposable GPO with the delegated execution account, or arrange administrator-assisted recovery. Do not grant broad domain or SYSVOL rights merely to silence this warning.

The attached external conversation used `gpor.remediator`, while prior successful WinRM evidence named `PROSOL\gpor.operator`. Confirm the exact account shown by the application's execution identity before troubleshooting delegation. A failed `Get-ADObject` followed by `True` from an old `$access` variable is not a valid effective-access result.

Offline regression and package tests do not establish live AD behavior, including remoting, ACL restore, replication or endpoint policy application.
