# 3.14.4 — Standard GPMC SYSVOL delegation

The selected-target access check now accepts the standard SYSVOL access granted by GPMC **Edit settings** delegation: Read & execute, Write, and Delete child. It no longer requires `Modify`, whose per-file Delete right is absent from a normal GPMC-managed GPO ACL.

Policy publication first attempts atomic file replacement. If Windows rejects `ReplaceFile` because the delegated account has the standard GPMC ACL without per-file Delete, the publisher performs an exclusive, flushed in-place write. This fallback runs only after the durable operation manifest and full GPO backup are committed. Deny ACEs and missing write access continue to block Preview and Apply.

Computer and user policy controls can target any discovered OU that the execution account may edit and link. A regression case now covers switching from the domain-account control to a different computer OU. Domain account password and lockout controls still use the domain root because linking those settings to an OU would not set domain-account policy for that OU's users.

## Upgrade

Pull `main` or replace the installation with the complete updated package and restart `GpoRemediator.cmd`. Existing GPMC **Edit settings** delegation is sufficient; do not grant broad Modify access to SYSVOL and do not enable domain-object password-policy write permissions for this workflow.
