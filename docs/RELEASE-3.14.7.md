# 3.14.7 — Backup access, OU targeting and remediation chain

- Both Control Panel and launcher now use one state initializer. The Control Panel's old recursive ACL reset was still removing backup delegation after the launcher fix in 3.14.6.
- Old backup descendants protected by the exact owner/SYSTEM/Administrators private-state ACL are migrated to inherit the repository ACL. Custom grants/denials are preserved. This fixes root-write readiness passing while Apply cannot create its GpoWorkflow execution directory.
- Broad read-only backup ACLs are accepted. Broad mutation rights remain blocked. Readiness reports the selected DC, execution account and backup path; disk capacity uses the local drive API.
- Password and lockout controls support two intents: local accounts in a computer OU, and AD domain accounts through a GPO at the domain root. An OU selection never silently changes domain-wide policy. Different AD user password policies require FGPP assigned to users/global security groups, not an OU GPO.
- Other computer/user controls can target a discovered OU or domain. Account policy badges and scope guidance no longer label all account controls domain-only.
- Local account mappings resolve consistently in the backend, manual procedures, batch previews and read-only scans.
- A delayed target-access response cannot clear a plan generated after that probe started.
- Apply failures retain their stage and product-owned diagnostic context. Interrupted writes retain their backup/manifest for review; they are not presented as success.

Validation includes the actual worker dispatcher with real private filesystem writes and mocked directory/GPMC commands: Preview, readiness, Backup, Apply, Link, read-back, Rollback and rollback verification for security templates, registry, audit and user policy. Browser tests click the actual OU/GPO pickers and Generate plan buttons, including a delayed permission denial on the same target.

These are offline/synthetic tests. They do not certify live AD permissions, replication or endpoint processing. A live pilot using the execution account is still required.

Upgrade the complete folder, including Control-Panel.ps1, GpoRemediator.ps1, scripts/Secure-Files.ps1 and the bundled runtime ZIP. Mixing old Control Panel files with a new backend reintroduces the ACL reset. If an old build already removed the root delegation, restore Modify once on the selected DC; the updated entry points preserve it thereafter.

References:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-policies
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies
