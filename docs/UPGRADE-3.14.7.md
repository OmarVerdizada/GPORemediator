# Upgrade to 3.14.7

1. Stop the workspace through the old Local Control Center. Close that Control Center and any old launcher windows.
2. Extract the complete new ZIP into a new folder. Keep the existing ProgramData database, configuration and backups. Do not combine old Control Panel/launcher scripts with the new runtime.
3. Run the new folder's GpoRemediator.cmd using the normal application administrator identity. Confirm 3.14.7 in the browser footer.
4. Sign in with the delegated domain execution account and run Check connection again. Backup diagnostics now name the selected DC, account and execution workspace.

Both startup paths preserve the administrator-managed Backups ACL. On the machine hosting this ProgramData tree, startup repairs inheritance on backup descendants that match the old private-state ACL exactly. Custom ACLs are retained.

If a previous build already removed the repository's delegated grant, an administrator must restore that root grant once on the selected DC. Use the intended operator group, not a broad Domain Users/Authenticated Users grant. For the previously configured deployment:

```powershell
$path = 'C:\ProgramData\GpoRemediator\Backups'
New-Item -ItemType Directory -Path $path -Force
icacls.exe $path /grant:r 'PROSOL\GG_GPOR_Operators:(OI)(CI)(M)'
```

Do not repeat this on each restart. If it disappears again, inspect whether an old Control Panel/launcher or another ACL-management policy is still running. A management host's C: drive is separate from the selected DC's C: drive.

For password/lockout controls, choose a computer OU for local member-computer accounts or the domain root for AD domain accounts. An OU GPO does not give different domain-user password policies. Use AD fine-grained password policies assigned to users/global security groups for that requirement.

Verify a dedicated pilot GPO with the real execution account before a production rollout. Offline regression tests and a successful backup probe do not establish endpoint convergence, effective delegation or live Restore-GPO authority.
