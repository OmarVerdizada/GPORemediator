# Selected-user password pilot

Current release scope: six password settings, one explicitly selected non-privileged domain user per plan. Other modules are retained for later development and their write endpoints are blocked. The old benchmark catalog remains embedded for compatibility, not as an assertion of current adapter support.

## Workflow and identity

Setup discovery reads the management computer's domain membership, PDC hostname, management hostname, process identity and certificate availability. It is cached in memory per service process and does not enumerate domain computers/users or run compliance checks. Saved configuration and manual edits are not overwritten. The UI runs discovery when Settings is first opened, and only reads the selected user's policy when Plan is clicked.

Windows mode requires HTTPS, Windows Integrated Authentication and an operator allowlist. The process identity executes AD commands. Default-domain GPO GUID, OU and host allowlists are not relevant to a user-scoped PSO and are cleared on pilot setup save. Saving always disables writes. No credentials or arbitrary PowerShell are accepted by the browser.

PowerShell is invoked noninteractively using only the bundled script and structured stdin. ExecutionPolicy Bypass is process-scoped for these local scripts, never a persistent machine policy change; centrally enforced policy still applies.

## Supported changes

History, maximum/minimum age (whole days), minimum length, complexity and reversible encryption. Suggested values in the UI are editable demonstration defaults, not licensed benchmark values. The selected user's entire effective password/lockout tuple is read using Get-ADUserResultantPasswordPolicy, falling back to Get-ADDefaultDomainPasswordPolicy when no PSO applies. All unselected fields are copied exactly. Fractional-day password ages are rejected instead of rounded.

A new PSO named `GpoRemediator-Pilot-<plan-id>` is created with precedence 1000 when there is no effective PSO, otherwise current precedence minus one. Precedence 1 conflicts require administrator review. The exact user GUID receives a direct assignment; no group, domain-default, OU or GPO is modified. Protected accounts (adminCount=1 and built-in Administrator/krbtgt) are excluded from the pilot. Account password-never-expires flags and passwords themselves are not modified.

Source fingerprint covers user GUID, DN, source PSO, precedence and all captured values. Preview expires after 15 minutes. Apply rechecks the snapshot in C# and again in PowerShell immediately before assignment. AD has no transaction covering external administrators' concurrent changes; remaining race/replication risks are surfaced through verification and recovery rather than claimed atomicity.

## Persistence, concurrency and recovery

The server stores previews and execution records in dedicated SQLite tables. A lifecycle gate prevents overlapping pilot writes and launcher stop/restart during Apply/rollback. The request continues independently of browser disconnection. Duplicate Apply returns the stored record without replay. A crash can leave APPLYING/ROLLING_BACK in history; it is never automatically resumed. A partial or timed-out write requires inspection/recovery.

Before the first AD write, an exclusive new JSON backup is flushed under `<BackupPath>\PasswordPilot\<plan-id>.json`. Directory permissions restrict access to the service account, SYSTEM and local Administrators. It contains the original effective policy and user identity, not a user password. Backup failure prevents PSO creation.

Rollback validates the exact generated name, ownership description, precedence, complete values and assignment list. Shared or edited PSOs are blocked. A later effective policy blocks removing an older assigned PSO. Roll back changes newest first. Empty PSOs from interrupted assignment can be removed using their plan. Only this operation's PSO is removed; the prior PSO is never restored by overwriting it. Resultant source and all original values are checked afterward. If the prior policy changed externally, the result is ROLLBACK_REVIEW_REQUIRED.

If the service is unavailable, run the shipped recovery helper with the backup file from the management host under an authorized AD identity. It prompts before removal and uses the same constrained rollback checks:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Recover-PasswordPilot.ps1 -BackupFile 'C:\ProgramData\GpoRemediator\Backups\PasswordPilot\<plan-id>.json'
```

Offline recovery does not rewrite application history; its JSON result is the recovery evidence. The next UI rollback checks current state before updating the record. Do not edit backup files or use them as a source of script text.

## Test-domain acceptance

1. Use a separate non-privileged test user with no precedence-1 PSO. Record the existing resultant/default policy with AD tools. Do not use a domain administrator as the target.
2. Launch on a domain-connected management host. Check detected domain/DC/operator and management DNS name. Install an enterprise-trusted HTTPS certificate in LocalMachine/My with private-key access for the process identity. The launcher provisions RSAT if missing; no certificate or AD delegation is silently created.
3. Save, restart, verify real Windows mode, check readiness, enable writes. Readiness checks connectivity, not delegated write rights. Grant PSO create/delete and assignment permissions through your AD administration process if needed.
4. Select a failed SecHard password setting and the matching desired value. Confirm preview names only the intended user. Check all other values remain identical.
5. Apply. Confirm exactly one new PSO and one direct user assignment. Independently check `Get-ADUserResultantPasswordPolicy` on the configured DC. Confirm domain default and a second user's policy are unchanged.
6. Check replication and rerun the relevant SecHard user-scoped check. A domain-default GPO check will not be remediated by this user-scoped pilot.
7. Roll back and confirm original effective values/source. Repeat with an existing PSO. Test stale plans, insufficient rights and an edited/shared pilot PSO; they must fail without claiming success.

Automated validation uses a separate Mock database, C# invariant tests and the actual PowerShell dispatcher with simulated AD cmdlets. This is not live-domain certification.

Microsoft references: [Fine-grained password policies](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies), [Get-ADUserResultantPasswordPolicy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduserresultantpasswordpolicy), [New-ADFineGrainedPasswordPolicy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adfinegrainedpasswordpolicy).
