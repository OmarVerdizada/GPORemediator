# 3.16.8 — effective domain account policy and focused results

The reported incident was a stored `LockoutBadCount=5` in Default Domain Policy while `Get-ADDefaultDomainPasswordPolicy` on the same domain controller returned `LockoutThreshold=0`. Version 3.16.7 left a measured domain mismatch in a generic pending state. A completed gpupdate process did not establish that the AD property changed.

Domain-account preview now records the actual AD value and its requested replacement. Apply requires a fresh matching AD snapshot and effective write authority for the exact domain attribute. After Backup-GPO, the approved setting is synchronized using `Set-ADDefaultDomainPasswordPolicy` and read back. The protected manifest retains the before/after AD property alongside the GPO backup. A GPO that already stores the requested value is not `NO_CHANGE` when its effective AD value still differs. OU local-account controls do not write domain account properties.

Rollback compares both the GPO snapshot and the recorded AD property, refuses external AD drift, checks domain write authority before importing, restores only the captured AD property, and verifies restoration. Older backups without an AD snapshot retain their original GPO-only restore behavior. Interrupted writes retain the pre-change evidence and require review; they cannot report success.

Verification returns the actual domain property and controller as measured evidence. A known mismatch produces `ENDPOINT_MISMATCH`, including the actual numeric value. Unavailable reads remain unavailable. Publication, replication and refresh completion remain separate facts.

The control workspace has one progress bar, one result heading, a before/requested/actual comparison, compact target metadata and direct repair actions. GPO values, native checks, per-host refresh and operation details are available below the measured result. Domain preview leads with the effective AD value. Known mismatches also replace the publication badge in Operations and the operation inspector. Sign-in and sidebar share the same shield mark; the sidebar toggle is aligned within the brand header. Explanatory scope text is collapsed instead of repeated in large cards. A copied-value notice expires automatically.

Regression fixtures reproduce GPO 5 / AD 0, effective writes/read-back, denied domain writes, external AD drift, snapshot rollback and desktop/mobile presentation. They do not establish the precise Windows processing cause of the original live discrepancy or certify live deployment success. The new domain write is explicit in preview and covered by the existing Apply approval.

Microsoft references: [Set-ADDefaultDomainPasswordPolicy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy), [MS-GPSB account lockout policy processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/563b4b54-b546-446b-af90-2847501d8989).
