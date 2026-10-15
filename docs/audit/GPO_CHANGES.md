# GPO change tracking

## A. Actual Active Directory changes

**NO LIVE AD GPO OBJECTS WERE MODIFIED.**

No Backup-GPO, Restore-GPO, Set-GPRegistryValue, Set-ADObject, New/Set/Remove-GPLink, Invoke-GPUpdate, auditpol /set, secedit /configure, or production launcher was executed against a real AD/endpoint policy during this audit. Native command names in regression output are mocks operating on isolated fixtures. Separate native read-only probes were auditpol /get (insufficient privilege) and Get-NetFirewallProfile ActiveStore (local read succeeded; no selected-GPO attribution).

| Domain | GPO name/GUID | Target | CIS ID | Before/after | Time/operation/backup | Verification/rollback |
|---|---|---|---|---|---|---|
| None | None | None | None | None | None | Live testing not performed |

## B. Software implementation changes

Mapping metadata changed for exactly 19 controls: 2.3.6.5, 2.3.7.3, 2.3.7.6, 2.3.9.1, 9.1.5, 9.2.5, 9.3.7, 18.5.9, 18.5.12, 18.9.25.5, 18.9.25.6, 18.9.25.7, 18.10.26.1.2, 18.10.26.2.2, 18.10.26.3.2, 18.10.26.4.2, 18.10.57.3.10.1, 18.10.93.4.2, 19.7.44.2.1.

All 394 automatic controls use the repaired common verification/evidence path. A complete list is in AFFECTED_CONTROL_IDS.csv; no control is omitted because it is difficult or unsupported. The defect-to-file/test map is in ALL_DEFECTS_AND_FIXES.md and SOURCE_CHANGES.csv. Source edits are not actual AD GPO changes.

Snapshots from prior mapping hashes remain recoverable. Non-recovery operations with changed mappings require a fresh preview; existing GPOs are not changed by installing this code.
