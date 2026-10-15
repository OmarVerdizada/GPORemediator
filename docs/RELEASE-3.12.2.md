# 3.12.2: effective advanced-audit evidence and verification colors

The affected host returned `No Auditing` from native `auditpol /get`. The previous endpoint verifier assumed that `/get /r` always included the seven-column numeric backup schema. Windows may instead return a five-column report ending in a localized Setting string. This incorrectly produced PENDING rather than an observed mismatch.

The endpoint probe now uses `auditpol /backup /file:<unique temporary CSV>` to read the numeric, restorable audit configuration, selects exactly one system-policy row by the requested GUID, compares numeric masks and removes the temporary export even on failure. Per-user rows, missing/duplicate GUIDs, failed commands and invalid or unchanged values do not produce verification. Export requires appropriate audit-policy permissions; failure remains pending with a permission diagnostic. The operation does not restore or change audit policy.

The old writer quoted every CSV field. MS-GPAC permits a quoted Subcategory, but requires literal System, GUID and numeric Setting Value tokens. The writer now emits that format and, during an approved audit apply, normalizes existing system rows while preserving their numeric settings. A GPO containing the old quoted rows now requires repair even when its parsed value already equals the requested value. Generic CSV parse/read-back tests had missed this protocol-format defect; dedicated literal-token and legacy-row repair tests now cover it. Whether it caused this particular host to ignore the file still requires live verification.

The GPO publication check now also requires the audit client-side extension and tool GUID pair. A matching `audit.csv` without this metadata no longer produces NO_CHANGE: an approved apply repairs the metadata and increments the computer policy version. Existing backup, scope, approval and drift protection remain in effect. Explicit None is serialized as MS-GPAC Setting Value 4; value 0 means unchanged and is no longer interpreted as an explicit disabled audit policy.

Audit preview warns about the separate subcategory-override control 2.3.2.1. Endpoint evidence reads `SCENoApplyLegacyAuditPolicy`; manual commands show the human-readable GUID query and this registry value. No additional control is silently applied. A matching GPO value still cannot establish the winning policy or processing completion. If the endpoint remains No Auditing, inspect actual override, competing GPOs and GroupPolicy events on that host. The user confirmed SCENoApplyLegacyAuditPolicy returns 1, so a disabled override is not established as the cause on that host. Its specific cause of endpoint non-application still requires validation after repairing the identified CSV-format defect.

Verification stages now use green verified, amber scheduled/pending/evidence-needed, red observed mismatch/failure and neutral unverified cards. Icons and short localized labels supplement color for accessibility. Raw status codes and technical evidence are under an expandable explanation; a scheduled refresh never appears completed.

## Use

The operator supplied the affected GPO row and confirmed the all-quoted System/GUID/value format is present on that server. No host or domain identifiers are needed to reproduce it. This confirms the storage defect exists in the affected installation; successful endpoint processing after repair still needs to be observed there.

Stop the old application, extract the new package to its own folder and start `GpoRemediator.cmd`. Confirm UI version 3.12.2. Existing 3.12.1 [emergency-stop instructions](RELEASE-3.12.1.md) still apply. Create a fresh preview before applying an audit control; old plans can legitimately fail source/fingerprint checks after an upgrade. Re-verify after endpoint policy processing. ProgramData configuration, database and backups do not need deletion.

No production AD/GPO changes or credential-based domain tests were performed during this repair. Local test evidence is recorded separately in `docs/audit/3.12.2-test-results.json`; it does not certify live policy processing.

One first-pass browser regression failed because it still selected the former stage divs after the renderer changed to article cards. The selector now follows the stage class and checks actual distinct border colors and hidden technical codes. The test runner also records native stderr failures without aborting before writing their result. A later warning-text edit produced a PowerShell quoting error; the syntax check caught it, it was corrected, and the interrupted run was discarded. Final results are listed separately; incomplete runs are not counted as passing suites.

## Primary references

- [Microsoft: auditpol get report format](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get)
- [Microsoft: auditpol backup and permissions](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-backup)
- [MS-GPAC: CSV grammar](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/6494a0f2-8a16-40e2-b87d-328be7d732e0)
- [MS-GPAC: numeric system audit settings](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/21ad2e80-3011-48ef-be13-cc11ff7bfeb1)
- [MS-GPAC: audit extension GUID pair](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/ac9c8234-d2e8-455d-be76-f84244dd1e58)
- [Microsoft: audit subcategory override](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override)
