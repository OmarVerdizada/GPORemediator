# 3.16.6 — review of all imported mapping sources

All 405 imported controls, grouped across sections 1–19, now have an individual configuration-source review record. The deployment target is Windows Server 2019, as confirmed by the operator. The review checks authored TSV records, explicit generator recipes, reviewed overrides, final mappings and policy references. It retains the boundary of 394 automated and 11 guided controls.

## Confirmed repairs

- **18.10.43.6.1.2 / ASR rule identity:** restored Office-macro Win32 API rule `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b`. An unrelated vulnerable-driver rule (`56a863a9-...`) had occupied its place. The 12 imported rule states now live in a dedicated source TSV and are checked against the catalog recommendation. Existing unrelated ASR entries in a GPO are preserved; changing this recipe does not remove them.
- **18.10.43.11.1.1.2 / feature identity:** the imported title requests Remote Encryption Protection, but the old address changed Brute Force Protection. It now writes `RemoteEncryptionProtectionConfiguredState` under `Remote Encryption Protection`. The selected value remains Block (1), stronger than the imported Audit-or-higher requirement. OS/Defender prerequisites remain separate.
- **Stale source records:** repaired old Guest/blank-password IDs, UAC Enabled value, cached-logon baseline, WinVerifyTrust value type, LLTD switches, IPv6 path, network blocking value, LAPS property name, Defender property and two orphan User-control IDs. Security-template settings no longer retain misleading registry source rows. Inline LAPS backup and Windows Connect Now recipes were also aligned with the reviewed result instead of depending on a later correction to hide an incorrect intermediate recipe.
- **Generation:** unknown IDs, missing required source files, invalid column counts, duplicate source records and invalid ASR records now fail generation instead of being ignored or silently overwritten.

## Applicability and dependencies

Additional plan warnings clarify ASR activation, Point and Print parent/update behavior, VBS/Secure Launch dependencies, scheduled update mode and longer password prerequisites. Microsoft documents the WMI-event-subscription ASR rule as requiring Server 1903 SAC or later; Server 2019 LTSC build 17763 is not equivalent. A written registry value cannot establish that an unsupported engine is enforcing a rule.

See [the review index](mapping-audit/3.16.6/README.md), [all 405 controls](mapping-audit/3.16.6/mapping-review.csv) and [exact effective mapping changes](mapping-audit/3.16.6/mapping-changes.json). Empty catalog headings in sections 3, 4, 6–8 and 10–16 are explicitly recorded as zero controls.

## Validation and limits

The real writer/read-back fixtures cover 394 automatic recipes with 11 guided boundaries and no failures. Real verifier fixtures cover 806 synthetic equality/inequality cases. All 800 published manual procedure variants parse in Windows PowerShell 5.1; offline execution scenarios cover each writer family, backup ordering, cancellation, idempotence, drift and failure. Independent source-corruption tests reject orphan/duplicate/missing sources, wrong recipe identity, scope/type/value errors and audit-mask disagreement.

The audit uses Microsoft's Windows Server 2019 Security Compliance Toolkit data, installed/custom Microsoft ADMX data, native read-only audit subcategory listings and cited Microsoft policy documentation. Microsoft baseline recommendation values are not substituted for the imported CIS requirements. The exact original CIS product/version document has not been independently bound to this imported subset. This release does not certify full CIS coverage, compatibility with every Server 2019 build/role, or live AD/endpoint enforcement.

Deploy the complete package. Mapping changes can invalidate stale execution plans; prepare and review fresh plans. Existing GPOs are not automatically changed by upgrading, and snapshot rollback retains its normal drift/context checks.
