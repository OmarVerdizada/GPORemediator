# Remediation audit — 3.10.0

## Scope classification

The 405 controls are validated as 385 computer, 12 user, and 8 domain controls. Registry hive and declared processing scope must agree: user controls use HKCU and computer controls use HKLM. User policy links target a user OU, while optional immediate refresh targets a separate endpoint computer OU. A concrete enabled user inside the selected user OU is required for exact HKCU endpoint evidence.

This release reviewed the complete 405-control catalog from mapping generation through write, read-back, refresh, verification, rollback and UI evidence. The supported boundary remains 401 automated GPO remediations and four guided controls: `1.2.3`, `2.3.11.6`, `18.10.43.10.1` and `18.10.43.10.2`.

## Corrected mappings

| Control | Correction |
| --- | --- |
| 2.3.1.2 | Moved Guest account status to `[System Access] EnableGuestAccount=0`. |
| 2.3.10.1 | Moved anonymous SID/name translation to `[System Access] LSAAnonymousNameLookup=0`. |
| 2.3.17.8 | Corrected UAC virtualization Enabled value from `0` to `1`. |
| 18.4.4 | Added both native and `Wow6432Node` WinVerifyTrust paths as documented string values and marked restart required. |
| 18.6.9.1 / 18.6.9.2 | Replaced LLTD option values with the actual `EnableLLTDIO` and `EnableRspndr` policy switches. |
| 18.6.14.1 | Added both `NETLOGON` and `SYSVOL` hardened UNC paths. |
| 18.6.19.2.1 | Corrected `DisabledComponents` to the TCP/IP v6 parameters path and marked restart required. |
| 18.6.20.1 | Reduced Windows Connect Now remediation to the authoritative `EnableRegistrars=0` switch. |
| 18.6.21.2 | Corrected the non-domain-network block value from `0` to `1`. |
| 18.9.23.1 | Added the policy enable switch together with the Automatic device-certificate authentication choice. |
| 18.9.25.1 / 18.9.25.2 | Corrected Windows LAPS AD backup to `BackupDirectory=2` and the password-expiration protection value name. |
| 18.10.43.17 | Replaced an unrelated Defender exclusion setting with `DisableAntiSpyware=0` and documented runtime-verification limits. |
| 18.10.93.4.2 | Added the required 180-day feature-update deferral value. |

The reviewed corrections live in `backend/data/mapping_sources/reviewed-overrides.json`. The generator applies them deterministically and supports `--check`, so a future regeneration cannot silently restore the old mappings.

## Execution and evidence corrections

- Controls whose benchmark wording says **include** now preserve stronger existing deny-right principals and audit bits. Adding Guests no longer removes other denied groups; adding Success auditing no longer removes Failure auditing.
- Registry publication verification checks the registry value type as well as its data.
- A lockout threshold of `0` no longer passes a “5 or fewer, but not 0” comparison.
- Effective security-policy verification exports merged domain and local policy with `secedit /mergedpolicy`, checks native exit codes, resolves account names to SIDs and treats absent or unreadable evidence as pending/unavailable instead of compliant.
- Endpoint sampling is limited to in-scope, allowlisted hosts. A PDC selected only as a refresh target is not automatically treated as evidence for another OU.
- `Invoke-GPUpdate` is represented as **scheduled**. The application waits for the server-managed follow-up verification schedule before claiming endpoint convergence.
- The result view shows the observed endpoint value and guidance for `gpresult`, competing GPOs, restart and logon requirements. An endpoint-only mismatch does not suggest rewriting an already matching GPO.
- Catalog upgrades invalidate stale Apply/Verify/Refresh plans while preserving access to their full-snapshot rollback. Verification and refresh remain available after that snapshot has been restored.

## Validation coverage

- The Windows authentication and other bundled .NET packages are pinned to the 10.0.13 security servicing release; the vulnerability audit must return no advisories.
- All 401 automated mappings are exercised offline for initial mismatch, write, read-back, idempotence and endpoint-recipe serialization. The four guided controls are asserted as non-automatic.
- Independent regression assertions pin every corrected key, value and multi-value mapping.
- Installed Windows ADMX files are used for a read-only address and simple Enabled/Disabled cross-check. The audit records source hashes and currently matches 221 catalog controls that map directly to those templates.
- Endpoint tests cover merged-policy export, native command failures, missing values, SID order, stronger deny/audit sets, scope boundaries and asynchronous refresh semantics.
- Backend, security, workflow, frontend and browser tests remain part of CI.

## Acceptance boundary

These tests do not write to a live Active Directory domain. A release operator must still run a pilot against the exact target Windows Server version, Central Store ADMX version and installed roles. Verify AD/SYSVOL convergence, `gpresult`/RSoP, service state, Defender status, restart/logon effects and application compatibility before broad deployment. Registry policy evidence alone is not proof that a service or security engine is enforcing the setting.

Primary behavior references used for the review include Microsoft documentation for `secedit /mergedpolicy`, Windows LAPS policy values, `Invoke-GPUpdate`, Windows Update for Business and WinVerifyTrust signature validation.
