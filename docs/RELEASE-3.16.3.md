# 3.16.3 — native account evidence and endpoint disk failures

## Built-in account verification

Guest status (2.3.1.2) and built-in account rename controls (2.3.1.4/2.3.1.5) are verified against the live local account, identified by RID 501 or 500. The account can already have a different display name. A missing `EnableGuestAccount` line in a secedit export is not used as the account's live state.

The endpoint probe reads local SAM accounts with Get-LocalUser. A bounded local-only CIM fallback is available when the LocalAccounts command is unavailable; that fallback refuses domain controllers. Domain principals, missing or ambiguous accounts, unknown enabled flags and failed reads remain insufficient evidence. Account checks create no temporary security-policy export. Generated manual checks use the same RID-based account identity and preserve the wrong-host terminating guard.

Matching local account state does not establish which GPO caused it. A configured GPO value, an applied-GPO list, a completed refresh and winning-policy attribution remain separate evidence claims. A previous failed refresh remains visible even if the account is now disabled.

## WinRM failure classification

Windows disk-full errors 112 and 39 are reported as **ENDPOINT_DISK_FULL**, with guidance to inspect the endpoint's system/profile/temp volumes and quotas. TCP/5985 reachability and a running WinRM service do not prove that a PowerShell host process can start.

No automatic cleanup, volume changes or permission grants occur. Restore adequate free space through normal storage administration and repeat the same-credential remote test from the selected DC. Free space on a different volume is not automatically available to the system/profile volume.

## Delegated endpoint access

GPO edit and link delegation do not grant endpoint PowerShell access. Inspect the endpoint's actual Microsoft.PowerShell session ACL. If it explicitly permits Remote Management Users, an operator's membership in that local group can grant session access without making the operator a local administrator. The privileges required by each native command remain separate. Logon restrictions, credentials and token membership can also affect access.

Get-LocalGroupMember can fail on unresolved member SIDs. A read-only `net.exe localgroup` query using group names resolved from SIDs 544 and 580 provides an alternative inspection path. Group-query failure is not evidence that the group is empty; do not delete unresolved principals merely to make enumeration work.

## Validation

Actual worker probes were executed with isolated SAM/CIM/remoting fixtures: renamed disabled Guest, enabled mismatch, account renames, denied and missing reads, unknown flags, domain identity rejection, ambiguous identity, bounded fallback and domain-controller refusal. The all-mappings endpoint fixture covers 394 passing controls and 806 synthetic equality/inequality cases. All 405 manual check commands parse in Windows PowerShell 5.1; the generated Guest check was executed against a native-command double. No target AD or SAM was modified by these tests.

References: [local account SIDs](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts), [Get-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser), [Win32_UserAccount](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-useraccount), [Windows error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-), [group enumeration issue](https://github.com/PowerShell/PowerShell/issues/2996).
