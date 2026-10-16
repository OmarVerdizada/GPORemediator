# Firewall mapping review, 2026-10-16

## Observed result and comparison limits

The supplied target output confirms Domain Enabled=True, DefaultInboundAction=Block, NotifyOnListen=False, the expected domainfw.log path and LogMaxSizeKilobytes=16384. Domain LogBlocked=False and LogAllowed=False do not satisfy 9.1.6 and 9.1.7. Their policy values were absent from the supplied registry output. This does not establish that those controls were applied or that the writer failed.

The application's supplied screen is 9.1.5 (Domain log size), and its VERIFIED sample agrees with the native 16384 value. The supplied SCeHard script is 9.2.4 (Private log path), a different setting. The target subsequently reports the PrivateProfile\Logging registry path missing. This does not establish a contradiction between the tools. The SCeHard audit/check script and the same control's scan result were not supplied.

The supplied SCeHard script writes configuration, suppresses errors and unconditionally exits zero. Its exit code alone cannot prove a successful write. It branches on Test-ComputerSecureChannel, which [Microsoft documents as inappropriate for domain controllers because it can return false positive errors](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-computersecurechannel?view=powershell-5.1). On a DC it may enter its local Set-NetFirewallProfile branch rather than its policy registry branch. This is a possible script issue, not a confirmed cause of this scan result. A missing Private policy key does not by itself prove its resultant local profile value; the supplied Format-List command had a trailing bracket in the property name.

Compare the same endpoint, control ID, profile, expected value, benchmark version and scan timestamp. The following commands are read-only; they compare Private log path only:

```powershell
Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name LogFilePath -ErrorAction Continue
Get-NetFirewallProfile -Name Private -PolicyStore ActiveStore | Format-List Name,LogFileName
```

A matching sampled endpoint configuration does not attribute the value to the selected GPO, prove packet-level enforcement, log file write permissions, or certify all rules in a profile. Inspect RSoP and policy processing when published and endpoint values disagree. Do not bypass GPO by writing local settings to make a scanner pass.

## Mapping review

All 23 controls use the appropriate profile under `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall`. Registry writes use Set-GPRegistryValue against the selected GPO/domain/DC; there is no live local firewall remediation in this application. Each Apply concerns the selected control. Registry.pol publication is distinct from the target's resultant [ActiveStore configuration](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile).

| Controls | Profile field | Registry type / desired | Endpoint field |
|---|---|---|---|
| 9.1.1 / 9.2.1 / 9.3.1 | EnableFirewall | DWORD 1 | Enabled=True |
| 9.1.2 / 9.2.2 / 9.3.2 | DefaultInboundAction | DWORD 1 | DefaultInboundAction=Block |
| 9.1.3 / 9.2.3 / 9.3.3 | DisableNotifications | DWORD 1 | NotifyOnListen=False |
| 9.3.4 | AllowLocalPolicyMerge | DWORD 0 | AllowLocalFirewallRules=False |
| 9.3.5 | AllowLocalIPsecPolicyMerge | DWORD 0 | AllowLocalIPsecRules=False |
| 9.1.4 / 9.2.4 / 9.3.6 | Logging\LogFilePath | String, domainfw/privatefw/publicfw.log | LogFileName, expanded case-insensitive comparison |
| 9.1.5 / 9.2.5 / 9.3.7 | Logging\LogFileSize | DWORD >=16384 | LogMaxSizeKilobytes |
| 9.1.6 / 9.2.6 / 9.3.8 | Logging\LogDroppedPackets | DWORD 1 | LogBlocked=True |
| 9.1.7 / 9.2.7 / 9.3.9 | Logging\LogSuccessfulConnections | DWORD 1 | LogAllowed=True |

Paths begin `%SystemRoot%\System32\logfiles\firewall\`. Microsoft specifies [REG_SZ for LogFilePath](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/e3c69589-ae53-45bb-8355-3084c1f3d481), [DWORD for LogFileSize](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/067ce0bf-d984-44cb-88b5-02725378eee1), [0=Allow / 1=Block for DefaultInboundAction](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/5f0dde47-6431-4561-8bac-2efe8465f1e3), and [the per-profile Logging key for dropped packets](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/1726ae36-5ec8-401a-b716-a8dd38218b41). Firewall policy uses [computer registry.pol via MS-GPREG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/39cc067f-ccac-4da4-bb7d-a42c3b08407e).

No mapping change is justified by the supplied comparison. Tests verify disabled logging remains MISMATCH even when log size passes, Private values remain independent from Domain values, equivalent path case is accepted, stricter log sizes are preserved, and unavailable/NotConfigured reads remain pending. These fixtures do not certify SCeHard behavior or a live domain.
