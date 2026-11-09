# GPO Remediator 3.18.1

Apply results distinguish saved GPO settings, endpoint values that match, and checks that are incomplete or show a mismatch. Bulk verification records the remaining controls after a measured endpoint mismatch and reports the affected CIS IDs.

| CIS controls | Defect reproduced in the verifier | Correction |
|---|---|---|
| 5.2 | The startup registry value could match while Print Spooler was still running. | Read the service startup mode and state using Win32_Service. The disabled recommendation requires a disabled startup mode and a stopped service. |
| 18.10.43.6.1.2 | ASR registry settings could match while Defender reported different actions. | Compare each selected rule GUID and action with Get-MpPreference. |
| 18.10.43.6.3.1, 18.10.43.10.5, 18.10.43.16 | Matching registry entries were sufficient for an endpoint match. | Also compare the network protection, script scanning and PUA values reported by Get-MpPreference. |
| 18.10.43.10.2, 18.10.43.10.3, 18.10.43.10.4, 18.10.43.17 | Matching registry entries were sufficient for an endpoint match. | Read the corresponding IOAV, real-time, behavior monitoring and antivirus status from Get-MpComputerStatus. |
| 9.2.4, 18.1.1.1, 19.7.5.2 and other registry-backed controls | Windows PowerShell 5.1 reports a missing value under an existing key as an argument error. The verifier treated it as an unreadable result. | Report the missing value as a mismatch. Preserve unavailable results for actual read failures. The listed IDs exercise the firewall, computer and user probe paths. |
| Shared verification | The first endpoint mismatch stopped later batch checks. A sample flag could also overstate coverage when a record had a larger pinned target list. | Retain mismatches by control and finish the remaining read-only checks. Require complete, unique evidence when a pinned target count is recorded. Keep out-of-scope hosts visible. |

The additional provider reads are read-only. An unavailable Defender or service provider produces unavailable evidence when the registry matches. Registry equality for other controls remains a measurement of the corresponding endpoint policy values. Historical results reflect the probes that ran at the time. Use a new Verify to collect the updated evidence.

The nine new provider paths returned readings on the development Windows host. The regression fixtures separately cover matching registry entries with mismatched or unavailable provider results. [Microsoft Defender preferences](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell) and [Defender protection status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2019-ps)

The checked-in CIS v4.0.0 catalog contains 405 controls across seven populated sections. The per-control audit covers policy scopes, the native worker against directory fixtures, and endpoint comparisons against native API fixtures. Results from those tests cannot identify which GPO won on a particular production host or reproduce a SecHard result from a different environment.

The current source review found no recipe drift. It found local configuration references for 302 controls and retained 11 guided entries. For the 92 entries whose references are absent from the current inputs, the reviewed recipe fields match the archived primary-reference audit. [Archived Server 2019 mapping review](mapping-audit/3.16.6/README.md)

The final regression run covers 413 Apply and rollback scenarios and 1,169 endpoint comparisons. The initial scope assertion and subsequent passing run are both recorded. [Control-by-control results](audit/3.18.1/controls.csv) and [command results](audit/3.18.1/test-results.json)
