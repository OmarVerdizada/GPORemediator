# GPO Remediator 3.18.3

Rollback reports **GPO snapshot restored** after confirming the saved GPO, links and any captured AD domain policy values. For new Apply operations, the backup manifest also records readable pre-change values from a bounded sample of up to five authorized endpoints. The first rollback receipt is rechecked after the snapshot restore and any requested refresh. Endpoint readings are compared with the recorded pre-change readings for the same host and policy fields. A measured mismatch requires review while the snapshot retains its restored state.

For 2.3.10.4, the worker reads the endpoint's `DisableDomainCreds` DWORD directly. It distinguishes 0, 1, an absent value, and unavailable evidence. A restored GPO can leave the endpoint DWORD at 1. Windows requires a restart before Credential Manager uses a changed value. [Microsoft's policy reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication)

For older records or unreadable endpoints, the result shows the current observation and marks endpoint rollback unverified. Sample agreement concerns the measured readings. Full scope and runtime enforcement require their own evidence. A batch restore verifies the complete GPO snapshot, while its endpoint sample is for the first restored control.

If a device retains the applied setting, confirm the intended pre-change setting from the backup or your approved baseline, verify which GPO applies to that device, and review any explicit corrective Apply using the original scope. Request policy refresh and any required restart through the normal change process. Re-check the endpoint before rescanning in SecHard.

All 75 checks passed, including 405 controls across 413 Apply and rollback scenarios and 1,169 endpoint comparisons. The worker reproduced a restored 2.3.10.4 GPO with a retained endpoint DWORD in the fixture. The development Windows registry read used the native probe. Production AD and SecHard were outside the test environment. [Command results](audit/3.18.3/test-results.json)
