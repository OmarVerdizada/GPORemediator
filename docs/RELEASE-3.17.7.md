# GPO Remediator 3.17.7

Interrupted publication checks no longer permanently lock a successfully configured control out of refresh. The worker saves a durable post-write fingerprint before assurance. Read-only Verify can certify the current requested GPO/link without replaying Apply; full rollback requires its own independent post-state proof. An original publication failure is retained in the backup manifest and recovery receipt.

For eligible pre-3.17.7 numeric domain security-template records, a missing anchor may be recovered only after validating the complete retained policy backup against the original full-tree hash, proving the exact intended template delta, unchanged linked-scope membership/selected links, CSE state and recorded AD value. Unrelated changes, corrupted backup content and missing proof block automatic full restore. Current live publication/refresh can still be verified independently. Inspection explains an unanchored post-state instead of silently offering a restore.

Local GPT.INI access and version parsing are isolated probes. Temporary file locks receive bounded retries; unreadable/invalid metadata stays explicitly unverified with a safe diagnostic instead of terminating publication with an opaque method exception. Signed/unsigned AD version forms normalize without nested BitConverter calls.

Rollback now returns actual AD values and the saved restoration target immediately and on later verification/refresh. Failed restore attempts keep their target and actual-value evidence; read-only Verify does not disguise them as successful Apply. The result page offers rollback review rather than a repair plan for the original forward value. If the saved GPO and AD values differed before Apply, recovery shows this difference before optional gpupdate because policy processing can apply the saved GPO value again.

Focused fixtures reproduce the publication failure, recover both checkpoint and legacy records, allow explicit refresh, restore AD 15 to 30 and preserve unrelated settings. They also reject corrupt backups/external changes and retain denied-rollback evidence. Real private-file GPT locks and actual Chromium cover metadata diagnostics and result/action behavior. Directory, GPMC and endpoint calls are mocked; no live AD success is claimed.

After updating, open the original interrupted operation and select Re-verify live state. For rollback, open its Operations details and select Check rollback availability before confirming restore. A newer NO_CHANGE plan has no new backup and does not replace the original operation's retained snapshot. Unproven legacy snapshots remain blocked with a recovery reason.

Backup contents are checked using the [Microsoft-documented SYSVOL security-template layout](https://devblogs.microsoft.com/powershell/new-group-policy-cmdlets-for-nano-server/); native restore still uses [Import-GPO](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/import-gpo).
