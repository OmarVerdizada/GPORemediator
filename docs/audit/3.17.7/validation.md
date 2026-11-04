# 3.17.7 validation

All 72 commands in scripts/Invoke-FullAuditTests.ps1 passed on their final runs. The final package was rebuilt after the generalized rollback display fix. The mapping fixture initially lacked a GroupPolicy inheritance mock needed by the new rollback link evidence; adding that mock and rerunning the unchanged production path passed. Original command records and hashes remain in initialAttempt. The exact worker fixture matrix covers 405 controls in 413 scope cases; the endpoint matrix covers 1,148 cases. Per-command hashes, per-control results and selected output are retained here.

Publication recovery fixtures inject a failure after GPO/link/AD writes, verify the durable checkpoint and certify the current state without replaying Apply. Legacy records without the checkpoint must prove the complete retained backup and exact numeric security-template delta. Unrelated GPO changes, corrupt backups and external AD changes cannot authorize an automatic full restore. Current publication and explicit refresh remain separate from full-snapshot restore authority.

The focused recovery cases restore AD 15 to 30 and read the restoration target and actual AD value back. A denied pre-import rollback preserves its original phase for retry; read-only Verify reports rollback review rather than disguising the failed restore as successful Apply. Different pre-change GPO/AD values are exposed before optional gpupdate.

Real private-file GPT.INI locks exercise bounded read retries and explicit unavailable metadata. Invalid and signed/unsigned version forms are covered. Actual Chromium checks publication recovery, refresh eligibility, confirmed restore and the displayed actual AD value. The included screenshot uses synthetic example.test data.

Directory, GPMC and endpoint calls are mocked. Private filesystem/ACL tests and local Chromium run for real. Live AD writes, real DC replication, WinRM refresh and Sechard comparison were not run; local results are not a production-domain success claim.
