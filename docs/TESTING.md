# Production acceptance testing

Static package validation is performed by `scripts/Validate-ProductionPackage.py`. Windows/domain acceptance must be executed on a disposable test GPO and test OU before production use.

The canonical acceptance sequence is in `PRODUCTION-TEST-CHECKLIST.md`. It covers first-run setup, authentication, readiness, preview, idempotency, real writes, link creation, gpupdate, AD/SYSVOL replication, effective endpoint verification, stale-plan protection, concurrent-operation protection, interruption recovery, rollback and evidence.

Do not validate the write path against Default Domain Policy except for the CIS Account Policy controls that explicitly require it. For the first Account Policy acceptance test, use a controlled lab/test domain because those settings are domain-wide by design.
