# Production acceptance testing

Static package validation is performed by `scripts/Validate-ProductionPackage.py`. Windows/domain acceptance must be executed on a disposable test GPO and test OU before production use.

The canonical acceptance sequence is in `PRODUCTION-TEST-CHECKLIST.md`. It covers first-run setup, authentication, readiness, preview, idempotency, real writes, link creation, gpupdate, AD/SYSVOL replication, effective endpoint verification, stale-plan protection, concurrent-operation protection, interruption recovery, rollback and evidence.

Do not validate the write path against Default Domain Policy except for the CIS Account Policy controls that explicitly require it. For the first Account Policy acceptance test, use a controlled lab/test domain because those settings are domain-wide by design.

## Regression tests

Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Test.ps1` for a current build, .NET invariants, production PowerShell worker transactions, configuration recovery/save and frontend integrity checks. Invariants are rebuilt on each run so stale test binaries cannot hide failures.

Developer browser tests require Node.js and Playwright (not required to run the product):

- `node tests/Frontend.cjs`: isolated HTTP fixtures for initialization, setup, all control tabs, connection errors, cancellation/timeouts, numeric preview, one managed write-gate restart, memory-only reconnection, fresh final preview, renewed approval, apply/verify/rollback and history filtering. No real domain changes.
- After `Build-Portable.ps1`, `node tests/Frontend.Live.cjs`: the packaged executable and a real browser in isolated Setup mode with a temporary database. Does not save the host configuration or contact AD.

Both browser tests use installed Edge by default; set `PLAYWRIGHT_CHANNEL` to select another installed Playwright browser channel. Provide Playwright through the development environment's module search path.

The worker transaction suite covers all four handlers with AD/GroupPolicy doubles and temporary policy files. It exercises host allowlists, explicit empty values, numeric audit masks, idempotency, partial multi-setting writes, replay rejection, interrupted publication/rollback, and manifest read-back mismatches. The service invariants exercise concurrent Verify/Rollback and maintenance exclusion, ambiguous refresh rejection, wildcard write denial, and reproducible evidence hashes.
