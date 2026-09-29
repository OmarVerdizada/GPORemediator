# Production acceptance testing

Static package validation is performed by `scripts/Validate-ProductionPackage.py`. Windows/domain acceptance must be executed on a disposable test GPO and test OU before production use.

The canonical acceptance sequence is in `PRODUCTION-TEST-CHECKLIST.md`. It covers first-run setup, authentication, readiness, preview, idempotency, real writes, link creation, gpupdate, AD/SYSVOL replication, effective endpoint verification, stale-plan protection, concurrent-operation protection, interruption recovery, rollback and evidence.

Do not validate the write path against Default Domain Policy except for the CIS Account Policy controls that explicitly require it. For the first Account Policy acceptance test, use a controlled lab/test domain because those settings are domain-wide by design.

## Regression tests

Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Test.ps1` for a current build, .NET invariants, production PowerShell worker transactions, configuration recovery/save and frontend integrity checks. Invariants are rebuilt on each run so stale test binaries cannot hide failures.

Developer browser tests require Node.js and Playwright (not required to run the product):

- `node tests/Frontend.cjs`: isolated HTTP fixtures for initialization, setup, all control tabs, connection errors, cancellation/timeouts, numeric preview, apply/verify/rollback and history filtering. No real domain changes.
- After `Build-Portable.ps1`, `node tests/Frontend.Live.cjs`: the packaged executable and a real browser in isolated Setup mode with a temporary database. Does not save the host configuration or contact AD.

Both browser tests use installed Edge by default; set `PLAYWRIGHT_CHANNEL` to select another installed Playwright browser channel. Provide Playwright through the development environment's module search path.

### Endpoint refresh regression coverage

The invariant suite checks disabled defaults, legacy plan compatibility, explicit hostname validation and the 100-host limit. Worker doubles check selected endpoints, out-of-scope and invalid names, empty automatic targets, publication, manual refresh, partial scheduling and rollback conflict preservation. Browser fixtures cover the new refresh controls, persisted selection across tabs, checkbox size and horizontal overflow at 1440/768/390 widths.

Automatic Apply plus gpupdate uses one operation gate, persists the publication result before scheduling and has a client timeout covering both worker stages. Real AD/RPC scheduling, membership changes between preview and refresh, and endpoint convergence must still be exercised in the domain lab with both automatic Yes and No.
