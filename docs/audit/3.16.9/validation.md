# 3.16.9 validation

The audit covers 65 command-level checks, with initial results and targeted rechecks retained in `test-results.json`. The final package build and source/distribution compatibility checks use Windows PowerShell 5.1. Deployment-domain AD and endpoint calls were **not run**.

`control-chain.json` records 413 passing scenarios across all 405 catalog controls, including both domain-account and OU-local-account paths for the eight shared settings. Each uses the real worker dispatch against private filesystem fixtures with mocked directory, GPMC and endpoint APIs. A stored value that already matches the requested value is additionally checked with the direct target link removed; it must not become NO_CHANGE. Review-gated controls are exercised with fixture inputs, not made automatically writable in the product.

PowerShell lifecycle tests prove that controller checking/results use a separate information stream and do not contaminate nested metadata returns. A default PowerShell serialization round-trip preserves the information-record payload and forwarding shape. Backend protocol tests reject malformed and unsupported progress frames, assign server timestamps and keep frames separate from the final result.

The real frontend runs against local HTTP fixtures: queued verification, switching to another OU without leaking the queued check, fresh server stages, per-host checking/results, interrupted polling, unavailable endpoint reasons, disabled/missing/reprioritized links, an enabled link without inferred endpoint evidence, mixed per-host values, compact navigation and 390/320px layouts. Polling submits exactly one verification request and no Apply/Refresh/Rollback. Existing recovery, user-session refresh, offline evidence, keyboard/navigation and workflow regressions are covered.

The first full audit had five failures: the removed renderer's old test contract, a missing asynchronous recovery warning, an incomplete queued-job UI fixture, and two source/distribution mismatches during final edits. The recovery warning was restored, fixtures/contracts updated, the package rebuilt, and affected checks rerun. Initial failures remain recorded instead of being erased.

The first additional catalog-chain attempt stopped at 18.4.8 with a sanitized MethodInvocationException during writing. Fifty isolated repetitions and a complete instrumented rerun passed. Its original native cause was not established. One additional concurrently run UI interruption check timed out; failure artifacts are now captured, and subsequent standalone checks passed. These observations do not establish live reliability or the cause of either intermittent result.

Working logs: `work/audit/3.16.9/`. UI screenshots: `work/screens/3.16.9/`. Complete package: `work/releases/GPORemediator-3.16.9.zip`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1 -OutputDirectory work/audit/3.16.9/reproduce
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-RemediationChain.ps1 -AllControls -ReportPath work/audit/3.16.9/reproduced-chain.json
node scripts/Test-LivePolicyUi.cjs
```
