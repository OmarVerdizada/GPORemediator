# 3.16.8 validation

64/64 command-level checks pass after targeted rechecks of the final artifacts. Initial UI-contract failures and subsequent rechecks are retained in `test-results.json`. All directory, GroupPolicy and endpoint calls in execution fixtures are mocked; no live deployment domain was contacted.

The real worker dispatch is exercised across all eight mapped AD domain-account properties, representative registry/security/audit/user controls and all review-gated controls. The domain fixture maintains mutable AD state instead of always returning a compliant value. It reproduces GPO 5 / AD 0, proves that this is not NO_CHANGE, applies and reads back the actual threshold, reports a measured mismatch, rejects external AD drift on rollback, restores the saved AD value, and rejects both denied writes and a silently ineffective setter. Selected assertions are in `domain-policy-evidence.txt`.

The catalog-wide writer/verifier regressions and 800 generated manual procedure variants also pass. These are configuration/fixture checks, not proof of live Windows enforcement. One additional chain run had an isolated publication-read exception; an instrumented rerun and the final ordinary run passed. This does not establish that exception's external cause.

The real frontend is exercised with local recorded API responses on desktop and at 390/320px. The domain result shows actual AD 0 against requested 5 even when the stored GPO is 5 and gpupdate completed. Matching AD 5 is verified; unavailable AD data stays unverified. Repair preview shows the effective AD transition. Sign-in and sidebar use one shield mark. Offline evidence, disabled live actions, manual Copy, reconnect, approval/cancel, recovery and keyboard navigation remain covered.

## Reproduce

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1 -OutputDirectory work/audit/3.16.8/final
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-RemediationChain.ps1
node scripts/Test-DomainAccountUi.cjs
```

Full working logs are retained under `work/audit/3.16.8`. Screenshots are under `work/screens/3.16.8`. Install the complete 3.16.8 package and generate a fresh Preview/Apply for a domain account repair; old plans do not contain the new AD snapshot.
