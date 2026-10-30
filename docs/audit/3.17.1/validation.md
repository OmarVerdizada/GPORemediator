# 3.17.1 validation

65 command-level checks pass after targeted rechecks. `test-results.json` retains the original complete audit and the hashes of superseding logs. The complete audit had 63 checks with one source/distribution mismatch while UI refinements were still in progress. The final portable build and UX/source-fingerprint rechecks pass. The reviewed-control and full worker matrices are two additional checks; the current full-audit runner includes the reviewed-control matrix for reproduction.

All 405 control mappings explain user/computer targeting before OU selection, and all eight account-policy mappings explain domain-root targeting. The complete worker matrix passes 413 scenarios covering those 405 controls and the additional domain-account scopes. It exercises Preview, backup, write, link, publication, value provenance, explicit refresh where applicable, snapshot rollback and read-back using mocked directory APIs and private filesystem fixtures. Its per-scenario results are retained in `remediation-controls.json`.

Eleven reviewed controls also pass through mappings produced by the real C# value/review validation. Control 2.2.6 uses the incident's explicit SID list. A denied write remains review-required; two read-only Verify calls retain its original sanitized failure code/stage without retrying the write. Refresh remains blocked for the interrupted publication. A fresh reviewed repair plan completes publication/link verification, permits explicit gpupdate scheduling and retains snapshot rollback. Those eleven cases are in `reviewed-remediation-controls.json`.

The first full 413-scenario attempt stopped at 18.10.43.6.1.2 with a MethodInvocationException during a private registry-write fixture. That attempt did not complete; its exact local failure cause was not established. The subsequent logged full pass completed all 413 scenarios. This is not evidence of successful execution in a deployment domain.

Browser checks exercise the actual frontend against local HTTP fixtures. They cover the full-width justification field, short/whitespace review rejection, review and SID draft preservation across GPO/OU selection, fresh-plan versus recorded-result steps, visible escaped errors, unknown versus absent values, repair navigation on an already-open route, both themes and 320/390px layouts. Existing recovery, live checking, offline evidence, scope/endpoint selection, keyboard and contrast regressions pass. The new reviewed-target presentation test submits no Apply, rollback or refresh operation; the separate recovery workflow tests use mocked local HTTP actions.

No live AD or deployment endpoint was changed. The user's supplied result omits its nested original failure, so this release does not claim to establish why the original domain-side 2.2.6 write failed. Re-verify now retrieves the retained original error from the DC manifest rather than replacing it with a generic incomplete-publication message.

Working logs: `work/audit/3.17.1/`. UI screenshots: `work/screens/3.17.1/`. Complete installation package: `work/releases/GPORemediator-3.17.1.zip`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1 -OutputDirectory work/audit/3.17.1/reproduce
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-RemediationChain.ps1 -AllControls -ReportPath work/audit/3.17.1/reproduce/all-controls.json
node scripts/Test-ReviewedTargetUi.cjs
```
