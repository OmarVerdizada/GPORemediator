# Executed validation

Generated from individual subprocess exit codes and SHA-256-checked logs, not assumed coverage. Final command checks: **35 executed / 35 passed / 0 failed**. No listed command was skipped. Eleven classes of live/unsupported validation were not run, as documented in UNVERIFIED_SCENARIOS.md. No remote CI completion is claimed.

Known parameterized coverage (distinct measurements, not a summed assertion count):

- 394 real mapping writer/read-back/idempotence/endpoint-recipe synthetic fixtures; 11 explicit manual blocks.
- 806 synthetic positive/negative/stronger-bound verifier cases across all 394 automatic controls.
- 1,592 backend control/refresh/priority combinations; invalid selections/value bounds and manual denial additionally checked.
- 405 generated manual PowerShell commands parsed by Windows PowerShell 5.1 without executing them.
- 9 replication/launcher regression scenarios; all final tests retain real source functions.
- 221 registry control addresses matched installed ADMX; 0 detected simple Enabled/Disabled mismatches. Unmatched entries are not inferred correct or broken merely from absence in ADMX.
- Real local TestServer HTTP/RBAC/CSRF/idempotency, local DPAPI and private-file ACL fixtures, and Chrome desktop/mobile UI tests. These are actual Windows-local integration tests, not live AD tests.
- Actual Windows/AD end-to-end enforcement tests: **0**.

| Command check | Scope | Result | Seconds | Evidence |
|---|---|---|---:|---|
| build-portable | build/package | PASS | 26.13 | [log](evidence/build-portable.txt) |
| SecurityRegression | offline regression | PASS | 18.95 | [log](evidence/SecurityRegression.txt) |
| WorkflowRegression | offline regression | PASS | 4.59 | [log](evidence/WorkflowRegression.txt) |
| WorkspaceRegression | offline regression | PASS | 5.35 | [log](evidence/WorkspaceRegression.txt) |
| HardeningRegression | offline regression | PASS | 11.43 | [log](evidence/HardeningRegression.txt) |
| Test-SecurityFiles | offline regression | PASS | 0.93 | [log](evidence/Test-SecurityFiles.txt) |
| Test-RuntimeIntegrity | offline regression | PASS | 3.44 | [log](evidence/Test-RuntimeIntegrity.txt) |
| Test-GpoMappings | offline regression | PASS | 11.73 | [log](evidence/Test-GpoMappings.txt) |
| Test-EndpointEvidence | offline regression | PASS | 1.45 | [log](evidence/Test-EndpointEvidence.txt) |
| Test-AllEndpointMappings | offline regression | PASS | 9.88 | [log](evidence/Test-AllEndpointMappings.txt) |
| Test-VerificationLifecycle | offline regression | PASS | 3.92 | [log](evidence/Test-VerificationLifecycle.txt) |
| Test-PowerShellSyntax | offline regression | PASS | 1.06 | [log](evidence/Test-PowerShellSyntax.txt) |
| frontend-syntax | syntax | PASS | 3.65 | [log](evidence/frontend-syntax.txt) |
| stylesheet-build | offline regression | PASS | 0.2 | [log](evidence/stylesheet-build.txt) |
| Test-FrontendSystem | offline regression | PASS | 0.27 | [log](evidence/Test-FrontendSystem.txt) |
| Test-RemediationEvidence | offline regression | PASS | 0.18 | [log](evidence/Test-RemediationEvidence.txt) |
| Test-RecipeWorkspace | offline regression | PASS | 0.23 | [log](evidence/Test-RecipeWorkspace.txt) |
| Test-GuidedRemediation | offline regression | PASS | 1.21 | [log](evidence/Test-GuidedRemediation.txt) |
| Test-GpoScopePicker | offline regression | PASS | 0.2 | [log](evidence/Test-GpoScopePicker.txt) |
| Test-UX-Contract | offline regression | PASS | 0.23 | [log](evidence/Test-UX-Contract.txt) |
| Test-Studio-UI | offline regression | PASS | 0.23 | [log](evidence/Test-Studio-UI.txt) |
| Test-EnterpriseCenter | offline regression | PASS | 0.21 | [log](evidence/Test-EnterpriseCenter.txt) |
| Test-ManualVerification | offline regression | PASS | 1.14 | [log](evidence/Test-ManualVerification.txt) |
| Test-RecoveryUi | offline regression | PASS | 18.19 | [log](evidence/Test-RecoveryUi.txt) |
| Test-WorkflowUi | offline regression | PASS | 37.32 | [log](evidence/Test-WorkflowUi.txt) |
| mapping-generation | offline regression | PASS | 0.16 | [log](evidence/mapping-generation.txt) |
| Test-ProductionMappings | offline regression | PASS | 0.11 | [log](evidence/Test-ProductionMappings.txt) |
| Audit-PolicyScopes | offline regression | PASS | 0.13 | [log](evidence/Audit-PolicyScopes.txt) |
| Validate-ProductionPackage | offline regression | PASS | 12.99 | [log](evidence/Validate-ProductionPackage.txt) |
| installed-admx-review | local ADMX comparison; not policy execution | PASS | 0.6 | [log](evidence/installed-admx-review.txt) |
| secret-guard-selftest | offline regression | PASS | 0.12 | [log](evidence/secret-guard-selftest.txt) |
| secret-guard | offline regression | PASS | 0.46 | [log](evidence/secret-guard.txt) |
| domain-gpo-isolation | offline regression | PASS | 3.5 | [log](evidence/domain-gpo-isolation.txt) |
| dependency-vulnerability-query | dependency advisory query with completeness/vulnerability checks | PASS | 4.42 | [log](evidence/dependency-vulnerability-query.txt) |
| built-source-match | current source/distribution compatibility | PASS | 1.39 | [log](evidence/built-source-match.txt) |

Earlier failures are not hidden: the baseline aggregate stopped on the obsolete 3.11.0 asset-version assertion; the first audit run had 32/34 passing checks, failing the changed sample-result label expectation and the PowerShell 5.1 String.Split isolation test. Both assertions were repaired for their intended semantics and the entire final run repeated. An intermediate packaging check also rejected audit transcripts saved with the forbidden runtime-log extension; published static transcripts now use .txt, while the package validator continues to reject runtime .log artifacts unchanged. Developing the new verifier matrix also exposed the auditpol argument error; final per-control results are preserved in evidence/endpoint-controls.json. Synthetic failure fixtures were corrected to use genuinely noncompliant values rather than values satisfying a minimum.

The published logs normalize workspace/runtime paths. Their original and normalized SHA-256 values are recorded in evidence/test-results.json. They contain synthetic example identities only. Runtime ZIP SHA-256: 6b8fde7c840cfe3e7e3b51f469c5dca2641a598a0d7152020e23573b88f5a9e8.
