# 3.17.3 validation

All 66 command-level checks pass after the targeted domain UI recheck. The initial domain UI assertion expected one whitespace-joined label/value string; it was updated to assert the separate value and source fields introduced by the result layout. The original attempt remains in `test-results.json`. The final portable build and stricter copied-LSA-command rechecks supersede the initial runs where applicable.

Command-level results and log hashes are retained in `test-results.json`; complete working logs are under `work/audit/3.17.3/`. Browser screenshots are under `work/screens/3.17.3/`.

The real C# service is exercised with private in-memory connections, store and configuration. A second GPO/OU pair is authorized only after a successful write-access preview and readiness result. The grant is usable by real submission validation, with no configuration/hash change or restart. Read-only scans, failed readiness, a different session/operator, a different GPO/OU cross-product, disconnected tokens and expired absolute sessions remain blocked. The fixture never decrypts credentials or invokes native AD operations.

The native LSA reader is compiled by Windows PowerShell 5.1 and invokes the local LsaOpenPolicy API. The local test identity receives access denied (5); the reader propagates this instead of returning an empty/matching assignment. Thus successful native enumeration on a deployment endpoint is not claimed from this test. Explicit native doubles exercise SID matches, mismatches, empty assignments and unavailable LSA access through the actual endpoint verifier. A matching exported security template with different LSA assignment data must produce a mismatch. The all-endpoint matrix covers 394 automated controls in 806 synthetic cases; eleven reviewed controls retain their separate review and writer-chain tests.

Endpoint diagnostics exercise 1726/PSSessionStateBroken, JobFailure, a JobFailure wrapping Win32 error 1726, access denial, authentication, disk-full, native failure and mixed per-host refresh outcomes. Raw exceptions and credentials are excluded. Refresh checks emit distinct REFRESH opening/completion/failure frames for each host; the actual C# stream reader validates that phase separately from endpoint-value checks.

Browser fixtures verify that a session-authorized second GPO preview needs no write-gate button, configuration POST or restart. Result UI checks ensure both the specific refresh failure and the value-check job failure remain visible, unavailable endpoints are not labeled as value mismatches, inspected hosts are shown and GPO provenance does not overlap the stored value. Existing live checking, source/absence semantics, offline evidence, recovery, both themes, keyboard/contrast and mobile layouts remain covered. All 405 copied verification procedures are parsed by PowerShell 5.1, including the LSA reader's here-string inside the guarded manual-check block.

No deployment AD, GPO or endpoint was changed. The supplied Default Domain Policy report contains the requested Create global objects principals; the exact cause of the external Sechard failure remains unestablished. The recorded PSLWSUS01 session failure is not treated as a proven policy mismatch or a proven firewall/permission fault. The 413-scenario complete writer matrix from 3.17.1 is historical evidence and is not presented as a fresh 3.17.3 run.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1 -OutputDirectory work/audit/3.17.3/reproduce
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-EndpointEvidence.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-LsaUserRights.ps1
dotnet run --project scripts/WorkflowRegression -c Release
node scripts/Test-LivePolicyUi.cjs
```
