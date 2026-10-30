# 3.17.5 validation

The complete runner is `scripts/Invoke-FullAuditTests.ps1`, also used by GitHub Actions. All 72 command-level checks passed. Coverage includes the 405-control/413-scope real-worker fixture matrix, baseline and exact endpoint matrices (1,148 exact endpoint fixture cases), security/authorization/transport checks, standalone PowerShell generation, browser layouts/recovery and package integrity.

New targeted regressions reproduce the audit failures and assert their corrected outcomes. `Test-AuditSafety` uses private files/ACLs and mocked process controls. `Test-AuditFrontend` covers report consistency, exact recommendation metadata, accepted-job polling recovery and complete history pagination. `Test-AuditUi` exercises actual Chromium viewport positioning, focus containment, overlaid sign-in and legacy mismatch reporting against a loopback fixture API. C# regressions cover inventory concurrency, stable history snapshots, evidence integrity, domain scan intent and observed HTML link state.

Final per-command results and hashes are in `test-results.json`; targeted final reruns retain their initial attempt metadata. Per-control reports and selected output are retained beside it. Portable runtime, source fingerprints and package hashes are verified after the last source edit.

No live AD was contacted. No real runtime was force-stopped. Native successful endpoint LSA enumeration and real multi-DC/WinRM/Sechard behavior remain deployment validation tasks; existing local LSA smoke behavior is recorded without claiming live-domain success.
