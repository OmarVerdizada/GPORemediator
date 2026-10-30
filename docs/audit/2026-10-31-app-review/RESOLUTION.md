# Application audit resolution — 3.17.5

The original audit describes the 3.17.4 baseline (`ea5dcf7`). Its screenshots, observations and reproducers are retained as historical evidence. Current regression tests live in `scripts`; the baseline reproducers are not the release validation entry point.

All 18 changes below are implemented. Final local validation is recorded in `docs/audit/3.17.5`. Live AD, real interrupted DC writes and a remote GitHub Actions run are not claimed.

| Finding | Change | Regression coverage |
|---|---|---|
| A01 | Busy/denied/unresponsive normal Stop, migration, orphan and port checks never silently force-kill a runtime. Explicit administrator emergency recovery remains separate. | Test-AuditSafety, Test-ServiceControl |
| A02 | Fingerprints enumerate hidden/system files and fail on file/directory links or unavailable content. | Test-AuditSafety, Test-GpoMappings, complete remediation matrix |
| A03 | Readiness checks root/workspace ACLs; the selected run tree is checked before its manifest/backup is used. Broad mutation grants and links fail closed; delegation is preserved. | Test-AuditSafety, Test-SecurityFiles, HardeningRegression, complete remediation matrix |
| A04 | Reports use the shared assurance classifier, including actual AD mismatches and refresh failures. | Test-AuditFrontend, Test-AuditUi, Test-EnterpriseCenter |
| A05 | Server-derived custom-value metadata distinguishes exact recommended intent from changed values. Legacy history receives the same annotation. Attention takes precedence over the custom note. | WorkflowRegression, Test-AuditFrontend, Test-FrontendSystem |
| A06 | Bounded history pages expose total, next offset and a stable insertion snapshot. The client loads every page; concurrent inserts/updates cannot move existing page rows. | WorkflowRegression, Test-AuditFrontend |
| A07 | Inventory publication retries against the current connection, retaining heartbeat expiry and session authorization state. | WorkflowRegression |
| A08 | Evidence schema 1.2 includes per-host refresh results, both coverage objects, previous AD policy and pinned targets in its hash. Nullable fields preserve legacy evidence serialization. | WorkflowRegression |
| A09 | Verify/Refresh preflight reads the selected GPO policy-half status and reports GPO_POLICY_DISABLED. | Test-AuditSafety, Test-AllEndpointMappings, full verifier/mutation matrices |
| A10 | CI invokes Invoke-FullAuditTests, with browser dependencies installed first. Retired test references are removed. | Complete local audit; CI source inspection |
| A11 | Domain account access reports include the separate AD attribute write right as a required row. | Test-AuditSafety, Test-PolicyDiagnostics |
| A12 | HTML reports display link intent and observed link separately; missing observations are explicit. | WorkspaceRegression |
| A13 | Domain account scans preserve Domain/first-priority intent. User/manual/organization-input controls remain individually reviewed. | WorkspaceRegression |
| A14 | GPO/OU dialogs share focus containment, background inert handling and trigger focus return with other modals. Overlaid sign-in remains interactive across renders. Intro animation no longer anchors fixed dialogs to the scrolled page or puts them under the header. | Test-AuditUi, Test-RecoveryUi, existing scope/browser regressions |
| A15 | An accepted job remains accepted after a transient reload failure; its known active state keeps polling enabled. Mutations are not replayed. | Test-AuditFrontend, Test-LivePolicyUi |
| A16 | Risk fallback derives domain/restart sensitivity even without server annotations. | Test-AuditFrontend, Test-ValueEditor |
| A17 | Duplicate notification logic, unused browser credential cache/replay and unreachable reconnect branches are removed. Restart requires explicit sign-in with preserved draft context. | Test-AuditFrontend, Test-Responsiveness, Test-RecoveryUi |
| A18 | Security and retention documents describe the actual role-free identity model, pinned/paged verification and remote backup checks. | Documentation review |

C01 also receives a defensive change: application authorization compares escaped RDN components rather than raw DN suffixes. Synthetic escaped-comma and true-child cases are tested in WorkflowRegression. The original audit did not establish an end-to-end live AD bypass; that limitation is preserved.

The full local suite covers all 405 controls in 413 scope cases and separately exercises endpoint verification. Directory/GPMC/endpoint interfaces are mocked; ACL/filesystem fixtures and Chromium rendering are real. No test result should be presented as a successful production-domain change.
