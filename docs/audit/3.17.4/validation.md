# 3.17.4 validation

Scope: the complete 405-control mapping catalog, all 413 local/domain scope cases, reviewed execution, current-value comparison, direct links, publication, endpoint evidence, explicit refresh, and guarded snapshot recovery. This is local regression evidence. No live prosol.local or other AD domain was contacted.

The final 69 command-level checks pass; results are in `test-results.json`. Final targeted reruns retain the original attempt and its log hash. The first endpoint-catalog attempt needed a fixture for the newly independent stored-domain comparison. The first full exact-write chain exposed Windows ReplaceFile error 1175; the production commit path now retries bounded transient errors and supports the existing durable fallback for that error. Neither initial failure is represented as a passing first attempt.

## Coverage

- 413 exact remediation mappings across 405 controls, including all eight domain-account variants and 11 controls requiring explicit environment review. C# and frontend field/comparator parity, idempotent normalization and catalog isolation are checked.
- Full real-worker preview, preflight, backup, mapping write, link, publication, stored-value source, explicit refresh, rollback and read-back use private filesystem fixtures with mocked directory/GPMC/endpoint APIs.
- 413 endpoint mapping cases pass 1,148 synthetic checks. This includes alternate numeric values rejected by exact plans. Baseline scans separately retain benchmark bounds: 394 supported controls, 806 synthetic checks, 11 controls outside automatic execution.
- The reported AD duration=30/window=30/threshold=0 state rejects duration 15 before backup or writes. Explicit window 15 followed by duration 15 changes only approved properties. GPO 15/AD 30 with an existing link cannot become NO_CHANGE. Exact AD mismatch and enabled priority-1 link evidence are checked; rollback restores duration 30 and blocks unsafe dependency/drift states.
- Real private-file commits test ordinary replacement, transient sharing/lock failures, bounded retries, native 1175 and access-denied durable fallback, and unchanged original contents after persistent sharing or disk failures.
- Browser checks cover legacy false-success records, mismatch and unavailable values, repair plans, source GPO, link enablement/priority, disabled-lockout notes, live progress, refresh/rollback actions, and desktop/mobile layouts. The result screen was also visually inspected.
- Generated standalone PowerShell coverage parses 800 scripts and exercises offline Preview/Apply, cancellation, backup ordering, read-back, idempotence, drift and partial-write paths.

## Final analysis

New write previews pin exact field values; read-only benchmark scans keep compliance thresholds. Required-inclusion controls retain additional denied principals/audit flags unless explicitly overridden. Stored GPO content, direct-link state, replication, actual AD/endpoint values, refresh completion and winning-policy attribution remain distinct claims. Legacy ambiguous Apply plans require a fresh preview; read-only verification and snapshot recovery remain available.

Windows/AD constraints and remote permissions can still prevent a live change. An unavailable probe, failed refresh or mismatch cannot establish effective success. Local LSA API smoke testing under this workspace identity returns access denied, so native successful LSA enumeration is not claimed; mocked verifier tests cover the comparison logic. Deployment must collect fresh evidence on the intended DC/endpoints with the installed 3.17.4 package.
