# GPO Remediator 3.2.0

The desktop and web workspace now make the next action, change context and verification evidence easier to inspect.

- Dashboard: connection/readiness checklist, recent controls and direct access to operations needing review. Coverage and outcome metrics remain separate.
- Benchmark: hierarchy/list switch, exact control ID/subtree search, result counts, filter reset and CSV export of the current result set. Export escapes spreadsheet formulas and preserves Unicode.
- Operations: newest/oldest/attention ordering and a detail drawer for publication, linking, replication, effective policy, value changes, scope, approval, backup and endpoint results. Visible operation records refresh every 15 seconds; polling does not execute AD scripts.
- Navigation: reachable notifications, AZ/EN usage guide, accurate keyboard hints and accessible drawers with focus containment, Escape and return focus.
- Visuals: consistent navy/blue identity, calmer dashboard, responsive cards, corrected form controls and dark theme support.
- PowerShell: validate request, hostname and credential shape before remoting. Remote deadlines finish before the backend watchdog. Responses include duration and failure stage without logging credentials.
- Executor: bounded stdout and streamed stderr prevent unbounded output accumulation. Operation completion logs contain only operation name and elapsed time.
- Service control: validate loopback URLs before sending Windows credentials. Create stop markers only after acceptance; HTTP 4xx errors never fall through to forced termination.
- Desktop Control Center: copy a credential-free service summary for troubleshooting.

Existing approval, backup, write allowlist and rollback protections remain in force. The durable database schema/version remains unchanged. No credentials are added to browser storage or files.

Validation: Release build, JavaScript syntax, PowerShell 5.1 input/stop regressions, executor output limits, Control Center render smoke test and browser interaction/layout checks. Real domain Apply/Verify/Rollback acceptance remains environment-specific.
