# 3.15.1 validation

51 command checks passed; zero failed. The complete audit suite ran, and the final build/frontend matrix was repeated after the keyboard-focus adjustment. [Logs and SHA-256 hashes](audit/evidence/3.15.1/test-results.json) record which results came from the complete run and which were final affected reruns.

Frontend coverage:

- Dashboard, Benchmark, Workflow center, Reports, Diagnostics, Audit, OU password policies and Operations at 320, 390, 768 and 1440 pixels, in both light and dark themes.
- Blue, cyan and violet accents in both themes. Primary, secondary, success, warning and danger text pairs meet at least 4.5:1 contrast.
- Saved appearance before CSS paint, blocked/invalid storage, system-theme changes, focus preservation, Escape/outside-click dismissal, large text, high contrast, mobile navigation and short desktop windows.
- Keyboard skip navigation, focus transfer to the new page, roving tabs and Arrow/Home/End interaction.
- 201-user evidence pagination, escaped account values, typed confirmations, cross-field validation, malformed-history retry, stale-plan invalidation and execution-context changes.
- Complete 201-endpoint JSON export and rejection of incomplete/duplicated full-coverage evidence.
- Existing control/GPO/OU selection, Preview, approval, workflow, recovery, themes, security, mapping and package regressions remain passing.

Browser tests use local recorded fixtures and do not contact AD. Tests assert that appearance/navigation never submits policy writes. No live domain changes were made for this frontend release.
