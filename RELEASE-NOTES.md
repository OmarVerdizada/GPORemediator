# GPO Remediator — 2026-09-28

- A single standalone interface replaces the competing legacy React shell. Removed unsupported legacy API requests and duplicate navigation.
- Simplified dashboard: connect, select a control, review results. Accurate totals: 405 controls, 401 automated, four read-only.
- Bounded requests, visible progress, cancelable read requests, recoverable startup errors and resilient local preferences.
- Restored GPO selection, impact, verification and history helpers. Numeric overrides survive redraws; fixed-value controls send valid integer payloads.
- Windows account slash normalization and case-insensitive reading of existing configuration files. Settings now wait for the restarted process instead of navigating after an arbitrary delay.
- Corrected Windows PowerShell readiness array serialization, single-item mapping checks and atomic file replacement. Verification details are retained in operation results.
- Stage-specific connection diagnostics. Domain sign-in and readiness are shown separately; uncertain execution outcomes require review.
- Source fingerprints prevent stale binaries from being reused. Rebuilds preserve saved runtime configuration and data. UI responses are not cached.

Validation: .NET invariants, isolated production PowerShell worker, recovery/configuration integration, browser workflow fixtures and real packaged-backend browser smoke tests. Real domain publication and effective-policy convergence still require the Windows/AD acceptance checklist.
