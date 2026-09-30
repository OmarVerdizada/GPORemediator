# Production remediation assurance update — 2026-09-28

- Fixed `gpoRefresh` executor allowlist and added a dedicated refresh timeout.
- `Apply` never triggers gpupdate automatically; explicit refresh re-verifies live GPO/link state first.
- Added drift-aware **Remediate again** flow that creates a new live preview/plan instead of replaying a stale operation.
- Result Summary now separates GPO publication, link state, AD/SYSVOL convergence, gpupdate scheduling, and effective endpoint policy.
- Live verification exposes the current GPO value and endpoint evidence so manual out-of-band changes are visible.
- Operations now includes timestamps, change reference, approver, evidence export, verification, rollback, and drift recovery actions.
- Added delegated-session expiry visibility and clearer session-expired behavior.
- Removed the obsolete Password Pilot and non-production remediation backend surface from the source tree.
- Release package no longer contains environment-specific config, SQLite runtime state, WAL/SHM files, logs, or screenshots.
- Added dependency-free workflow smoke tests plus an optional pinned Playwright browser-test dependency manifest.

# GPO Remediator — 2026-09-28

- A single standalone interface replaces the competing legacy React shell. Removed unsupported legacy API requests and duplicate navigation.
- Simplified dashboard: connect, select a control, review results. Accurate totals: 405 controls, 401 automated, four read-only.
- Bounded requests, visible progress, cancelable read requests, recoverable startup errors and resilient local preferences.
- Restored GPO selection, impact, verification and history helpers. Numeric overrides survive redraws; fixed-value controls send valid integer payloads.
- Windows account slash normalization and case-insensitive reading of existing configuration files. Settings now wait for the restarted process instead of navigating after an arbitrary delay.
- Corrected Windows PowerShell readiness array serialization, single-item mapping checks and atomic file replacement. Verification details are retained in operation results.
- Stage-specific connection diagnostics. Domain sign-in and readiness are shown separately; uncertain execution outcomes require review.
- Active GPO sessions now use a sliding 30-minute idle timeout. Expired or restarted sessions show a direct reconnect action.
- Source fingerprints prevent stale binaries from being reused. Rebuilds preserve saved runtime configuration and data. UI responses are not cached.

Validation: .NET invariants, isolated production PowerShell worker, recovery/configuration integration, browser workflow fixtures and real packaged-backend browser smoke tests. Real domain publication and effective-policy convergence still require the Windows/AD acceptance checklist.

## Final stability hardening — 2026-09-28
- Fixed control-panel runtime readiness check to use the same production marker and source fingerprints as the launcher.
- Added rollback-aware re-verification: a successful rollback stays `ROLLED_BACK`; post-rollback changes become `ROLLBACK_DRIFT_DETECTED` instead of incorrectly overwriting the operation as ordinary remediation drift.
- Pinned first-run portable SDK bootstrap to .NET SDK 8.0.425 and added download retries.
- NuGet restore now retries three times and uses the local product cache.
- Backend publish is staged and swapped atomically, so an interrupted/failed build cannot leave a half-updated runtime.
- Stale prebuilt runtime binaries are intentionally excluded. First launch builds the exact packaged source once; later launches reuse the fingerprinted self-contained runtime.
- Production validator now checks refresh executor exposure, rollback verification, current runtime marker, source/dist sync, and absence of DB/log/local-config artifacts.
