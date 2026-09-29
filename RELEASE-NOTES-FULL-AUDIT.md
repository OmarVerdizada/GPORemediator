# Full audit release

This build was reviewed across launcher/build, backend orchestration, PowerShell worker, rollback/drift handling, frontend transport/UI state, test harness, data retention and packaging.

Key corrections in this audit:
- restored and retained the shared `PolicyValues` helper used by the backend;
- replaced stale invariant tests that referenced removed pre-production APIs;
- made PowerShell result construction safe under `Set-StrictMode -Version Latest` when optional fields are absent;
- preserved `gpupdate` results across later read-only verification;
- preserved rollback-aware verification for `ROLLBACK_DRIFT_DETECTED`;
- marked pre-write Apply failures as `FAILED_SAFE` and write-phase uncertainty as `REVIEW_REQUIRED`;
- made incomplete rollback return `ROLLBACK_REVIEW_REQUIRED` with its manifest retained;
- aligned frontend timeouts with long-running backend operations (`refresh`, `replan`, write-mode readiness);
- made delegated-login cookies browser-session scoped while server-side idle expiry remains authoritative;
- made ASP.NET data protection process-ephemeral so no key ring is persisted for delegated credentials;
- removed stale bulk/exception UI state with no backend execution path;
- made stop cleanup work even when the launcher process is no longer alive;
- preserved only bounded diagnostics after failed bootstrap/build; normal stop still removes runtime DB/log/session/temp state;
- removed stale legacy PowerShell test/source documentation references.

Real AD/GPO publication still requires the Windows/domain validation checklist because no Linux test can emulate GroupPolicy/ActiveDirectory cmdlets, SYSVOL or the target domain.
