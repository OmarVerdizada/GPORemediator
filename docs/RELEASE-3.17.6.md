# GPO Remediator 3.17.6

A duration of 15 minutes with a reset-counter window of 30 minutes cannot be applied through the AD cmdlet. Preview now returns an actionable prerequisite instead of only a toast: it shows actual/requested duration and the related window, prepares control 1.2.4 with the same GPO/domain, and preserves a return action for a fresh original preview. Related changes require separate review and Apply. Returning early remains blocked; threshold 0 is never silently enabled. The reverse window/duration dependency and unlimited duration are also handled.

Refresh and rollback now re-check recorded-target authorization using the active connection before job submission. A missing session grant triggers native access/readiness preview under the same execution account; saved authorization configuration and the recorded operation remain unchanged. Failed access checks prevent job submission. Expired credentials still require sign-in, and approval/native mutation checks remain enforced.

The Windows dependency is documented in [Microsoft Set-ADDefaultDomainPasswordPolicy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy?view=windowsserver2025-ps).

Validation includes worker fixtures for AD 30/30/0, blocked direct Apply, separately approved window/duration changes, exact AD read-back, peer-state drift and rollback; server submission/identity checks; authorization-before-submit and denied-preflight tests; and actual Chromium desktop/mobile guided repair. Directory and endpoint interfaces are mocked. This release does not claim a live AD or Sechard run.
