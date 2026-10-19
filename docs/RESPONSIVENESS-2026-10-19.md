# Responsiveness maintenance — 2026-10-19

This maintenance update retains version 3.14.1 and its policy mappings.

## Changes

- Workflow polling renders only when results or error state change. It pauses in hidden tabs and during foreground operations, prevents overlapping requests, and defers rendering while editing a form or reviewing a dialog. Deferred terminal results are still displayed after editing or navigation.
- Healthy Setup status probes no longer rebuild the page every 15 seconds. History probes update the page only when recorded results change and no form or review panel is active.
- Full renders preserve the start, end and direction of text selections and restore input focus without scrolling.
- Catalog coverage, recipe cards and the 405-cell evidence map share a per-surface history index instead of filtering and sorting history separately for each control. Date ordering and tie behavior remain unchanged; each render uses fresh recorded evidence.
- Rollback inspection uses a 620-second browser deadline, matching the ten-minute server operation plus transport margin. Its previous default deadline was 20 seconds. Inspection remains read-only and cancelable.
- The maintenance gate counts active operations in SQLite without deserializing complete historical evidence records. Active state and write exclusion checks remain enforced.
- Source fingerprints use ordinal filename ordering, so Windows PowerShell 5.1 and PowerShell 7 agree on package integrity instead of producing different hashes for hyphenated font filenames.
- Frontend distribution, the self-contained Windows runtime archive and its SHA-256 manifest are rebuilt from the updated source.

## Validation

`scripts/Test-Responsiveness.cjs` covers a synthetic 10,001-record history, all 405 control lookups, one-pass heatmap processing, unchanged/hidden/busy polling, concurrent requests, deferred edits and terminal results, polling failure/recovery, Setup probes and rollback inspection deadlines. It runs in CI, `Validate-Source.ps1` and `Invoke-FullAuditTests.ps1`.

`Test-WorkflowUi.cjs` additionally verifies text selection preservation and DOM identity across unchanged polling in a real browser. The server regression verifies that every supported active state, including lowercase input, still blocks maintenance and a completed operation permits it.

Validation uses `scripts/Validate-Source.ps1 -IncludeBrowser`, the value-editor/manual-remediation tests, PowerShell syntax validation and the dependency advisory check. Build checks require .NET 10, Node.js and Python; browser checks require Playwright and a supported installed browser. On Windows, use a short checkout path if fixture paths exceed the legacy path limit. Build the portable package using Windows PowerShell 5.1 (`powershell.exe -File Build-Portable.ps1`) to reproduce the existing generated manual engine ordering.

These are local and synthetic regressions. No live AD domain was contacted or modified, and real-domain latency and policy enforcement still require a domain pilot.
