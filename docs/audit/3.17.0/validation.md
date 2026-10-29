# 3.17.0 validation

62 command-level checks pass after targeted rechecks. The original complete run and superseding logs/hashes are retained in `test-results.json`. Retired feature tests were removed with their features; the catalog, operation monitor and streamlined workspace have replacement coverage.

The initial complete audit had nine failures from obsolete imports of the removed Studio renderer, Recipes-specific selectors, tracked-but-deleted PowerShell paths, and source/distribution changes during visual QA. These contracts were updated to the retained hierarchy and assets, deleted-file handling corrected, and the package rebuilt before rechecking. An earlier interrupted audit also caught launcher/package guards still requiring the retired FGPP script; those required-file lists now match the four shipped PowerShell assets.

Backend coverage includes authentication/CSRF/identity boundaries, compiled asset integrity, denial of all four retired FGPP operations before native execution, the server job chain, batch recovery guards, explicit refresh, scope permissions and durable rollback. GPO domain-account processing remains independent of the removed FGPP feature.

Mapping/endpoint checks cover all 405 imported controls; the private worker-chain fixtures exercise the shared handlers and all eight domain-account properties. Manual verification covers 800 generated PowerShell procedures, with executable filesystem fixtures for the supported writers. Directory, GroupPolicy and endpoint calls in those fixtures are mocked. No deployment AD or endpoints were contacted.

UI checks use the real frontend with local recorded HTTP responses: all 405 controls in one nested/searchable hierarchy, removed navigation/actions/preferences, old-preference migration, retired bookmark redirects, target-aware live checks, asynchronous job completion, approval, rollback/refresh, manual guidance, offline evidence and no mutation replay. Both themes, WCAG text contrast, 320/390/768/1440px layouts and keyboard behavior are checked. Mobile navigation is explicitly checked to remain visible inside its bottom rail.

Full working logs are under `work/audit/3.17.0/`. Dashboard screenshots are under `work/screens/3.17.0/`. The complete installation archive is `work/releases/GPORemediator-3.17.0.zip`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1 -OutputDirectory work/audit/3.17.0/reproduce
node scripts/Test-CatalogState.cjs
node scripts/Test-StreamlinedUi.cjs
```
