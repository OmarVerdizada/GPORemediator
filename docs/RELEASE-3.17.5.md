# GPO Remediator 3.17.5

This release resolves the 18 application-audit findings. The resolution matrix and validation evidence are in `docs/audit/2026-10-31-app-review/RESOLUTION.md` and `docs/audit/3.17.5`.

- Migration, orphan/port checks and normal Stop never silently force-kill a runtime. Explicit administrator emergency recovery remains available.
- GPO fingerprints include hidden/system content and reject links. Backup root/workspace ACLs and selected snapshot trees are checked without removing legitimate delegation.
- Reports, catalog status and control results agree on AD mismatches and refresh failures. Exact recommended values retain their benchmark identity; explicit intent is separate from custom values.
- History has stable server pagination and complete frontend loading. Concurrent discovery/heartbeat updates preserve inventory. Evidence exports retain refresh, coverage, targets and the previous AD value.
- Verification reads current GPO policy-half status; domain permission reports inspect the separate AD write right. Domain scans retain their account scope. HTML reports distinguish link intent from observed state.
- Accepted jobs recover polling after transient reads. GPO/OU modals contain focus and make background controls inert. Risk fallbacks, credential-replay leftovers, duplicated functions and stale documentation are corrected.
- GitHub Actions invokes the same complete audit used locally, including the new safety, reporting, history, polling and browser regressions. Defensive RDN-aware scope matching also replaces raw suffix ancestry checks.

Validation is local: directory/GPMC/endpoint APIs are mocked, filesystem and ACL tests use private fixtures, and browser tests use a loopback fixture server. No live AD success is claimed. Collect fresh target evidence after installing the complete release.
