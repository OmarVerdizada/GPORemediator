# 3.15.0 validation

The complete 50-check audit and final affected reruns passed. Command logs and SHA-256 hashes are in [the consolidated results](audit/evidence/3.15.0/test-results.json). Counts refer to command checks, not live AD operations; affected reruns replace earlier attempts in the consolidated list.

Run the complete audit with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1
```

The suite rebuilds the self-contained runtime and checks source/distribution fingerprints, bundled-script integrity, the audit chain, native NTFS ACL preservation, every baseline mapping, endpoint verifiers, PowerShell syntax, browser workflows, dependency advisories, and secret/package guards.

New regression evidence:

- Real FGPP functions run against 201 synthetic users and private filesystem fixtures with all directory cmdlets replaced. Preview is read-only; create/update/subjects/resultant-policy verification, restore/remove, external drift, membership drift, unrelated PSO protection, and interrupted-write recovery status are exercised.
- Real refresh dispatch processes 201 synthetic endpoints in four bounded requests. Explicit endpoint credentials, concurrency, per-host completion, missing members, and page progress are checked without invoking live remoting or gpupdate.
- Verification-page tests cover 201 pinned endpoints exactly once. Incomplete coverage cannot establish full endpoint assurance.
- All eleven environment-sensitive mappings remain blocked by default. Explicit values and a substantive environment review enable their typed mapping. Their real worker preview/apply/rollback chains and actual browser selection/preview forms are exercised with mocked AD/GPMC APIs.
- The FGPP browser controller exercises its discovered OU selector, every request value, explicit Apply/Rollback, Verify, stale-preview invalidation, history, and narrow viewport behavior.
- A final browser layout probe checks that the password-policy heading stays below the sticky toolbar after navigation and that the keyboard skip link does not reserve a permanent header gap.
- Repeated backup Modify grants preserve existing delegation and consolidate identical ACEs. Both real startup entry points preserve root delegation and migrate legacy protected backup descendants; intentional custom ACLs are preserved.

No live AD write was run. This workstation cannot reach the supplied pilot DC over WinRM and has no current application connection or AD/GPMC modules. Real execution permissions, multi-DC convergence, resultant policy precedence, native Import-GPO behavior, and target processing must be checked on a delegated pilot before broader rollout.

Remaining platform prerequisites are reported instead of silently overridden: native AD/GPO/SYSVOL permissions; separate PSO permissions; loaded user hives/logon; user/rollback task completion; restart/service/tamper requirements; and RSoP attribution. Endpoint value equality does not prove that this GPO won.
