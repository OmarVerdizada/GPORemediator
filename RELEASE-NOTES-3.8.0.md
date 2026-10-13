# 3.8.0 — Operator workspace

- Fresh password confirmation for the authenticated Windows operator after each backend start. Refresh/reopen keeps confirmation while that process runs; restart invalidates all proofs. Browser Windows Security behavior remains controlled by Negotiate; the guaranteed confirmation is in the application.
- Same-origin, CSRF-protected confirmation, SID matching, bounded in-memory proofs and password retry/concurrency limits. Passwordless accounts need a separately designed alternative; no passwordless bypass is provided.
- Compact purple/teal/amber dashboard metrics replace the large white remediation panel. Four guided procedures remain available in expandable details.
- Twelve empty GPMC categories now explain the imported catalog boundary and offer category-specific review suggestions and related sections. Supplemental guidance does not count as CIS controls or verified compliance.
- No changes to the 405-control catalog, 401 automatic mappings, four guided execution boundaries or existing workflow approval requirements.

Validation: server security/workflow/workspace regressions, mapping/integrity checks, frontend unit checks and recorded browser flows. Windows password verification still requires a real-account domain-lab acceptance test; automated tests use an injected verifier without collecting user credentials.
