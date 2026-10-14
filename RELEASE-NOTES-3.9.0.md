# 3.9.0 — Complete remediation review

Version 3.9.0 audits all 405 catalog entries and keeps the published support boundary at 401 automated GPO controls plus four guided controls. It corrects policy addresses and values, completes multi-value policies, preserves stronger deny/audit configuration and makes mapping generation reproducible.

The bundled .NET dependencies are updated to 10.0.13, including the patched `Microsoft.AspNetCore.Authentication.Negotiate` release for CVE-2026-70179.

Endpoint evidence is now fail-closed: merged security policy and native command outcomes are checked, missing values cannot pass as compliant, and samples are limited to in-scope allowlisted hosts. A scheduled `gpupdate /force` remains pending until a later read-only verification observes the endpoint. The UI shows the observed endpoint value and does not recommend rewriting a GPO that already matches.

Old plans created from a previous mapping version cannot be applied or treated as current verification. Their full-snapshot rollback remains available, including post-rollback verification and refresh.

See [the remediation audit](docs/REMEDIATION-AUDIT.md) for corrected controls, validation coverage and the required live-domain pilot boundary.
