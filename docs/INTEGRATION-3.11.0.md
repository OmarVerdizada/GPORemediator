# Integrated release 3.11.0 — 15 October 2026

Base: GitHub commit `05a4740` (3.10.0). Inputs: `GPORemediator_Wave4_Domain_GPO_Script_Isolation_20261014.zip` and `GPORemediator_Studio_UI_All_6_Waves_20261014.zip`. Both archives are source patches, not complete runnable releases. Their documentation was assessed as project evidence, not treated as operator instructions.

## Included changes

- Cumulative CIS scope corrections, seven role-sensitive controls disabled for automatic writes, visual GPO/OU picker and compact workflow UI.
- Target impact discovery, fail-closed verification and read-only rollback assessment.
- Reports with JSON/CSV/HTML/print exports; readiness diagnostics including DNS SRV, GPMC, backup capacity and backup ACL checks.
- Secondary endpoint OU authorization, 15-minute idle/two-hour absolute delegated sessions, protected audit HMAC key, startup integrity gate and linked-script-directory rejection.
- Domain/GPO launchers with compiled script verification and matching domain/GUID guards.
- Six Studio UI waves layered onto the real application; existing single sign-in, backend authorization, preview, approval, backup and rollback behavior retained.

## Integration corrections

The cumulative installers needed adaptation for whitespace and frontend cache versions in the current GitHub source. Their output was reviewed and committed as normal source; users do not run the installers again.

The archive's isolation operation allowlists omitted `gpoRollbackInspect`, breaking its own earlier rollback assessment. Both launcher and C# allowlists now support it. Persistent DPAPI audit keys have an explicit Windows platform guard so the warnings-as-errors build succeeds. The imported regression project had invalid named-argument syntax and was corrected.

Plan authorization now includes both the selected user OU and endpoint OU, matching the strengthened server boundary. Reports exclude rolled-back operations from verified evidence. Diagnostics are recomputed from current session state, preventing cached readiness from surviving disconnect. Studio restoration status takes precedence over stale verification fields.

Tests now load Studio dependencies, use the actual visual OU picker, use server-shaped writable mapping fixtures, and enforce the 394 automated / 11 manual boundary. All regression projects live under `scripts/`; source patch backups and installers are excluded. The existing pinned GitHub Actions workflow is extended instead of adding a second overlapping build pipeline.

## Validation and limits

Run `Build-Portable.ps1`, then `scripts/Validate-Source.ps1 -IncludeBrowser`. The build refreshes canonical frontend assets, embedded resources, runtime archive, archive SHA-256 and source fingerprints together.

Validation covers .NET 10 Release compilation with warnings as errors, existing server/workspace/security regression applications, the imported hardening regressions, Windows PowerShell parser/mapping/endpoint tests, frontend tests, Playwright recovery/workflow tests, mapping generation, package checks and source fingerprints. The isolated launcher test executes all six scoped operations against a temporary local stub and rejects wrong domain/GPO/operation requests; it never contacts AD.

Browser fixtures and local regressions do not prove live domain behavior. A disposable AD pilot remains necessary for Kerberos/WinRM, GPO security filtering, replication, effective HKCU/computer policy, backup and Restore-GPO. Runtime is unsigned unless the operator builds with their code-signing certificate via `security/Build-Signed-Release.ps1`. Existing state and backups are not migrated or deleted by this integration.

The application supports one active domain configuration at a time. Domain/GPO folders provide scoped execution context; they are not separate Windows sandboxes. Existing isolated launchers include the absolute runtime bootstrap path and are deliberately rejected if altered or incompatible. Preserve and investigate them before an approved upgrade/recovery procedure; the app does not silently overwrite a mismatched launcher.
