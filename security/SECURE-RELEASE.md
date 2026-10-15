# GPORemediator Wave 3 — Secure Code & release controls

## Confirmed protections retained

- The existing `GpoWorkflowRules.ValidateWriteScope` rejects wildcard GPO IDs / scope DNs for production writes (not a new feature).
- The existing `BundledAssets.VerifyScripts` compares PowerShell files byte-for-byte against embedded resources, using SHA-256.
- Domain credentials reach a fixed, bundled PowerShell entrypoint via subprocess standard input and Kerberos remoting; no ad hoc PowerShell commands have been added.
- Operator roles, exact-origin CSRF protection, localhost restrictions, per-GPO locking and GPO change fingerprints remain in place.

## New controls

1. **Secondary endpoint OU authorization**: a User-policy selection that specifies an endpoint OU is not writable if that OU falls outside `Windows:AuthorizedOus` even when the primary user OU is authorized. Include both OU DNs in the approved allowlist. The original checks still apply on server-side Apply/Refresh/Rollback.
2. **Credential exposure window**: delegated GPO connections expire after **15 minutes of inactivity or 2 hours absolute**, whichever comes first. Encrypted ephemeral credential handling is retained; long workflows may require fresh sign-in.
3. **Authenticated audit for NEW records**: each new SQLite audit event gets an HMAC-SHA256 tag in the same transaction as its record. The 256-bit MAC key is sealed using Windows DPAPI (`CurrentUser`) and stored as `audit-hmac-key.dpapi` beside the database, outside SQLite. Never send this key off the host. The application fails startup if the protected key is missing when MAC records exist or a stored audit MAC/chain is invalid. Pre-existing historical records are SHA-hash-chain only: `legacy` counts are exposed by `/api/audit`.
4. **Executable script directory integrity**: parent directory junction/reparse points are rejected before fixed embedded script verification.
5. **CI security gate**: Windows .NET 10 compile, security regression executable, PSScriptAnalyzer, CodeQL for C#/JS, Semgrep, secret-pattern check, NuGet high/critical audit, and SBOM artifact.

## Residual limitations / operational cautions

- **Not absolute tamper-proofing**: HMAC prevents undetected modifications by an attacker who only changes SQLite contents, but does **not** detect deleting the entire tail of both `audit` and `audit_macs`. Export signed audit checkpoints to an immutable external SIEM/WORM store to protect against tail truncation and DB+key compromise.
- DPAPI **CurrentUser** binds the audit key to the Windows service identity. Back up the database and protected key together using an approved DPAPI recovery procedure. If switching the Windows service identity, perform supported migration/recovery before restarting; fail-closed startup is intentional. A reinstalled OS may not be able to decrypt the key without DPAPI recovery material.
- The `.NET 10 SDK` and NuGet access are required **only on an approved build host**, not on the end-user Windows Server when distributing a finished self-contained signed runtime.
- PSScriptAnalyzer/CodeQL/Semgrep are analyzers, not guarantees of secure code. CodeQL upload may require enabling code scanning in repository settings and depends on GitHub plan/entitlements.
- Build unsigned source with existing `Build-Portable.ps1` for the lab. For production with a suitable trusted code-signing certificate, run `security/Build-Signed-Release.ps1 -Thumbprint YOUR_CERT_THUMBPRINT -Source PATH` **before distribution**. It signs PowerShell source BEFORE the publish because embedded hashes are checked at runtime. The executable is signed AFTER publish and the runtime ZIP SHA-256 is regenerated. The certificate thumbprint must be independently pinned/verified by the deployment process. A ZIP sidecar checksum alone does not establish publisher authenticity.
- This patch does not add network ports, new GPO writes, or background scanning. No environment or AD operation was executed by preparing the patch.

## Validating on Windows

1. Use the integrated 3.11 source checkout; the original ZIP patch installers are no longer needed.
2. Run `security/Test-SecurityHardening.ps1` (from the source root; requires .NET 10, Python).
3. Run `dotnet build backend/GpoRemediator.csproj -c Release -r win-x64`.
4. Check PowerShell lint and `.github/workflows/security-checks.yml` security job on a pull request. Configure branch protection to block merges when a required check fails.
5. Validate read-only GPO preview, User-policy endpoint OU denial and allowed scope behavior in disposable AD, then Apply/Verify/Rollback. **Do not pilot production changes until this integration sequence passes.**
