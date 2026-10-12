# Security boundary

Version 3.6.0 is a security-hardening release, not a security certification or independent penetration-test report.

## Operator and execution identities

The service is local-only. Requests must originate from a loopback address and use a localhost/loopback Host header. Except for two minimal health endpoints, access requires the real Windows caller via Negotiate. Setup is restricted to the launcher owner. AD mode requires exactly one explicit Administrator, Remediator, Auditor or Viewer role. Mutation permissions are attached to resolved endpoints; an undeclared mutation fails closed. Administrators manage configuration and lifecycle; Administrators/Remediators may apply, restore and refresh. Audit events are limited to Administrators/Auditors.

The delegated AD execution account is separate from the browser identity. Its password is encrypted in server memory, passed to fixed worker scripts via stdin, and never placed in argv or persisted by the application. Sessions are bound to the operator, expire after 30 minutes idle or eight hours total, and disappear on restart. Managed strings cannot be reliably erased; the launcher owner and local administrators remain trusted and can inspect process memory. Logins are limited to five attempts per minute per Windows identity, four concurrent connection attempts and 32 active sessions.

## Request and write protection

API mutations require the exact application Origin, application/json and an identity-bound antiforgery token. Cookies are HttpOnly and SameSite=Strict. The local HTTP deployment does not provide TLS confidentiality: never proxy or expose it to a LAN. Browser scripts use a self-only CSP; inline styles remain permitted for existing UI rendering. Request bodies are limited to 32 KiB.

Apply, rollback and refresh require the write gate and explicit authorized GPO/OU boundary. Refresh accepts only Pdc or Scope. Endpoint targets must be exact DNS names within the configured domain, with at most 100 entries; wildcard host execution is rejected. Existing backup, stale-plan, rollback-drift and interrupted-operation safeguards remain in force. A reported publication result does not establish effective endpoint compliance.

## Files and distribution

ProgramData configuration, state, data, backups and recovery use private DACLs for the launcher account, SYSTEM and local Administrators. Existing broad child permissions are replaced. Junctions and symbolic links are rejected. Failure to apply these protections stops startup. The installed runtime receives the same protection. Remote DC backup and manifest storage must separately be secured by the domain administrator; this release's local ACL checks do not validate remote storage permissions.

Data Protection keys are protected with current-user DPAPI. Legacy plaintext keys are retired to encrypted `.dpapi` recovery copies, intentionally invalidating old browser antiforgery tokens. Preserve the Windows account/profile and protected state when planning recovery.

The launcher checks archive SHA-256 and compares installed runtime content with the archive. The compiled backend serves its embedded UI and checks worker scripts against embedded hashes before execution. Checksums do not prove publisher identity if an attacker can replace the entire package. Authenticode signing and signed release provenance are still required for a stronger distribution chain. Do not run packages from an untrusted or shared writable directory; a local administrator or compromised launcher account can replace the product or alter its data.

Audit hashes detect inconsistent records; they are not externally anchored signatures and do not defend against a privileged attacker rewriting the full chain. Export audit records to an independently protected system when stronger evidence is required.

## Verification and remaining work

Automated tests cover endpoint roles including casing/trailing slashes, origin/CSRF/identity isolation, login throttling, production refresh body mapping, host restrictions, script tampering, Windows ACL/junction rejection, DPAPI persistence/migration and embedded UI delivery. Workflow/mapping regressions and mocked browser recovery tests supplement these checks. GitHub CI runs these checks and a transitive NuGet vulnerability audit. A clean dependency result means no known advisory was returned at scan time; it is not proof of absence of vulnerabilities.

Before broad production use, perform an independent penetration test on an isolated domain lab: actual Windows/Negotiate authentication, privilege separation, concurrent/restarted operations, remote DC permissions, credential handling, GPO drift, rollback and endpoint refresh. Real AD execution was not performed for this release's automated local verification. Test runtime upgrades and recovery with the intended service account. Keep Windows, .NET release payloads and dependencies patched.

Report suspected vulnerabilities privately to the repository owner without publishing credentials, domain inventories or exploitable details in a public issue.
