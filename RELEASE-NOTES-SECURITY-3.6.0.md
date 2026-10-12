# 3.6.0 security hardening

The browser now authenticates its actual Windows caller. The launcher-owner impersonation fallback was removed, role checks use resolved endpoint metadata, and ambiguous/legacy-only roles fail closed. This closes route casing/trailing-slash permission bypasses. Setup remains available only to its launcher owner.

Local state/runtime permissions are replaced with private Windows DACLs, file links are rejected, DPAPI protects persisted Data Protection keys, and legacy plaintext keys are archived encrypted. The UI is embedded in the backend; altered worker scripts cannot execute. Runtime files are checked against the release payload on startup. Login limits, absolute session expiry and request bounds reduce resource and credential exposure. The portable backend was rebuilt for .NET 10.

The refresh endpoint now reads typed JSON and passes Pdc/Scope through to execution. Its production route mapping is shared with HTTP regression tests that assert both targets survive the request boundary. Unknown properties and invalid targets are rejected. Existing rollback UI offers optional refresh after a confirmed successful restore; the restore and refresh remain separately recorded operations. Server-managed chaining, detailed live stages, compliance scans, pilot/bulk workflows, recovery aggregation and reports remain future work.

## Upgrade

1. Stop the previous application, preserve ProgramData state/backups and extract this release into a new trusted local folder. Run the launcher with the intended Windows account.
2. The first upgrade closes an existing write gate. Prepare a new preview and explicitly authorize its GPO/scope before writing.
3. Each UI account must have exactly one explicit role. Duplicate memberships stop canonical configuration; correct them using recovery Setup. Configurations without explicit roles initialize only the launcher account as Administrator; other legacy AllowedOperators entries are not elevated.
4. Replace wildcard AllowedHosts entries with exact domain FQDNs. An empty list remains valid for discovery; scope refresh needs explicitly permitted targets.
5. Reconnect delegated credentials and refresh the browser. Retired legacy antiforgery tokens are intentionally invalid. Keep the Windows account/profile used for DPAPI recovery.
6. If Windows ACL protection fails, correct ownership/permissions under the intended administrator account before retrying. Do not bypass the checks or use a junction for application state.

No SDK or internet is required on the operator machine. Developers need .NET 10 and Node.js to rebuild; both frontend and backend source are included in the portable fingerprint. See SECURITY.md for threat boundaries and outstanding pentest/code-signing work.
