# Domain sign-in and AD permissions (2026-10-20)

The application no longer assigns Administrator, Remediator, Auditor or Viewer roles. It no longer requires AllowedOperators, rejects duplicate role membership, restricts audit/configuration pages by role, or requires an operator list for Windows-mode promotion. Legacy role/account lists are ignored and dropped by canonical configuration saves. No manual ProgramData edits are needed for this update.

## Sign-in and execution

1. Run GpoRemediator.cmd and configure the AD DNS domain and writable DC.
2. Sign in once using the execution account and password from that domain. The connection performs read-only DC inventory through Kerberos/WinRM. The worker checks the actual remoting user SID against the configured domain SID; trusted foreign-domain or local accounts are rejected.
3. GPO discovery, preview, apply, verification, rollback and refresh continue to use that explicitly supplied account. The launcher/backend account is never substituted as an execution credential. The DC enforces GPO, OU/link, WinRM and other Windows permissions; removing application roles grants no AD permissions. A domain account may still need WinRM/read access before it can open the workspace.
4. Audit and operation records retain both the Windows browser operator and the verified domain execution identity, alongside action, time, GPO and results. Startup confirmation now includes executionUser. Passwords are not persisted in logs or configuration.

Negotiate still identifies the local Windows browser caller for session/CSRF binding and audit context. Initial Setup, before an AD domain is configured, confirms the current Windows caller's password. Windows/AD mode uses the single domain login. This removes application RBAC, not Windows authentication itself.

Configuration, audit access and ordinary service controls no longer have application roles. Native service stop/restart continues to work before domain login, with Windows authentication, origin/CSRF validation and the idle-operation gate. Windows elevation for the explicit emergency process-stop command is an OS requirement and remains unchanged.

Production change consent, selected GPO/OU boundaries, backup, stale-plan checks, rollback drift checks, loopback-only hosting, CSRF/origin checks, session isolation, credential expiry and script integrity checks remain active. Domain permissions are the authority for execution, while these controls preserve the reviewed operation and recovery workflow.

## Upgrade

Stop the existing service in Local Control Center. Extract the complete updated package into a new folder and run GpoRemediator.cmd. Preserve ProgramData Data, Backups and Recovery. The updated launcher migrates existing role-bearing configuration automatically; old role values do not block startup. The release runtime is rebuilt from the updated source, so no SDK is needed on the operator host.

## Validation

Offline checks cover role-free APIs for unconfigured/previously conflicting accounts; invalid credentials, startup proof, CSRF, origin and cross-identity isolation; background workflows; production SID-domain validation; Windows PowerShell syntax; native service controls; and the packaged frontend/backend fingerprints. Domain SID tests execute the production predicate with synthetic identities. Browser fixtures omit the role property. These checks do not prove live AD access, effective GPO application or live permission denial. Those require a disposable domain pilot.
