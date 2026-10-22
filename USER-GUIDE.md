# User guide

1. Open GpoRemediator.cmd. The launcher installs the packaged runtime; normal startup requires no SDK or build.
2. In Settings, review the domain and writable DC FQDN, then choose **Save and start Windows / AD**.
3. Sign in with the domain execution account. Windows and AD enforce its permissions; there is no application role allowlist. Credentials remain in memory and expire after inactivity or service restart.
4. Choose **Check readiness** and resolve failures. Sign-in alone does not establish readiness. The backup directory must be accessible on the selected DC.
5. In Benchmark, find a control, select a discovered GPO and compatible OU/domain, review its value and choose **Generate plan**. Preview is read-only.
6. Review existing links and impact. Approve the specific GPO/scope, enable the production change gate, enter a change reference and confirm APPLY. The approver reference is optional.
7. Review Operations. Verify publication, replication and endpoint evidence separately. Use ROLLBACK only for an eligible operation with a valid backup.

## Updating

Run git pull --ff-only, then restart using GpoRemediator.cmd. The launcher replaces outdated runtime files from the verified release archive. Configuration and history remain in ProgramData. Use Ctrl+F5 for cached browser assets.

## Troubleshooting

- Enter the full DC DNS name, for example dc01.example.local. Configure AD DNS and synchronized time.
- Check WinRM, remote endpoint permissions and the signed-in account's GPO/OU delegation.
- Review each failed readiness check. Grant backup access to the execution account on the selected DC.
- If a write loses connectivity, inspect Operations before retrying. Stopping a read-only wait does not cancel server work.

Domain password/lockout controls use the domain root and link order 1; no particular GPO name or GUID is mandatory. See PRODUCTION-OPERATIONS.md. Pending evidence is not a successful verification result.
