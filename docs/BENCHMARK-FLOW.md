# Benchmark workflow

1. Start GpoRemediator.cmd, configure the AD environment and sign in with the delegated domain account.
2. Find a control by ID, title, section or automation filter. The imported CIS v4.0.0 catalog contains 405 controls; production mappings determine which are writable.
3. Review intent, risk and verification guidance. Select a discovered GPO and compatible OU/domain. Computer policies use computer OUs; user policies use a user OU and, when needed, a separate endpoint OU. Domain account policies use the domain root.
4. Review or customize the value and generate a read-only plan. The server checks the target, access, current values and existing links. Preview is not a domain-wide compliance assessment.
5. Approve the specific GPO/scope, enable writes, enter the change reference, acknowledge impact and confirm APPLY.
6. Review backup, publication, replication and effective endpoint evidence separately. A successful write does not prove effective compliance. Use the reviewed rollback workflow when recovery is required.

Manual controls remain visible with dedicated guidance. Viewing or downloading a script does not execute it. Server-owned mappings and live AD permissions enforce automatic writes independently of catalog visibility.
