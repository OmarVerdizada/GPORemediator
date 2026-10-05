# Production operations

## Start and connect

Extract the release into a new folder and run `GpoRemediator.cmd`. Save the AD DNS domain and writable DC FQDN, then start Windows / AD mode. Configuration/recovery mode permits settings changes only.

Open the console with an authorized Windows operator account. Connect separately with the delegated domain execution account. Readiness must confirm Kerberos/WinRM, ActiveDirectory/GroupPolicy modules, SYSVOL and the DC-side backup repository. Credentials remain in memory.

## Publish a policy

1. Select the CIS control, existing GPO and AD scope.
2. Generate a fresh read-only preview and review all existing links, filtering, inheritance and affected objects.
3. Authorize the selected GPO and scope. The launcher enables the change gate through one managed restart and the browser generates a new final preview.
4. Review the final preview, provide the change reference and acknowledge the impact. Protected/default policies require separate acknowledgement.
5. Apply. The DC worker creates a full GPO backup before writing and reads back the policy and selected link.
6. Review publication, AD/SYSVOL replication and effective endpoint results separately. Publication alone does not establish endpoint compliance. Refresh is a separate explicit action.

Domain password and lockout controls require Default Domain Policy and the domain root. Other controls should use the approved remediation GPO and intended OU. Wildcards are discovery-only and cannot authorize writes.

## Verify and recover

Use Verify to inspect live content, links, replication and available endpoint evidence. Generate a new plan after drift or a changed authorization boundary; never replay an uncertain Apply.

Rollback requires the recorded full backup and an unchanged post-write fingerprint. External GPO/link edits block automatic restore. A `REVIEW_REQUIRED`, `ROLLBACK_REVIEW_REQUIRED` or `ROLLBACK_DRIFT_DETECTED` result requires administrator inspection of the DC manifest, backup and live policy before further changes.

Keep the configured backup repository and preserved recovery copies. Inspect Control Center diagnostics for service startup failures. Export evidence for the change record before concluding the operation.

## Release maintenance

Use `Build-Portable.ps1` in the developer/release environment to regenerate the self-contained Windows runtime and its SHA-256 manifest. Production startup uses that local archive and does not install an SDK or download dependencies. `scripts/Validate-ProductionPackage.py` checks the production mapping, source/dist integrity and release contents.
