# GPO Remediator 3.18.2

| Area | Problem found | Correction |
|---|---|---|
| Workflow submission and startup | The in-memory queue received work before the workflow receipt and authenticated audit event were saved. A database error could leave a rejected request eligible to run. Startup recovery could also overlap new submissions. | Commit the receipt and audit event in a single SQLite transaction before queuing work. Recover interrupted records during hosted-service startup. |
| Apply and endpoint refresh | A refresh failure stopped later refresh groups and skipped read-only verification. Verify also dropped the stored refresh coverage when it retained per-host results. | Continue independent refresh groups after a measured endpoint failure, collect read-only verification, and keep the workflow in review. A live policy drift or uncertain outcome still stops refresh. Retain both the refresh results and coverage. |
| Batch rollback | The Computer and User projections both refreshed both policy halves. | Use the recorded projection to refresh the requested policy half and retain per-half results. Standalone snapshot rollback keeps its existing refresh choice. |
| Verification and pilot promotion | A status label could substitute for measured AD data or complete endpoint coverage in parts of the report and promotion flow. | Require the selected DC reading for domain verification. Use the same unique-host coverage checks for reports and pilot promotion. |
| Bulk Apply display | A temporary polling error stayed visible after the connection recovered. | Clear polling errors after a successful read and discard responses for a superseded batch. |

The audit uses a private SQLite failure fixture, mocked AD/GPMC and endpoint operations, and browser fixtures. Production AD and SecHard results require measurements in the target environment.

The worker matrix covered 405 controls across 413 scopes and the endpoint matrix covered 1,169 comparisons. The bulk browser test timed out once while searching the 5,000-OU fixture and passed on rerun. Both attempts are recorded. [Command results](audit/3.18.2/test-results.json)
