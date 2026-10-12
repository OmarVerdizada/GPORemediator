# GPO selection, operation timeline and recovery repair

## Rollback policy refresh

The recovery form now offers `gpupdate /force` after rollback: choose PDC emulator or scope computers, or leave refresh disabled. The final confirmation includes the chosen target. After a successful `ROLLED_BACK` response, the UI calls the existing guarded refresh endpoint with the selected strategy. An incomplete restore never triggers refresh; a refresh error preserves the completed restore and explains that refresh could not be scheduled.

Already restored operations expose a separate `gpupdate /force` button in the recovery panel, even when the original plan did not request refresh. Per-host scheduling results appear in that panel. The existing backend re-verifies restored content and links, limits refresh to authorized hosts, and schedules both user and computer policy refresh after rollback. Scheduling does not prove endpoint convergence.

Browser regressions cover both target strategies, disabled refresh, cancellation, incomplete rollback, separate refresh after restore, and refresh failure without repeating or losing the restore.

- GPO rows retain their grid layout when the shared button decorator runs. Names and GUIDs are readable, status badges align to the right, and small screens move badges beneath the name.
- The search field uses one focus outline around the search container. The picker no longer reserves a large blank area for short inventories.
- Operation timeline rows retain their grid layout, show the GPO name and status, and format long intervals as days/hours/minutes. Intervals explicitly describe start-to-last-update time rather than active execution time.
- Rollback is accessible from the default operation table, operation details and cards. The shared recovery panel displays the backup ID, requires the exact `ROLLBACK` text, and opens a final confirmation with the selected GPO, backup and operation ID.
- Completed restores, operations in progress, no-change operations and records without a backup do not offer another restore. Re-verify remains available. Existing server authorization, change gate, backup and conflict checks remain in force.

Validation: frontend system, recipe workspace, deterministic CSS build and production package validation; Playwright browser integration with simulated API responses on desktop and mobile. The browser regression checks search/empty results, layout, typed confirmation, cancellation without writes, the correct rollback API ID, and removal of rollback after a recorded restore. No real domain policy was changed during validation.

## Use

Extract the complete package into a new folder and start `GpoRemediator.cmd`. Connect to Windows / AD as usual. Open **Əməliyyatlar → Geri qaytar**, review the GPO and backup, type `ROLLBACK`, then confirm. Rollback still requires the existing production write gate and server authorization.

The backend and verified self-contained Windows runtime are unchanged. Both frontend source and distribution are synchronized, including the source fingerprint.
