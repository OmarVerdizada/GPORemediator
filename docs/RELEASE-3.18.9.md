# GPO Remediator 3.18.9

- Bulk Apply brings target selection, refresh choices and control values into one preparation screen. The workflow shows the current stage and the number of controls processed during execution.
- The Operations drawer updates in place while re-verification runs. It shows the live check and replaces it with the recorded outcome when the job finishes.
- Bulk results can re-verify the remaining controls after partial rollback or the authoritative restored snapshot after full rollback.
- The endpoint audit probe recognizes a numeric `0` with the explicit `No Auditing` label. Ambiguous exports stay pending.
- Dashboard adds a latest-record endpoint evidence summary and a direct link to the next result needing inspection. Benchmark and Operations use tighter spacing and a readable chronological journal.
- Bulk Apply highlights the actual server operation, including rebased plan IDs, and updates its stage without replaying writes. Processed controls remain distinct from verified endpoint values.
- Verification puts per-host values in a comparison table above expandable diagnostics. Mobile rows stack without horizontal scrolling.
- Modal, drawer, section and result transitions honor reduced motion. Mobile drawers fit the available viewport and keep their footer above navigation.
- A shared SVG policy-network logo appears in navigation, sign-in and the browser tab. Reports, Diagnostics, Access & evidence, Audit and Settings now share the workspace typography, cards, form styling and section identity in both themes.
- Route and tab transitions, button feedback, Settings opening/closing and account-checking feedback use brief motion. Closed Settings controls are excluded from keyboard focus; reduced motion also disables explicit smooth scrolling.
