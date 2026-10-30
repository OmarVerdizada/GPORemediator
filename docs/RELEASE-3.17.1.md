# GPO Remediator 3.17.1

The target form now explains whether a control applies to computer accounts, user accounts or domain accounts before the operator chooses an OU. This also appears beside the generated plan. Mixed OUs remain supported; their names do not determine GPO processing scope. User Rights Assignment controls, including 2.2.6, explicitly explain that rights are assigned on computers.

Reviewed controls have a full-width justification field, visible 10–2048 character requirements and a live trimmed character count. Whitespace-only and short reviews are rejected before Preview, while GPO/OU selection preserves the review and explicit policy values. Unfinished reviews no longer produce an internal custom-value error in the standalone manual procedure. Environment-sensitive controls receive High operational impact guidance rather than falling through to Low because their canonical handler is Manual.

Target/Preview steps use the new plan rather than an earlier operation. The Verification tab uses the recorded operation. Creating a repair plan explicitly returns to the fresh plan even when the route is already open.

An interrupted or failed operation shows its recorded failure message, last recorded stage and next steps in the main result card. Missing read-back after an interruption is shown as **Not checked**. **Not configured** is retained for a successfully inspected absent setting. GPO value provenance remains on its own line.

Repeated Re-verify previously replaced the original Apply error with a generic incomplete-publication message. Verification now retains the original failure code, stage and sanitized explanation from the DC manifest. It explicitly explains that read-only verification does not retry Apply. A fresh approved repair plan can complete publication and establish the prerequisites for explicit gpupdate; an interrupted record alone cannot authorize refresh.

These changes do not establish why the user's live 2.2.6 operation failed: the supplied screenshot contains the generic result but omits its nested error. The actual recorded error is now visible without opening the operation record. Re-verify remains required to establish live state after an interruption; refresh is still blocked until publication/link or restored-snapshot evidence permits it.

Validation evidence is in [audit/3.17.1/validation.md](audit/3.17.1/validation.md). Browser and worker regressions use local fixtures and mocked directory APIs. No live AD, GPO, OU or endpoint was changed during validation.
