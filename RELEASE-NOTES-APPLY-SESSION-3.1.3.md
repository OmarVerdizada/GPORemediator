# GPO Remediator 3.1.3 — Apply/session continuity

This maintenance patch fixes two operator workflow defects without weakening the production change gate.

## Fixed: first Apply asked for APPLY again
The read-only plan was created before the production GPO/OU allowlist was narrowed. The change-gate restart then loaded a different configuration hash, so the preserved plan was stale. 3.1.3 always creates a new final preview after the restart and only that plan can reach Apply.

## Fixed: repeated delegated account entry
The delegated DOMAIN\user credential is captured once and retained only in the current browser tab's volatile memory, never Web Storage or disk. The backend still keeps its normal 30-minute rolling idle session. During the one managed change-gate restart, the browser automatically re-establishes the backend delegated session and then regenerates the final preview.

The account is requested again only if the operator disconnects, the browser page/tab is reloaded or closed, the memory cache has been idle for 30 minutes, authentication fails, or an unrelated service restart occurs after the in-memory cache is no longer available.

## UI resilience
Typed `APPLY` plus the production-impact/protected-GPO acknowledgements are held in UI state. A server-side validation error no longer silently clears the confirmation form.
