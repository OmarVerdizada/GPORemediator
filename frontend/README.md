# Password pilot UI

Dependency-free editable UI: `source/workspace.js` provides the six-setting selection, exact test-user plan, Apply and history/rollback. `source/automation.js` provides automatic setup detection with manual overrides and Windows write-mode controls.

The existing bundled shell assets supply navigation/layout. Legacy navigation is hidden and legacy scan/write routes are blocked server-side in this release. No background inventory or compliance requests are issued. Environment detection runs on first Settings open and is cached by the server.

`frontend/source` is authoritative. The launcher copies it to `dist` and fingerprints the result; no Node/npm build is needed. See the main README and docs/PASSWORD-PILOT.md.
