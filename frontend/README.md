# Frontend packaging

`source/` is the canonical Web UI shipped with GPO Remediator. It contains the prebuilt base operator UI plus the dependency-free Automation Center (`automation.js` / `automation.css`).

`Build-Portable.ps1` copies `source/` to `dist/` and writes `dist/source.sha256`. No Node.js, npm, pnpm, Corepack, Vite install, or JavaScript package registry is used by the production bootstrap.

The browser UI talks only to typed same-origin `/api/*` endpoints. It cannot submit arbitrary PowerShell commands or scripts.

`workspace.js` and `workspace.css` implement the editable Azerbaijani start page (`#/home`), grouped module catalog (`#/modules`), responsive layout, and service controls. Existing compiled detail/history routes remain available. `automation.js` owns the guided scan, setup, plan and explicit apply panel; it retains form drafts, traps keyboard focus and supports Escape to close. `gr:open` is the small integration event used by workspace shortcuts.

The catalog groups the backend's actual controls by policy type. It does not claim that a supplied benchmark or PowerShell pack has already been installed. See `docs/MODULES.md` for the later module integration workflow.
