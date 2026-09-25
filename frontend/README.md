# GPO Remediator frontend

`frontend/source` is the authoritative dependency-free UI. `Build-Portable.ps1` copies it byte-for-byte to `frontend/dist` and records a source fingerprint; Node.js/npm/pnpm are not required.

The UI exposes the production CIS Benchmark v4.0.0 workflow: Dashboard, domain/subsection benchmark navigation, control workspace, real GPO discovery, preview/impact/preflight, approval, Apply, verification, Operations/Recovery and evidence. The browser does not execute arbitrary PowerShell.

The application is local-only in this release (`http://127.0.0.1:5080`). See the root README, `docs/ARCHITECTURE.md`, and `PRODUCTION-TEST-CHECKLIST.md`.
