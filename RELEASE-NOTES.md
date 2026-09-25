# GPO Remediator — Local Enterprise UI

## Current release
- Certificate-free local-only HTTP (`127.0.0.1`) for both Setup and Windows/AD mode.
- No inbound LAN binding and no Windows Firewall listener is required.
- New enterprise benchmark workspace with compact CIS domain navigation, searchable controls, remediation detail panel, approval flow, and verification timeline.
- New desktop Control Center visual design.
- Runtime SDK is not downloaded during normal starts. This package requires one one-time backend rebuild because the transport model changed from HTTPS to local HTTP; after that, the local runtime marker prevents repeat downloads/builds.
- Existing real GPO execution, backup, link, verify, gpupdate and rollback scripts remain the execution layer.

## Enterprise UX expansion
- Added environment health / pre-flight readiness dashboard with explicit pending probe states.
- Added saved benchmark views, favorites and bulk-remediation selection UX.
- Added dry-run / what-if presentation and before/after change diff.
- Added policy conflict graph and affected-object explorer placeholders without fabricating live probe results.
- Added local exception-management UX and contextual control guidance.
- Added evidence-pack JSON export for recorded control operations.
- Added notification center, Ctrl+K command palette and keyboard search shortcut.
- Existing real AD/GPO execution APIs and local-only HTTP transport remain unchanged.
