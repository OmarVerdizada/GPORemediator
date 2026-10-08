# GPO Remediator 3.4.0

The frontend is organized around operator decisions: connection context, the next action, controls and recorded outcomes. The dashboard uses a compact environment summary instead of a marketing hero. Neutral app navigation, consistent smaller controls, restrained surfaces and clearer type hierarchy apply across dashboard, catalog, change forms and operations.

The default catalog view is a semantic control table with 40 controls per page, numeric ordering, recommendation previews, execution support, last recorded implementation status and favorites. A section navigator and independent support/status filters work across Table, Recipes, Hierarchy and List views and CSV export. Clear filters resets all catalog constraints. Mobile displays the table as labeled records with usable actions; desktop supports comparing controls without opening each detail.

No domain results are fabricated. Missing evidence stays Not assessed. Recorded verification is associated with its GPO/time, not interpreted as a current domain audit. Existing backend authorization, delegated connection, preview/apply/rollback and portable packaging remain the execution architecture.

Design reference: https://github.com/wzx2002/codex-frontend-skill/blob/main/SKILL.md . Its design-first workflow, restrained hierarchy, state coverage and accessibility guidance were applied using local semantic UI equivalents consistent with this dependency-free portable frontend. React/Tailwind/shadcn were not installed or substituted for the existing architecture.

Validation: semantic rendering, filter logic, pagination edges, numeric sorting, escaping, status evidence and session regression tests; desktop/mobile/dark browser checks, disconnected and populated fixtures, search/empty/filter/view-switch/detail flows; JavaScript syntax, portable build and production-package synchronization.
