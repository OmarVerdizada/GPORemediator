# Frontend professional refresh — 2026-10-14

## Changes
- Dashboard prioritizes connection status, permission gate, 3 outcome KPIs, remediation coverage and last operations. Never fabricates a "compliant" domain score.
- Detailed health, onboarding, control map (405 cells), and coverage analytics are still reachable through the Advanced details section, instead of loading visually over the core actions.
- Control details: Overview / Target & Apply / Verification primary tabs, with Impact and Audit preserved in the More menu. Full benchmark context is collapsible.
- CIS 2.2 User Rights Assignment is labeled *Computer Configuration*, not User OU. Read-only Preview and existing backend-enforced GPO/OU authorization remain unchanged.
- CIS catalog section headings stop saying "Domain" (which users can confuse with AD domains).
- Batch list initially renders 80 controls for usability; all 405 remain searchable/selectable according to the existing safety rules.
- Uses only existing backend observations, no invented loading meters or artificial security scores.

## Security and limitations
This is an interface patch. It does not modify a Windows domain, delete conflict checks, alter GPO ACLs or remove rollback. Existing SYSVOL/AD convergence, effective-policy and manual role-sensitive gates are retained from the previous scope patch. Production requires successful full Windows backend/frontend regression, a fresh release runtime, and pilot testing in an isolated AD domain.
