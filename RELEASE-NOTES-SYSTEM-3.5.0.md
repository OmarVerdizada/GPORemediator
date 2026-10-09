# GPO Remediator 3.5.0

The established blue workspace now uses canonical light/dark color tokens, a shared type/radius/spacing scale, and one compiled stylesheet. Exact duplicate blocks are removed without changing selector order, and CSS no longer escalates with `!important`. Historical component layouts are retained in ordered sources for compatibility. New shared controls provide primary/secondary/danger/ghost sizes, SVG icons, icon-and-text statuses and accessible validation errors.

Navigation includes a persistent collapse control, an appearance/help menu with system theme, AZ/EN language, large text and high contrast options, and mobile bottom navigation. Dashboard height is reduced so environment and outcome information appears sooner. All 19 benchmark domains remain collapsible; desktop uses two columns and expanded domains span the full row. Controls have breadcrumbs and responsive independent step panels. The change button stays within a sticky action area, and Apply confirmation includes the actual GPO, scope, value and risk before using the existing guarded endpoint. Cancellation retains the plan.

Operations have an accessible compact table with the existing cards as an alternative. The detail drawer shows recorded stage evidence; an expandable time chart uses server start/update timestamps. The dashboard includes per-domain recorded outcome summaries and the existing automation-coverage ring. Neither is an inferred domain compliance score. Impact-path nodes can be inspected without writes. Dismissible notices, loading skeletons, reduced-motion handling and Alt+1/2/3 navigation complement existing shortcuts.

Audit displays server-verified chain integrity and the first invalid event ID. The backend retains append-only enforcement; regression tests verify a valid chain, rejection of updates, and detection of a corrupted appended event in an isolated in-memory database.

CSS, catalog and operation presentation are separated from API/authentication orchestration. Runtime remains offline and dependency-free; the developer CSS compiler uses Node built-ins without npm packages. Imported CIS benchmark content remains in its original English; product controls and guidance support AZ/EN.

Validation covers all 405 controls and 19 domains, recorded status semantics, escaping, pending vs verified outcomes, accessible tables, audit diagnostics, CSS/assets, session recovery, 2,406 mapping/refresh/priority combinations, preview validation and cancellation, responsive layouts and packaging. No real-domain write was used for UI validation.
