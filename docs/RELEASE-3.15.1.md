# 3.15.1 — frontend review and improvements

The review covered Dashboard, Benchmark, control tabs, Workflow center, Operations, Reports, Diagnostics, Audit, Settings and OU password policies. The product remains English-only.

| Finding | Result |
| --- | --- |
| Nine mobile destinations shared too little width; labels collided | Internally scrollable navigation with readable touch targets, active-destination reveal and safe-area spacing. Dashboard returns to the first position. |
| Short desktop windows could hide lower navigation items | The navigation list scrolls independently; branding and connection context remain available. Collapsed destinations have descriptive titles. |
| Mobile toolbar rules reduced popover buttons to icon dimensions | Appearance controls now have independent, full-width sizing and sufficient height. |
| Theme selection replaced the focused form element | Stable control identities preserve keyboard focus. Escape, outside click and focus departure close the popover. |
| Saved dark mode arrived after the initial light paint | A small local bootstrap applies validated appearance preferences before styles load. Invalid or unavailable storage has safe defaults. |
| Accent colors, secondary text and control states varied between themes | Shared semantic palettes cover light/dark, blue/cyan/violet, focus, validation, high contrast and large text. The bundled Geist font is used consistently. |
| Password policy fields were one undifferentiated form; results were long JSON output | Grouped identity/password/lockout fields, scope guidance, snapshot facts, explicit action state, paged resultant-policy tables and full evidence downloads. |
| Invalid related numeric values reached the API | Client validation checks password age ordering and lockout-window limits. Native/server validation still applies. |
| Malformed history responses could crash the view; stale account context remained after failures | History errors have retry states. Context changes clear old previews even after failed history requests; recorded-context actions remain guarded. |
| Reports discarded endpoint evidence after row 20 | JSON exports retain every endpoint result, actual values and coverage metadata. UI rendering remains bounded. |
| An inconsistent full-coverage claim could appear verified | Shared display logic checks complete counts, unique hosts and successful endpoint states. Rolled-back records do not count as compliant. |
| Tabs were mouse-oriented | Arrow/Home/End navigation, roving keyboard focus and accessible scrollable report regions are supported. |

Validation includes the complete regression suite plus a real-browser frontend matrix at 320, 390, 768 and 1440 pixels in both themes; six semantic color palettes; appearance focus/dismissal; large text/high contrast; keyboard navigation; no unintended policy writes; 201-user evidence pagination; cross-field validation; history retry/context changes; and complete 201-endpoint JSON exports.

See the [validation record](VALIDATION-3.15.1.md) for the 51 successful command checks and their evidence.

All domain authorization, write gates, confirmation requirements and native execution checks remain enforced by the backend. Browser tests use local fixtures, not a live domain.

Visual review: [light desktop workspace](ui/3.15.1/desktop.png) · [dark mobile appearance](ui/3.15.1/mobile-appearance.png).
