# GPO Remediator 3.3.2

The 3.3.1 workspace now groups the recipe catalog into 19 collapsible benchmark domains. Each domain has an icon, a color accent and counts derived from actual matching controls. Domains start collapsed; opening another closes the previous domain. Expanded domains retain ordered recipes, recorded implementation statuses, recommendations and favorites. Empty benchmark domains are explicitly identified.

Search and saved-view filters apply before grouping. Filtered domains remain collapsible, and domains without matches are omitted. The hierarchy view shares the same domain header. Dashboard and remediation workflows retain the 3.3.1 design.

Validation: regression checks cover all 19 domains and all 405 controls, collapsed state, filtering, empty domains, numeric ordering and escaped text. Browser checks cover switching, collapse, filtered controls and mobile layout. Source and packaged frontend are synchronized.
