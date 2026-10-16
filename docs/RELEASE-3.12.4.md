# 3.12.4: benchmark category navigation

Opening a large CIS category previously rendered every recipe, so changing expanded categories could move the clicked header far from its original viewport position. Search matches also remained hidden until an extra category click.

Recipe view now shows a compact subsection selector inside the open category. The first matching subsection is selected by default; each option includes its control count. All subsections remains available as an explicit selection. The selected subsection is retained per category during the session and falls back to an available subsection when filters change. All 405 controls remain accessible.

Search automatically expands matching categories and displays matching controls across their subsections. Categories can still be collapsed during search; changing the search resets those search-specific collapsed states. Normal browsing retains the one-category-at-a-time accordion. Category and hierarchy subsection toggles preserve the clicked header's viewport position and keyboard focus after rendering. Arrow keys and Home/End navigate category headers.

Mobile headers hide redundant counters while retaining category title and total control count. The subsection selector wraps within the category body. Empty imported categories retain their supplemental guidance. Search, favorites, level/type filters and the list/hierarchy views remain available; hierarchy toggles expose their expanded state.

This release changes catalog presentation only. No real AD/GPO operations were performed. The packaged runtime is rebuilt because it embeds the updated UI and verifies its source fingerprint. Local tests cover all-category/all-control accessibility, bounded initial rendering, automatic and manually collapsed search results, scroll/focus preservation, keyboard navigation, subsection selection and mobile overflow, alongside the existing workflow/security suite.

Dated local command results are in `docs/audit/3.12.4-test-results.json`. Stop the previous application and start the new package; confirm UI version 3.12.4. Existing protected configuration, history and backups do not need deletion.
