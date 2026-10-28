# 3.16.7 — mixed scopes, GPO sources and measured outcomes

The target picker uses one OU/domain scope for both user and computer controls. Mixed OUs are supported. The plan briefly states whether Computer Configuration or User Configuration is processed; optional session endpoint overrides remain available for users signing in elsewhere.

Configured current/before values display their source GPO name and GUID in preview, results, operations and exported evidence. Missing values display no source. These are values read from the selected GPO; winning endpoint GPO attribution remains separate RSoP evidence.

Apply and Refresh collect read-only effective endpoint evidence before the workflow reports its outcome. An unchanged endpoint value produces `NEEDS_REVIEW`; inaccessible, incomplete or unconverged evidence produces `CHECKS_INCOMPLETE`. Publication and gpupdate completion use pending badges, and do not independently imply effective compliance. Configured follow-up checks remain scheduled while convergence is pending.

Section 17 reads and replaces only System audit CSV rows, preserving per-user rows with the same subcategory GUID. Matching audit bits are insufficient to report verified audit configuration when subcategory override is disabled or unavailable; the result identifies control 2.3.2.1 for review. Microsoft's [subcategory override reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override) explains how legacy category policy can override subcategory policy.

Rollback refresh consistently schedules both computer and signed-in user policy processing after a full-GPO restore. It processes recorded targets in bounded pages, rechecks live membership and restored content, and retains failures without erasing rollback status. Scheduling remains distinct from completion.

Opening Verification before the first execution now shows the empty state correctly. Keyboard focus survives tab rerendering.

See [validation](audit/3.16.7/validation.md) for all 19 imported headings, 405 controls, 413 chain cases and the command-level regression results. All AD/endpoint calls in these tests are mocked. The precise cause of the previously reported live audit no-change incident cannot be established without target evidence; the new workflow exposes that evidence instead of treating a write as effective success.

Deploy the complete 3.16.7 package and generate fresh plans. Existing policies are not changed by upgrading.
