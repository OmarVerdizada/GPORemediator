# Visual GPO / AD OU catalog — 14 October 2026

**User-facing flow**: CIS control → choose existing GPO from searchable visual inventory (already supported) → choose User OU / Computer OU from a searchable hierarchical AD tree (new) → optional endpoint OU for User gpupdate → read-only Preview → explicit approval → Apply → Verify.

- OU names and DNs are taken exclusively from authenticated `/api/gpo/inventory`/AD discovery. No typing arbitrary OU DNs or GPO GUIDs.
- User Configuration requires an OU hosting the users. Computer Configuration requires an OU hosting the computers. Domain account policies require the actual domain root, and the Default Domain Policy constraint remains enforced.
- User Rights Assignment `2.2.*` is a **Computer** policy even when user/group names appear in the privilege list.
- A GPO already linked to another OU might affect **both** OUs after editing. Existing links, security filtering, WMI filters and inheritance are never deleted to make the UI work. Preview retains these warnings and a full GPO backup is required.
- Duplicate old `targetForm` was removed by the base safety patch; the new OU tree replaces the existing drop-down rather than creating competing inputs. Batch plans are computer-only and avoid pretending User or Domain policies can be applied with a computer OU.
- The backend verifies scope kind against the actual discovered OU list, including for crafted API requests. UI is not an authorization boundary.
- Search supports nested OUs and escaped commas in DNs. Display is capped to 240 visible rows; search to narrow large directories. Domain root is a non-selectable parent for Computer/User targeting.
- Offline validation cannot prove applicability in a real AD. Verify OU objects, security filtering, effective gpresult/RSoP, SYSVOL convergence and rollback in an isolated Windows domain before production.
