# GPO/OU visibility and permission-based planning (2026-10-20)

All GPOs and domain/OU entries returned by the signed-in account's AD inventory remain visible in the target pickers. A readable object is not labelled writable. Completing a compatible GPO/OU selection triggers a debounced, read-only access check without creating a plan. Its result appears beside the target. Edit permissions are checked again when preparing a remediation plan. Delayed results for an earlier selection cannot overwrite the current target feedback. AD ACLs can hide objects from discovery; the application does not use a second privileged identity to reveal them.

Control compatibility and account permissions are separate. All discovered targets can be inspected/selected, but incompatible selections show an inline explanation and disable Preview. Domain-password workflows accept any active discovered GPO but require the domain root and link order 1; computer/user controls require OUs. A disabled GPO is identified as disabled, not as an access-denied result. The application never silently replaces the operator's selected GPO.

## Read-only permission assessment

Before a remediation preview is built, the worker on the pinned DC checks the actual delegated execution account:

1. The GPO's writable AD attributes are queried using `allowedAttributesEffective` for versionNumber and the appropriate machine/user extension attribute.
2. If the requested link would change, writable gPLink authority is queried on the selected OU/domain. An already enabled link whose order is preserved does not require a link write. Apply likewise skips Set-GPLink when no link change is necessary.
3. Windows AccessCheck evaluates the real token against the selected GPO's SYSVOL directory, GPT.INI and the relevant Machine/User branch. This checks modification rights used by the file replacement workflow, including deny ACEs and token group semantics, without attempting a write. Inspection is bounded to 5,000 branch entries.

A proven denial blocks the remediation plan with a specific code. An unavailable, incomplete or unsupported effective-access result blocks it as GPO_ACCESS_UNVERIFIED rather than falsely asserting that access is denied. Apply checks access again before operation file creation and again in the fresh preview. A successful permission check is not a guarantee that subsequent filesystem, replication, RPC or AD operations will succeed; Windows still enforces each operation.

Read-only scans explicitly skip the write-delegation requirement. They do not imply remediation authorization. Apply always repeats the write check even for a plan produced during a scan.

Reference: Microsoft's [allowedAttributesEffective specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/c9ab3c97-5f3d-4676-850b-67515912a097) defines the computed writable-attribute list. See also [GPO permission levels](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gppermission).

## Guidance shown to the operator

- **GPO_EDIT_ACCESS_DENIED**: ask an administrator to open GPMC > Group Policy Objects > selected GPO > Delegation and grant the execution account/group **Edit settings** for that GPO. Read/Apply permissions alone do not grant editing.
- **OU_LINK_ACCESS_DENIED**: GPMC > selected OU/domain > Delegation > **Link GPOs**. This is distinct from permission to edit the GPO.
- **SYSVOL_WRITE_ACCESS_DENIED**: review the selected GPO's GPMC delegation and its SYSVOL NTFS Effective Access. Repair consistency for that GPO only; do not grant broad write access to SYSVOL.
- **GPO_ACCESS_UNVERIFIED**: review metadata read access, connectivity, effective GPO/SYSVOL rights and target delegation. No remediation plan is issued until access is established.

After a permission/group change, disconnect and sign in again to obtain a fresh execution token. The application does not grant permissions itself. The target form displays the account, selected GPO and DN beside the remediation guidance. Failed selection and preview access checks are recorded as GPO_TARGET_ACCESS_BLOCKED / GPO_PREVIEW_ACCESS_BLOCKED with the actor, execution identity, target and error code; no password is logged.

## Validation and limits

Native Windows fixtures exercise a private local file with read-only, modify and deny-over-allow DACLs. Synthetic AD fixtures exercise distinct GPO/link/SYSVOL failures, unavailable metadata, user/machine extensions, unchanged links and link-order changes, stopped Preview/Apply paths and read-only scan bypass. Browser fixtures exercise all-target visibility, compatibility messages, all four access guidance codes, immediate checking without preview creation, delayed old-target response isolation, and clearing the error after a successful retry. They do not contact a real domain or modify live GPOs. An isolated domain pilot remains necessary to validate actual delegation, nested/deny AD permissions and environment-specific SYSVOL ACLs.
