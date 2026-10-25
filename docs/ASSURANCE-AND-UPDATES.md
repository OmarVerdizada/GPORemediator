# Permissions, policy explanations, pilot and release updates

## Exact access report

Open **Access & evidence**. Select a discovered GPO, OU/domain and control, then choose **Check exact permissions**. The report shows the execution account, selected DC, exact AD object/file targets and the required authority. It does not grant permissions or edit policy. Backup readiness may create/delete disposable probe files.

GPO **Edit settings**, target **Link GPOs**, SYSVOL access, backup workspace access and PSO delegation are separate rights. An unchanged link does not require a link edit. Do not resolve a selected-GPO failure by granting broad write access to SYSVOL. A PSO creation capability does not establish permission to edit an existing PSO, change its subjects or delete it. UNKNOWN means the tool could not establish the right; it does not mean ALLOWED.

## Explain an endpoint result

Choose a recorded operation and one of its pinned endpoints, then **Read RSoP and processing events**. The server validates the original operator/execution context and current target membership before remote access. The explicit delegated credential is used with Kerberos.

The report keeps three kinds of evidence separate:

- Logged per-setting RSoP source/precedence, including a competing winning GPO, recorded security denial or WMI filter failure.
- Current values read by the native verifier.
- Recent GroupPolicy Operational events and generic pending-restart indicators.

Logged RSoP can be stale. An absent GPO alone does not establish a filtering cause. Native value equality alone does not establish which GPO supplied it. Missing read permissions, unsupported providers and incomplete records produce partial/unknown evidence. No refresh or restart is triggered. Domain-user account policy receives domain context guidance rather than misleading workstation local-account attribution. User RSoP requires the selected verification user and a recorded user namespace on the endpoint.

Per-setting attribution supports registry policy, SecurityTemplate System Access and Privilege Rights provider records. Advanced audit has no mapped per-setting RSoP attribution here. The report states that limitation and retains the native value/event evidence. Reads are bounded to 500 GPO records, 10,000 records per setting-provider class and 20 events from the last day; truncation is explicit.

Provider references: [RSOP_GPO](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-gpo), [RSOP_RegistryPolicySetting](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-registrypolicysetting), [RSOP_SecuritySettingNumeric](https://learn.microsoft.com/en-us/previous-versions/aa375064(v=vs.85)), [RSOP_UserPrivilegeRight](https://learn.microsoft.com/en-us/previous-versions/aa375080(v=vs.85)).

## Reconcile an OU password-policy snapshot

In **Password policies**, open an operation and choose **Compare current OU membership**. This creates a fresh preview of the same policy/OU. Review additions, removals, unchanged subjects, identities moved within the OU and departures since the last applied user snapshot. Download evidence for the complete lists; the screen bounds individual lists to 100 rows.

Only a newly confirmed **APPLY FGPP** reconciles PSO assignments. Preview does not modify membership. Apply rechecks both the previous PSO and current enabled OU users; intervening changes block the write. Direct PSO subjects are snapshots, not a live OU association. A GPO on a computer OU controls local accounts; domain-user OU passwords use FGPP.

## Live pilot in the AD environment

Run the application on the management host in that environment. Use a dedicated unprotected GPO linked only to a dedicated pilot OU with 1–5 enabled, DNS-addressable computers. Pass readiness and authorize that exact GPO/OU through the application. The change gate must already be enabled. Choose an automated computer control with a real value change and no custom-input or restart requirement.

From the complete release folder:

```powershell
.\scripts\Invoke-LivePilot.ps1 `
  -GpoId 'PILOT-GPO-GUID' `
  -OuDn 'OU=Pilot,DC=example,DC=local' `
  -ControlId 'REVIEWED-CONTROL-ID' `
  -MaxComputers 5 `
  -Confirmation 'RUN PILOT'
```

The runner prompts for the delegated account locally. Do not put passwords in a command or chat. Only a loopback application origin is accepted. It captures native baseline values, previews, applies with backup, completes computer gpupdate, verifies full endpoint/replication evidence, requests guarded rollback and compares the resulting endpoint values with the baseline. A no-op does not certify the write path. Unknown transport outcomes are not blindly retried. Inspect the recorded operation/DC manifest if recovery requires review.

Private JSON reports are written below `%LOCALAPPDATA%\GpoRemediator\PilotReports`. Exit code 0 and CONFIGURATION_LIFECYCLE_VERIFIED require the full checked lifecycle. This confirms only the chosen configuration/targets; it does not certify every control's runtime requirements. The release's local tests use fixtures. **A live AD pilot was not run in the development environment.**

## Install or update the complete release

Download the full release ZIP and its separately trusted SHA-256. Extract the installer and its scripts from that package, then run:

```powershell
.\Install-GpoRemediator.ps1 `
  -PackagePath 'C:\Downloads\GPORemediator-3.16.0-full.zip' `
  -ExpectedSha256 'TRUSTED-64-CHARACTER-SHA256' `
  -DesktopShortcut
```

The default install root is `%LOCALAPPDATA%\Programs\GpoRemediator`. A dedicated empty folder can be supplied with `-Destination`. Hashes detect incomplete/mixed files; they do not authenticate a publisher. Obtain the expected hash through a trusted release channel. A ZIP-adjacent `.sha256` containing only the digest is accepted if `-ExpectedSha256` is omitted.

The installer validates every application component against `release/package-files.json`, stages an immutable version and then atomically activates it through `current.json`. Start through the installed root's `GpoRemediator.cmd`, which revalidates the active release. Keep the whole release together; do not replace only the EXE or frontend. Application configuration, databases, backup contents and delegated credentials are not copied into version folders. Existing ProgramData state remains in place; credentials still require sign-in after restart.

Close the application before updating, or add `-StopRunning` to request its idle-safe stop. An active job prevents the stop/activation; the installer never kills it. Failed staging leaves the active pointer intact and can be retried. Staged/previous version folders are retained for review and recovery. To reactivate the previous compatible installed release:

```powershell
.\Install-GpoRemediator.ps1 -Rollback
```

This rolls back application activation, not policy/database contents. State-schema changes require a reviewed migration; the installer blocks automatic activation across incompatible schemas. Optional `-Start` launches the selected version; `-DesktopShortcut` creates a shortcut to the stable launcher.

## Large directories and journals

Operations render 50 rows per page, audit 100, GPO selection 80 and the expanded OU tree 240. Filtering runs across the full loaded list, so later entries remain discoverable. OU indexes are cached for an inventory snapshot. Exports retain complete loaded evidence. This release bounds DOM rendering; it does not claim server-side journal streaming or unlimited AD inventory.
