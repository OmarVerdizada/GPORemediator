# 3.16.1 — endpoint refresh diagnostics

An enabled GPO link and a matching GPO value do not establish that an endpoint processed the policy. In particular, a failed refresh and an unavailable endpoint probe must remain visible after read-only verification reports the GPO as published.

- Show per-host refresh messages and completed counts beside the verification result. Keep failed refreshes in the attention state after re-verification; preserve rollback and measured mismatch outcomes.
- Retain a bounded, product-owned error classification for denied endpoint access, authentication failure, connection failure and other probe failures. Never return raw exception text or credentials. Preserve successful hosts when other hosts fail.
- Stop generated manual checks before reading any policy value when the computer name differs from the selected endpoint. The guard and probe are one PowerShell script block, so pasting several statements cannot continue past the guard.
- Use the active theme surface for the result panel. The old undefined surface token could leave a white panel with nearly white text in dark mode.

## Endpoint permission boundary

GPO **Edit settings**, OU/domain **Link GPOs**, and backup-directory **Modify** are independent of endpoint permissions. In the current application, computer refresh uses an explicit delegated credential with Kerberos/WinRM from the selected DC to each endpoint, then runs `gpupdate /target:computer /force /wait:-1`. Native security-policy verification uses `secedit` on that endpoint.

The default Windows PowerShell session typically permits local Administrators. An administrator can delegate Execute on the session, but that alone does not grant privileges needed by every native probe. Remote Management Users membership must not be assumed sufficient for the default session or for security-policy export. Domain Admin membership is unnecessary; any chosen endpoint administration rights should be limited to the intended member computers. Local invocation of gpupdate does not universally require administrator rights and can also be constrained by policy. Automatic Group Policy processing does not require the operator to be a local administrator.

## Diagnosing a failed target

Run these read-only checks **on the selected DC**, matching the application's connection origin. Enter the same execution account; do not paste its password into a script or chat.

```powershell
$target = 'PSLWSUS01.prosol.local'
Test-NetConnection -ComputerName $target -Port 5985
$cred = Get-Credential 'PROSOL\gpor.operator'
Invoke-Command -ComputerName $target -Authentication Kerberos -Credential $cred -ErrorAction Stop -ScriptBlock {
    whoami
    $env:COMPUTERNAME
    [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
```

A successful TCP probe proves reachability, not authentication or authorization. A denied remote session should be investigated at that endpoint's session ACL and effective logon rights. A successful remote session with failing native commands requires checking that command's privileges. If refresh exits nonzero, review the endpoint GroupPolicy Operational log and resulting policy; do not rerun Apply merely to retry refresh.

For a password-length policy linked to a member-computer OU, verify **local account policy on those computers**. This does not set the password policy of AD users in that OU. Use the separate Password policies/FGPP workflow for scoped domain-user password requirements.

## Validation boundary

Local tests execute the actual refresh dispatcher and probes with transport/native-command doubles, generated-command parsing and wrong-host execution guards, UI result rendering, and the backup/write/link/rollback fixture chain. They do not establish live connectivity, endpoint effective access, refresh completion or policy precedence in another AD environment.

References: [PowerShell remoting requirements](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-5.1), [Group Policy processing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing), [non-administrator machine refresh policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-grouppolicy#disableusersfrommachgp).
