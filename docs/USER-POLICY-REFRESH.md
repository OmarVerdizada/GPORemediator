# Refreshing user policies

A user GPO links to the OU containing user accounts. User policy processing happens on the computers where those users sign in. The user OU therefore does not identify a list of session computers.

## Prepare and run

1. On **Target & apply**, select the user GPO and user OU.
2. Select the separate **user-session endpoint OU**, containing the computers where the affected users sign in. Endpoint discovery uses that OU and its child OUs, subject to the configured endpoint authorization.
3. Leave the verification user blank for OU-wide publication and refresh, or enter a user for a sampled loaded-profile HKCU check. This field does not narrow the GPO to one user.
4. Generate and review the plan, then record Apply. If policy content and link already match, a fresh plan can record no change rather than writing the policy again.
5. In the recorded result, choose **Run gpupdate /target:user /force**, review **User sessions on endpoint OU computers**, and confirm.

An older plan without an endpoint OU cannot safely invent the session hosts. Prepare a fresh plan with the endpoint OU. Changing the current draft does not retarget an old operation.

Remote user refresh uses Invoke-GPUpdate with Target User. Scheduling is based on computers and their signed-in users; it is not restricted to the optional verification user. Windows still evaluates links, security filtering, WMI, inheritance and loopback. A schedule can therefore refresh other signed-in users' applicable policies on those same computers. Users who are not signed in may need their next logon/normal processing cycle.

GPO edit/link permission and WinRM access do not automatically grant remote task-scheduling access. The endpoint must permit the scheduling identity and the required RPC/WMI/task-scheduler communication. Review these endpoint permissions separately; do not grant Domain Admin or broad SYSVOL access merely to fix refresh. Scheduling failures remain per-host failures. The application does not force logoff or reboot.

## Manual check in the affected user's own session

On that user's computer, open an ordinary command prompt as the affected user:

```powershell
gpupdate.exe /target:user /force
gpresult.exe /scope user /r
Get-ItemPropertyValue -LiteralPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'ScanWithAntiVirus'
```

For control 19.7.5.2, the requested GPO value in this workflow is 3. Read the resulting value in the intended user's session. Running HKCU checks as Administrator or gpor.operator reads that account's hive, which can differ from the affected user's settings. A matching value alone does not establish which GPO supplied it. An absent property or an unavailable profile remains unverified.

**Published** establishes GPO configuration/link evidence. **Scheduled** establishes a remote scheduling request. Neither establishes that every user has received the policy. Review per-host failures and collect resulting user policy evidence separately.

Microsoft references: [Invoke-GPUpdate and Target User](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/invoke-gpupdate), [remote Group Policy refresh and signed-in sessions](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj134201(v=ws.11)).
