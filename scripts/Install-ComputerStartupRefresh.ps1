# One-time setup on a domain member. The task action is the Windows executable.
[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference = 'Stop'
$machine = Get-CimInstance Win32_ComputerSystem
if (!$machine.PartOfDomain -or $machine.DomainRole -notin 1,3) {
    throw 'Run this installer on a domain member workstation or member server.'
}
$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'One-time task installation requires a local administrator or endpoint management.'
}
$name = 'GPO Remediator - Computer policy at startup'
$executable = Join-Path ([Environment]::SystemDirectory) 'gpupdate.exe'
$arguments = '/target:computer /force /wait:-1'
$existing = Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $name
if ($existing) {
    $action = @($existing.Actions)
    $trigger = @($existing.Triggers)
    if ($action.Count -ne 1 -or $action[0].Execute -ne $executable -or $action[0].Arguments -ne $arguments -or
        $existing.Principal.UserId -notin 'SYSTEM','S-1-5-18','NT AUTHORITY\SYSTEM' -or
        $trigger.Count -ne 1 -or $trigger[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger' -or
        $trigger[0].Delay -ne 'PT1M' -or !$trigger[0].Enabled -or !$existing.Settings.Enabled) {
        throw 'A task with this name exists with different settings. Inspect it in Task Scheduler.'
    }
    Write-Output "Already installed on $env:COMPUTERNAME. Computer refresh is scheduled one minute after startup."
    return
}
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Register $name")) {
    $action = New-ScheduledTaskAction -Execute $executable -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT1M'
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $action -Trigger $trigger -Settings $settings `
        -User 'SYSTEM' -Description 'Refresh computer Group Policy one minute after startup.' -ErrorAction Stop | Out-Null
    Get-ScheduledTask -TaskName $name -TaskPath '\' | Select-Object TaskName,State
}
