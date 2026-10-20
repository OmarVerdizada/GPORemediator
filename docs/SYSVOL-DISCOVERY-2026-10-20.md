# Delegated SYSVOL discovery

A delegated operator can connect with WinRM and access SYSVOL while CIM
`Win32_Share` enumeration returns Access denied. Previously both readiness and
GPO file operations depended on that query, incorrectly blocking those operators.

The worker now reads `SysVol` and `SysvolReady` from the selected DC's local
`HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` registry key.
It requires readiness 1, an absolute local drive path and an accessible domain
Policies directory. This supports relocated and DFSR paths without guessing the
Windows directory or using another DC/UNC hop. Missing configuration and access
errors still fail closed; readiness reports the execution account and actual
exception. No registry values or permissions are modified.

Microsoft documents the active SysVol location in Netlogon parameters:
https://support.microsoft.com/en-us/topic/virus-scanning-recommendations-for-enterprise-computers-that-are-running-windows-or-windows-server-kb822158-c067a732-f24a-9079-d240-3733e39b40bc

The same resolver is included in generated manual procedures. GPO-specific AD,
SYSVOL effective write checks, backup permissions and Apply checks remain in
force. A successful readiness check alone does not authorize a GPO change.

`scripts/Test-SysvolDiscovery.ps1` exercises relocated paths, expansion, denied
registry/directory reads, missing directories, unready SYSVOL and nonlocal paths
using synthetic fixtures. `Test-SelectionAccess.ps1` retains the effective rights
regressions. Live delegated AD validation must be repeated after updating.
