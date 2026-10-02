# GPO Remediator — AD connection troubleshooting

Run these checks on the Windows management host that runs GPO Remediator. Example values below use `prosol.local` and `dc-01.prosol.local`.

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4
Resolve-DnsName dc-01.prosol.local
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.prosol.local
Test-NetConnection dc-01.prosol.local -Port 88
Test-NetConnection dc-01.prosol.local -Port 389
Test-NetConnection dc-01.prosol.local -Port 445
Test-NetConnection dc-01.prosol.local -Port 5985
Test-WSMan dc-01.prosol.local
Test-Path "\\dc-01.prosol.local\SYSVOL"
w32tm /query /source
w32tm /query /status
```

Expected results:

- the DC FQDN resolves through AD DNS;
- the AD SRV query returns a domain controller;
- Kerberos/KDC TCP 88 is reachable;
- LDAP 389 and SMB/SYSVOL 445 are reachable;
- WinRM HTTP 5985 is reachable and `Test-WSMan` succeeds;
- SYSVOL is accessible;
- Windows Time is checked and displayed. `Free-running System Clock` / `Local CMOS Clock` is a warning in 3.1.1 when Kerberos already succeeds; correct the PDC/NTP source before broad production rollout.

Test the real delegated path with Kerberos:

```powershell
$cred = Get-Credential "PROSOL\gpo-remediator"
Invoke-Command -ComputerName dc-01.prosol.local -Credential $cred -Authentication Kerberos -ScriptBlock {
    hostname
    whoami
    Import-Module ActiveDirectory
    Import-Module GroupPolicy
    Get-ADDomain | Select-Object DNSRoot,PDCEmulator
    Get-GPO -All | Select-Object -First 5 DisplayName,Id
}
```

Do not use `TrustedHosts` to bypass Kerberos. The production path is intentionally pinned to Kerberos and the selected writable DC.

## Diagnostic files

If Windows mode cannot start or remain healthy, inspect:

- `C:\ProgramData\GpoRemediator\State\windows-startup-error.log`
- `C:\ProgramData\GpoRemediator\State\bootstrap.log`
- `C:\ProgramData\GpoRemediator\State\server-error.log`
- `C:\ProgramData\GpoRemediator\State\preflight.log`
- `C:\ProgramData\GpoRemediator\Recovery`

Connection errors are separated into DNS, WinRM, Kerberos/authentication, remoting, and readiness categories so infrastructure faults are not reported as generic setup failures.
