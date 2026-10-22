/* Guided procedures only. Rendering/copying never submits or executes a command. */
(() => {'use strict';
const pair=(_fallback,en)=>({_fallback,en});
const securityRead=`$ErrorActionPreference = 'Stop'
$guideExport = Join-Path $env:TEMP ('security-review-' + [guid]::NewGuid().ToString('N') + '.inf')
secedit.exe /export /mergedpolicy /cfg $guideExport /areas SECURITYPOLICY /quiet
if ($LASTEXITCODE -ne 0) { throw 'Security policy export failed' }
Get-Content -LiteralPath $guideExport | Select-String 'AllowAdministratorLockout|LockoutBadCount|LockoutDuration|ResetLockoutCount|ForceLogoffWhenHourExpire'
Write-Output ('Review export: ' + $guideExport)`;
const contextRead=`Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, DomainRole
whoami.exe
gpresult.exe /scope computer /r`;
const definitions={
 '1.2.3':{
  mode:'Local security policy · guided manual change',
  desired:'Allow Administrator account lockout = Enabled',
  intent:'Allows the built-in local Administrator account to be locked after failed network sign-ins, including when that built-in account was renamed.',
  checks:'Check Windows/update support. Review a nonzero lockout threshold, duration and reset interval together. Confirm alternate administrator and console access first. Treat a DC as a separate domain-policy change.',
  procedure:'On the target, open elevated PowerShell and run the review/export commands. Open secpol.msc → Account Policies → Account Lockout Policy → Allow Administrator account lockout → Enabled. Stop if the setting is unavailable; do not invent a registry value. If domain/Intune policy owns it, change the authoritative management source.',
  verify:'Export again and confirm Enabled in the local policy UI. A missing export key means unknown, not Disabled. Test network-lockout behavior in a lab with a dedicated account; do not deliberately lock the production Administrator. Console and network sign-ins have different behavior.',
  rollback:'Record the original Defined/Not defined state and the three related lockout values. Restore only changed settings to their original state. Do not import the entire merged export; it can alter unrelated policies.',
  caveat:'This is not a general switch for every Administrators-group member. Failed attempts can temporarily deny remote administrator access.',
  read:securityRead,apply:'secpol.msc',sources:[['Microsoft KB5020282','https://support.microsoft.com/en-us/topic/kb5020282-account-lockout-available-for-built-in-local-administrators-bce45c4d-f28d-43ad-b6fe-70156cb2dc00']]
 },
 '2.3.11.6':{
  mode:'Local security policy · guided manual change',
  desired:'Network security: Force logoff when logon hours expire = Enabled',
  intent:'Controls SMB/file-share disconnection when account logon hours expire. It is not a general Windows-desktop or RDP sign-out command.',
  checks:'Review account logon hours, SMB-dependent applications and local/domain role. Do not generalize the behavior to administrator accounts. A local change on a DC can affect domain policy; do not apply this local procedure on a DC.',
  procedure:'On a member server/workstation, export before changing. Open secpol.msc → Local Policies → Security Options → Network security: Force logoff when logon hours expire → Enabled. Review authoritative domain account policy for domain accounts. Its Security Template key is ForceLogoffWhenHourExpire; EnableForcedLogOff is a different related policy.',
  verify:'Confirm Enabled in local policy and inspect ForceLogoffWhenHourExpire in the export. Validate behavior in a lab using restricted logon hours and an SMB session. A registry read alone, or an RDP session staying open, does not prove the result.',
  rollback:'Record the original Defined/Not defined and Enabled/Disabled state. Restore only this setting, not the entire security export. Rollback does not automatically reconnect terminated SMB sessions.',
  caveat:'Open file-share sessions can be interrupted and applications can fail. A behavior test requires configured logon-hour restrictions.',
  read:securityRead,apply:'secpol.msc',sources:[['Microsoft: Force logoff','https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-force-logoff-when-logon-hours-expire'],['Microsoft: Security Template format','https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/reset-user-rights-in-default-domain-group-policy']]
 }
};
function defender(id,property,desired,oobe){
 const value=desired?'$true':'$false';
 const read=`Get-Command Set-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty Parameters | Select-Object -ExpandProperty Keys | Where-Object { $_ -eq '${property}' }
Get-MpPreference -ErrorAction Stop | Select-Object ${property}
Get-MpComputerStatus -ErrorAction Stop | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, IsTamperProtected`;
 const apply=`$ErrorActionPreference = 'Stop'
$guideRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
if ($guideRole -ge 4) { throw 'This guided endpoint procedure excludes domain controllers' }
if (-not (Get-Command Set-MpPreference).Parameters.ContainsKey('${property}')) { throw 'Unsupported Defender parameter' }
$guideBefore = (Get-MpPreference).${property}
if ($guideBefore -isnot [bool]) { throw 'Previous value is unknown; stop' }
$guideStatus = Get-MpComputerStatus
if ($guideStatus.AntivirusEnabled -ne $true -or $guideStatus.AMRunningMode -ne 'Normal') { throw 'Defender is not active in Normal mode; review management first' }
if ($guideStatus.IsTamperProtected -eq $true) { throw 'Tamper Protection is enabled; use the approved management channel' }
$guideBackupPath = Join-Path $env:LOCALAPPDATA ('remediation-${id}-' + [guid]::NewGuid().ToString('N') + '.json')
[pscustomobject]@{ Control='${id}'; Computer=$env:COMPUTERNAME; Property='${property}'; Previous=$guideBefore; Applied=${value}; CapturedAt=(Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $guideBackupPath -Encoding UTF8
Write-Output ('Backup: ' + $guideBackupPath)
Set-MpPreference -${property} ${value} -ErrorAction Stop
if ((Get-MpPreference).${property} -ne ${value}) { throw 'Change not confirmed; inspect policy ownership and protection' }
Get-MpPreference | Select-Object ${property}`;
 const rollback=`$ErrorActionPreference = 'Stop'
# Replace with the exact backup path printed before Apply.
$guideBackupPath = 'C:\\REPLACE_WITH_EXACT_BACKUP_PATH.json'
$guideBackup = Get-Content -LiteralPath $guideBackupPath -Raw | ConvertFrom-Json
if ($guideBackup.Control -ne '${id}' -or $guideBackup.Property -ne '${property}' -or $guideBackup.Computer -ne $env:COMPUTERNAME -or $guideBackup.Previous -isnot [bool] -or $guideBackup.Applied -isnot [bool] -or $guideBackup.Applied -ne ${value}) { throw 'Backup does not match this control/endpoint' }
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { throw 'Domain controller excluded' }
$guideCurrent = (Get-MpPreference -ErrorAction Stop).${property}
if ($guideCurrent -ne $guideBackup.Applied) { throw 'Current value changed; review drift before rollback' }
if ((Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected -eq $true) { throw 'Use approved management; do not disable Tamper Protection' }
Set-MpPreference -${property} $guideBackup.Previous -ErrorAction Stop
if ((Get-MpPreference).${property} -ne $guideBackup.Previous) { throw 'Rollback not confirmed' }
Get-MpPreference | Select-Object ${property}`;
 return {
  mode:'Endpoint PowerShell · operator-run procedure',desired:`${property} = ${desired?'True':'False'}`,
  intent:oobe?'Enables Defender real-time protection and Security Intelligence updates during Windows initial setup (OOBE).':'Enables Defender IOAV checking for downloads and attachments. DisableIOAVProtection=False means protection is enabled.',
  checks:'Use elevated PowerShell on the selected endpoint. Check OS/Defender parameter support, Normal mode and GPO/Intune ownership. Change centrally managed settings at their source. Do not disable Tamper Protection. This example blocks DCs and protected/passive Defender modes.',
  procedure:'Run the read-only checks first. After approval, run the backup + apply block separately and retain the printed JSON backup path. Only this parameter is changed. The product does not execute the command for you.',
  verify:oobe?'Read True with Get-MpPreference. This proves configuration only; an installed endpoint does not prove OOBE behavior. Use a clean VM/initial-setup test for behavior.':'Check DisableIOAVProtection=False and independently inspect AntivirusEnabled, RealTimeProtectionEnabled and IoavProtectionEnabled. Correct configuration does not prove every file is safe.',
  rollback:'Use only the operator-held JSON backup created for this endpoint and replace the path placeholder. Restore validates endpoint/control and checks the current value still matches Apply; only the previous Boolean is restored. The JSON is not publisher-signed; keep it trusted.',
  caveat:'GPO/Intune can later overwrite local values. gpupdate /force is not part of this endpoint procedure. Results are not automatically recorded as product history or compliance evidence.',
  read,apply,restore:rollback,sources:[['Microsoft: Set-MpPreference','https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference'],['Microsoft: Defender CSP','https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp']]
 };
}
definitions['18.10.43.10.1']=defender('18.10.43.10.1','OobeEnableRtpAndSigUpdate',true,true);
definitions['18.10.43.10.2']=defender('18.10.43.10.2','DisableIOAVProtection',false,false);
const get=id=>Object.hasOwn(definitions,id)?definitions[id]:null;
function render(id,{state,esc,say}){
 const g=get(id);if(!g)return '';const text=p=>p['en'];
 const code=(label,value,kind)=>`<section class="content-card guide-command" data-guide-command="${kind}"><div class="card-title-row"><h3>${label}</h3><button type="button" data-copy-value="${esc(value)}">${'Copy'}</button></div><pre tabindex="0"><code>${esc(value)}</code></pre></section>`;
 return `<div class="guided-remediation" data-remediation-guide="${esc(id)}"><section class="content-card"><span class="card-kicker">GUIDED REMEDIATION · ${esc(id)}</span><h2>${esc(text(g.mode))}</h2><p class="guide-boundary">${'This page provides instructions. Viewing or copying starts no AD/GPO/endpoint operation; automatic Apply remains blocked.'}</p><p>${esc(text(g.intent))}</p><p><strong>${'Desired state'}:</strong> ${esc(g.desired)}</p><p>${esc(text(g.caveat))}</p></section><section class="content-card"><h3>1 · ${'Preflight'}</h3><p>${esc(text(g.checks))}</p></section>${code('Target and policy ownership · read-only',contextRead,'context')}${code('Current state · read-only',g.read,'read')}<section class="content-card"><h3>2 · ${'Remediation procedure'}</h3><p>${esc(text(g.procedure))}</p></section>${code(g.restore?'Backup + apply · changes the system':'Open local policy editor',g.apply,'apply')}<section class="content-card"><h3>3 · ${'Verify result'}</h3><p>${esc(text(g.verify))}</p><h3>4 · ${'Recovery procedure'}</h3><p>${esc(text(g.rollback))}</p></section>${g.restore?code('Rollback · restores previous value',g.restore,'rollback'):''}<section class="content-card"><h3>${'What happens behind the scenes?'}</h3><p>${'The product only renders the local guide. The operator runs endpoint commands on the target; the server does not send credentials, open WinRM or create backup/refresh/jobs. Manage a central GPO separately in GPMC if chosen. Reading instructions does not establish compliance.'}</p><h3>${'Official sources'}</h3><ul>${g.sources.map(([label,url])=>`<li><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a></li>`).join('')}</ul></section></div>`;
}
function dashboard({state,esc,say}){
 const rules=state.catalog?.rules||[],ready=rules.filter(r=>r.implementation==='live').length,guided=rules.filter(r=>r.implementation!=='live');
 const cards=[[rules.length,'Total controls','CIS catalog coverage','total','◇'],[ready,'Automatic GPO','Preview → Approve → Apply → Verify','auto','✓'],[guided.length,'Guided remediation','Local policy and endpoint PowerShell','guided','↗']];
 return `<section class="dashboard-remediation" data-dashboard-remediation aria-label="${'Remediation coverage'}"><div class="dashboard-remediation-cards">${cards.map(([count,label,copy,key,icon])=>`<article class="remediation-metric remediation-metric-${key}"><span class="remediation-metric-icon" aria-hidden="true">${icon}</span><div><span>${label}</span><b data-remediation-${key}>${count}</b><small>${copy}</small></div></article>`).join('')}</div><details class="dashboard-guided-details"><summary>${'How are the remaining eleven controls handled?'}<span>${'View guidance'} →</span></summary><p>${'Automatic Apply is blocked for these controls. Viewing/copying changes no system, starts no WinRM/gpupdate and creates no compliance evidence. Change centrally managed settings at their GPO/Intune source.'}</p><div class="dashboard-remediation-links">${guided.map(r=>`<button type="button" data-rule="${esc(r.id)}"><span><b>${esc(r.id)}</b><small>${r.id.startsWith('18.')?'Endpoint PowerShell':'Local policy'}</small></span><strong>${esc(r.title)}</strong><span aria-hidden="true">→</span></button>`).join('')}</div></details></section>`;
}
window.GpoRemediationGuides=Object.freeze({get,render,dashboard,ids:Object.freeze(Object.keys(definitions))});
})();
