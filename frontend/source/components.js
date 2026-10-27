/* Shared presentation components. No policy writes or invented progress. */
(() => {
  'use strict';
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const text=(s,_fallback,en)=>en;
  const paths={
    grid:'<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
    library:'<path d="M4 4h6v16H4zM10 4h6v16h-6zM18 4l3 15-3 1-3-15z"/>',
    publish:'<path d="M12 16V3m-5 5 5-5 5 5M4 14v6h16v-6"/>',
    network:'<rect x="8" y="2" width="8" height="5" rx="1"/><path d="M12 7v6M5 17v-4h14v4"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/>',
    shield:'<path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6zM8 12l3 3 5-6"/>',
    alert:'<path d="m12 3 10 18H2zM12 9v5m0 3v1"/>',activity:'<path d="M2 12h4l3-8 6 16 3-8h4"/>',
    settings:'<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="15" cy="17" r="3"/>',
    search:'<circle cx="10" cy="10" r="7"/><path d="m15 15 6 6"/>',refresh:'<path d="M20 7v5h-5M4 17v-5h5M19 12a7 7 0 0 0-12-5L4 10m16 4-3 3a7 7 0 0 1-12-5"/>',
    sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2"/>',
    moon:'<path d="M20 15A9 9 0 0 1 9 4a9 9 0 1 0 11 11z"/>',
    help:'<circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 2-3 4m0 3v1"/>',
    menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',panel:'<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/>',
    check:'<path d="m5 12 4 4L19 6"/>',clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    undo:'<path d="M3 9h12a6 6 0 0 1 0 12M3 9l5-5M3 9l5 5"/>',file:'<path d="M4 3h11l5 5v13H4zM15 3v5h5M8 12h8M8 16h8"/>',
    key:'<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-3-3 3-3m-6 0 3-3"/>',lock:'<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    folder:'<path d="M3 6h7l2 3h9v12H3z"/>',wifi:'<path d="M2 8a16 16 0 0 1 20 0M5 12a11 11 0 0 1 14 0m-11 4a5 5 0 0 1 8 0m-4 4v1"/>',
    user:'<circle cx="12" cy="7" r="4"/><path d="M4 22v-3a8 8 0 0 1 16 0v3"/>',close:'<path d="m5 5 14 14M5 19 19 5"/>',star:'<path d="m12 3 3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z"/>',chevron:'<path d="m9 5 7 7-7 7"/>'
  };
  function icon(name){return `<svg class="ui-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name]||paths.shield}</svg>`;}
  const domains={1:'key',2:'shield',3:'file',4:'user',5:'settings',6:'grid',7:'folder',8:'network',9:'shield',10:'network',11:'wifi',12:'key',13:'lock',14:'shield',15:'grid',16:'lock',17:'activity',18:'settings',19:'user'};
  function status(s,value){
    const v=String(value||'UNKNOWN').toUpperCase();
    const known={PUBLISHED:['Published','Published'],REFRESH_COMPLETED:['Refresh completed','Refresh completed'],VERIFIED_ON_ALL_TARGETS:['Verified on all pinned targets','Verified on all pinned targets'],NO_CHANGE:['No change','No change'],ROLLED_BACK:['Rolled back','Rolled back'],APPLYING:['Applying','Applying'],VERIFYING:['Verifying','Verifying'],FAILED_SAFE:['Safely stopped','Safely stopped'],DRIFT_DETECTED:['Drift detected','Drift detected'],VERIFY_MISMATCH:['Mismatch','Mismatch'],REVIEW_REQUIRED:['Needs review','Needs review'],VERIFIED_ON_SAMPLE:['Verified on sample','Verified on sample'],DOMAIN_VALUE_MATCHES_ON_SELECTED_DC:['Matches on selected DC','Matches on selected DC'],REPLICATION_PENDING:['Replication pending','Replication pending'],ENDPOINT_VERIFICATION_PENDING:['Endpoint verification pending','Endpoint verification pending'],REFRESH_SCHEDULED:['Refresh scheduled','Refresh scheduled'],ROLLBACK_ENDPOINT_PENDING:['Post-rollback verification pending','Post-rollback verification pending'],PUBLISHED_REFRESH_FAILED:['Published, refresh failed','Published, refresh failed']};
    const tone=v==='ROLLED_BACK'?'neutral':/FAIL|ERROR|DRIFT|MISMATCH|REVIEW|PARTIAL/.test(v)?'danger':/^(PUBLISHED|NO_CHANGE|VERIFIED_ON_SAMPLE|VERIFIED_ON_ALL_TARGETS|REFRESH_COMPLETED|DOMAIN_VALUE_MATCHES_ON_SELECTED_DC)$/.test(v)?'success':'pending';
    const symbol=v==='ROLLED_BACK'?'undo':tone==='danger'?'alert':tone==='success'?'check':'clock';
    const label=known[v]?text(s,...known[v]):v.replaceAll('_',' ');
    return {tone,label,icon:symbol,html:`<span class="ds-badge ds-${tone}">${icon(symbol)}${esc(label)}</span>`};
  }
  function breadcrumb(s,rule){const sections=s.catalog.sections,domain=sections.find(x=>!x.parentId&&rule.id.startsWith(x.id+'.')),section=sections.find(x=>x.id===rule.sectionId);return `<nav class="ds-breadcrumb" aria-label="${'Breadcrumb'}"><a href="#/benchmark">Benchmark</a>${domain?`<span aria-hidden="true">/</span><button data-breadcrumb-domain="${esc(domain.id)}">${esc(domain.title)}</button>`:''}${section&&section.id!==domain?.id?`<span aria-hidden="true">/</span><span>${esc(section.title)}</span>`:''}<span aria-hidden="true">/</span><strong aria-current="page">${esc(rule.id)}</strong></nav>`;}
  function operations(s,runs){return `<div class="ds-table-wrap"><table class="ds-table"><caption class="sr-only">${'Operations and recorded outcomes'}</caption><thead><tr>${['Control / GPO','Status','Operator','Time','Actions'].map(x=>`<th scope="col">${x}</th>`).join('')}</tr></thead><tbody>${runs.map(h=>`<tr><td><strong>${esc(h.plan?.selection?.setting||'GPO')}</strong><small>${esc(h.plan?.preview?.gpo?.name||'—')}</small></td><td>${status(s,h.result?.state).html}</td><td>${esc(h.plan?.executionUser||'—')}</td><td><time datetime="${esc(h.updatedAt||'')}">${window.GpoProduct.date(h.updatedAt,s.lang)}</time></td><td><button class="ds-button ds-secondary ds-sm" data-inspect="${esc(h.id)}">${'View details'}${icon('chevron')}</button>${h.result?.backupId&&!/^(ROLLBACK_DRIFT_DETECTED|BATCH_ROLLED_BACK|NO_CHANGE|APPLYING|ROLLBACKING|VERIFYING|REFRESHING)$/.test(h.result?.state||'')?`<button class="ds-button ds-danger ds-sm" data-inspect="${esc(h.id)}">${icon('undo')}${'Rollback'}</button>`:''}</td></tr>`).join('')}</tbody></table></div>`;}
  function timeline(s,h){const r=h.result||{},steps=[['Preview',!!h.plan],['Approval',!!h.approval],['Backup',!!r.backupId],['GPO write',r.gpoPublished===true],['Target link',r.linkVerified===true],['Replication',r.verification?.replicationConverged===true],['Effective result',window.GpoUiDomain.effectiveVerified(r.effectiveStatus)]];return `<ol class="ds-timeline" aria-label="${'Recorded stages'}">${steps.map(([label,done],index)=>`<li class="${done?'done':''}">${icon(done?'check':'clock')}<strong>${label}</strong><span>${r.state==='NO_CHANGE'&&[2,3].includes(index)?'Not required':done?'Confirmed in record':'Not confirmed'}</span></li>`).join('')}</ol><p class="ds-caption">${'Stages reflect the latest server record, not a live percentage.'}</p>`;}
  function domainEvidence(s){return `<section class="ds-evidence"><h2>${'Recorded outcomes by domain'}</h2><p>${'Summary of latest operations. No compliance score is inferred across GPOs and targets.'}</p><div class="ds-evidence-grid">${s.catalog.sections.filter(d=>!d.parentId).map(d=>{const rules=s.catalog.rules.filter(r=>r.id.startsWith(d.id+'.')),results=rules.map(r=>window.GpoProduct.controlStatus(s,r)),verified=results.filter(r=>r.tone==='good').length,review=results.filter(r=>r.tone==='warning').length,recorded=results.filter(r=>r.run).length;return `<button data-dashboard-domain="${esc(d.id)}" class="${review?'review':verified?'verified':''}"><span>${esc(d.id)} · ${esc(d.title)}</span><strong>${verified} / ${rules.length}</strong><small>${recorded?`${recorded} ${'recorded'} · ${review} ${'review'}`:'Not assessed'}</small></button>`;}).join('')}</div></section>`;}
  function skeleton(s){return `<section class="ds-loading" role="status" aria-live="polite"><h1>${'Loading workspace'}</h1><div class="ds-skeleton"></div><div class="ds-skeleton"></div><div class="ds-skeleton short"></div><p>${'Fetching benchmark and service information.'}</p></section>`;}
  function auditChain(s){const a=s.audit;if(!a)return '';const valid=a.integrityValid===true,broken=a.firstInvalidEventId;return `<section class="ds-chain ${valid?'valid':'broken'}" aria-label="${'Audit chain'}"><div>${icon(valid?'shield':'alert')}<strong>${valid?'Hash chain verified':'Hash chain mismatch'}</strong></div><p>${broken?`${'First invalid event'}: #${esc(broken)}`:valid?'The server verified hashes and links across the entire chain.':'Review required.'}</p><div class="ds-chain-nodes">${(a.events||[]).slice(0,10).map(e=>`<span class="${e.id===broken?'invalid':''}" title="${esc(e.hash)}">#${esc(e.id)}</span>`).join('<i aria-hidden="true"></i>')}</div></section>`;}
  function activity(s,runs){
    const items=window.GpoProduct.sortedRuns(runs).slice(0,8).map(h=>({h,start:Date.parse(h.startedAt||''),end:Date.parse(h.updatedAt||'')})).filter(x=>Number.isFinite(x.end));
    if(!items.length)return '';
    const min=Math.min(...items.map(x=>Number.isFinite(x.start)?Math.min(x.start,x.end):x.end)),max=Math.max(...items.map(x=>x.end)),range=Math.max(1,max-min);
    const duration=ms=>{const seconds=Math.round(ms/1000),days=Math.floor(seconds/86400),hours=Math.floor(seconds%86400/3600),minutes=Math.floor(seconds%3600/60);return days?`${days} ${'d'} ${hours} ${'h'}`:hours?`${hours} ${'h'} ${minutes} ${'min'}`:minutes?`${minutes} ${'min'} ${seconds%60} ${'sec.'}`:`${seconds} ${'sec.'}`;};
    return `<details class="ds-activity" open><summary>${icon('activity')}${'Operation timeline'}<span>${items.length} ${'recent records'}</span></summary><p class="ds-caption">${'Bars show the interval from start to last server update, not active execution time.'}</p><div class="ds-activity-list">${items.map(({h,start,end})=>{const known=Number.isFinite(start)&&start<=end;return `<button type="button" data-inspect="${esc(h.id)}" class="ds-activity-row"><span class="ds-activity-copy"><strong>${esc(h.plan?.selection?.setting||'GPO')} · ${esc(h.plan?.preview?.gpo?.name||'GPO')}</strong><small>${window.GpoProduct.date(h.updatedAt,s.lang)}</small></span><span class="ds-activity-track" aria-hidden="true"><i style="margin-left:${(known?start-min:end-min)/range*95}%;width:${known?Math.max(1,(end-start)/range*95):1}%"></i></span><span class="ds-activity-duration">${known?duration(end-start):'Start unavailable'}</span>${status(s,h.result?.state).html}${icon('chevron')}</button>`;}).join('')}</div></details>`;
  }
  function psQuote(value){return `'${String(value??'').replaceAll("'","''")}'`;}
  function registryPath(key){return String(key||'').replace(/^HKLM\\/i,'HKEY_LOCAL_MACHINE\\').replace(/^HKCU\\/i,'HKEY_CURRENT_USER\\');}
  function manualCheck(s,h,endpoint){
    // Scope/session placeholders are evidence context, never executable hosts.
    if(endpoint&&!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(String(endpoint?.hostname||'')))return '';
    const mapping=s.settings?.find(x=>x.id===h.plan?.selection?.setting),items=mapping?.items||mapping?.Items||[],handler=String(mapping?.handler||mapping?.Handler||'');
    let lines=[];
    if(/^Registry(Set)?$/i.test(handler)){
      const user=String(mapping?.scope||mapping?.Scope).toLowerCase()==='user',identity=h.plan?.selection?.verificationUser;
      if(user&&identity)lines.push(`$userSid = ([System.Security.Principal.NTAccount]${psQuote(identity)}).Translate([System.Security.Principal.SecurityIdentifier]).Value`);
      for(const item of items){const key=item.key||item.Key,name=item.name||item.Name;if(!key||!name)continue;
        const path=user&&identity?`('Registry::HKEY_USERS\\' + $userSid + ${psQuote('\\'+String(key).replace(/^HKCU\\/i,''))})`:psQuote('Registry::'+registryPath(key));
        if(user&&!identity)lines.push('# Run in the intended user session; HKCU belongs to the current PowerShell identity.');
        lines.push(`Get-ItemPropertyValue -LiteralPath ${path} -Name ${psQuote(name)} -ErrorAction Stop`);
        const profile=/\\WindowsFirewall\\(Domain|Private|Public)Profile/i.exec(key)?.[1];
        const firewallProperty={EnableFirewall:'Enabled',DefaultInboundAction:'DefaultInboundAction',DisableNotifications:'NotifyOnListen',LogFilePath:'LogFileName',LogFileSize:'LogMaxSizeKilobytes',LogDroppedPackets:'LogBlocked',LogSuccessfulConnections:'LogAllowed',AllowLocalPolicyMerge:'AllowLocalFirewallRules',AllowLocalIPsecPolicyMerge:'AllowLocalIPsecRules'}[name];
        if(profile&&firewallProperty)lines.push(`Get-NetFirewallProfile -Name ${psQuote(profile)} -PolicyStore ActiveStore | Format-List Name, ${firewallProperty}`);
      }
    }
    else if(/^SecurityTemplate$/i.test(handler)&&items.length&&items.every(x=>String(x.section||x.Section)==='System Access'&&['EnableGuestAccount','EnableAdminAccount','NewGuestName','NewAdministratorName'].includes(x.key||x.Key))){
      lines=["$localAccounts = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.PrincipalSource -eq 'Local' })"];
      for(const item of items){const key=item.key||item.Key,rid=['EnableGuestAccount','NewGuestName'].includes(key)?501:500;
        lines.push(`$account = @($localAccounts | Where-Object { [string]$_.SID -match '-${rid}$' })`,`if ($account.Count -ne 1) { throw ${psQuote('Exactly one local built-in RID '+rid+' account was not found. No account state was established.')} }`);
        lines.push(key.startsWith('Enable')?`$account | Select-Object Name, Enabled, SID, @{Name=${psQuote(key)};Expression={[int]$_.Enabled}}`:'$account | Select-Object Name, Enabled, SID');
      }
    }
    else if(/^SecurityTemplate$/i.test(handler)){
      const checks=items.filter(x=>x.key||x.Key).map(x=>`Select-String -LiteralPath $policyFile -Pattern ${psQuote('^\\s*'+String(x.key||x.Key).replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s*=')}`);
      lines=[`$policyFile = Join-Path $env:TEMP ([guid]::NewGuid().ToString('N') + '.inf')\ntry {\n  secedit.exe /export /mergedpolicy /cfg $policyFile /quiet | Out-Null\n  if ($LASTEXITCODE -ne 0) { throw 'secedit export failed' }\n  ${checks.join('\n  ')}\n} finally { Remove-Item -LiteralPath $policyFile -Force -ErrorAction SilentlyContinue }`];
    }
    else if(/^AdvancedAudit$/i.test(handler))lines=[...items.filter(x=>x.guid||x.Guid).map(x=>`auditpol.exe /get /subcategory:"${String(x.guid||x.Guid).replaceAll('"','')}"`),`Get-ItemPropertyValue -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -ErrorAction Continue`];
    if(!lines.length)lines=[`gpresult.exe /scope ${String(mapping?.scope||mapping?.Scope).toLowerCase()==='user'?'user':'computer'} /r`];
    const host=String(endpoint?.hostname||'').split('.')[0];
    // Keep the guard and probe in one block. A terminating error on the first
    // pasted line must not leave subsequent console statements free to run.
    return host?`& {\n  if ($env:COMPUTERNAME -ine ${psQuote(host)}) { throw ${psQuote('Wrong computer. Run this check on endpoint '+endpoint.hostname+'. No policy value was read.')} }\n${lines.join('\n').split('\n').map(line=>'  '+line).join('\n')}\n}`:lines.join('\n');
  }
  function rollbackCheck(s,h){
    const item=s.rollbackChecks?.[h.id],age=Date.now()-(item?.at||0);
    return item&&item.updatedAt===h.updatedAt&&item.state===h.result?.state&&item.processId===s.service?.processId&&item.session===s.gpoSession&&age>=0&&age<60000?item.result:null;
  }
  function refreshAction(s,h){
    const r=h.result||{},busy=/^(APPLYING|ROLLBACKING|VERIFYING|REFRESHING)$/.test(r.state||''),offline=s.serviceOffline||s.serviceTransition||!s.gpoSession?.connected;
    const known=r.state==='ROLLED_BACK'||r.gpoPublished===true&&r.linkVerified===true&&['PUBLISHED','NO_CHANGE','REVIEW_REQUIRED','REFRESH_COMPLETED','REFRESH_PARTIAL','REFRESH_SCHEDULED','PUBLISHED_REFRESH_FAILED'].includes(r.state);
    const user=window.GpoUiDomain.isUserPolicy(h,s.settings||[]),choices=window.GpoUiDomain.refreshChoices(h,s.settings||[]);
    const enabled=known&&!busy&&!offline&&choices.length>0;
    const reason=offline?'Reconnect the service and delegated session before endpoint refresh.':busy?'Wait for the current operation to finish.':!known?'Run read-only Re-verify first. A published GPO/link or a verified restored snapshot is required before endpoint refresh.':!choices.length?'This recorded user-policy plan has no session endpoint OU. Create a fresh plan with the computers where affected users sign in.':'';
    return `<button type="button" class="ds-button ds-secondary ds-sm" data-gpupdate="${esc(h.id)}" ${enabled?'':'disabled aria-disabled="true"'}>${icon('refresh')}${r.state==='ROLLED_BACK'?'gpupdate /force after rollback':user?'Run gpupdate /target:user /force':'Run gpupdate /force'}</button>${reason?`<p class="ds-caption refresh-block-reason">${esc(reason)}</p>`:''}`;
  }
  function recovery(s,h){
    const r=h.result||{},busy=/^(APPLYING|ROLLBACKING|VERIFYING|REFRESHING)$/.test(r.state||''),offline=s.serviceOffline||s.serviceTransition||!s.gpoSession?.connected;
    const check=rollbackCheck(s,h),available=!!r.backupId&&check?.canRestore===true&&!busy&&!offline;
    const inspection=check?`<section class="rollback-assessment"><strong>${check.canRestore?'Snapshot state permits a guarded restore':'Automatic restore blocked'}</strong><p>${esc(check.message||'')}</p><dl><dt>Manifest phase</dt><dd>${esc(check.manifestPhase||'Not reported')}</dd><dt>Reason</dt><dd>${esc(check.reason||'Unknown')}</dd><dt>Checked at (UTC)</dt><dd>${esc(check.checkedAt||'Not reported')}</dd></dl>${check.failure?`<p><strong>Last retained failure</strong></p><p>${esc(check.failure.code||'')} · ${esc(check.failure.stage||'')}</p><p>${esc(check.failure.message||'')}</p>`:''}<p class="ds-caption">The full GPO snapshot may affect every linked scope. Restore rechecks live drift and permissions under a lock.</p></section>`:'';
    const choices=window.GpoUiDomain.refreshChoices(h,s.settings||[]);
    return `<section class="ds-recovery"><h3>${icon('undo')}Rollback & endpoint refresh</h3><p>${busy?'An operation is in progress.':!r.backupId?'No completed backup is recorded.':'Inspect the retained backup and live GPO before confirming another full-GPO restore.'}</p>${r.backupId?`<dl><dt>Backup</dt><dd>${esc(r.backupId)}</dd></dl><button type="button" class="ds-button ds-secondary ds-sm" data-rollback-inspect="${esc(h.id)}" ${busy||offline?'disabled':''}>Check rollback availability</button>`:''}${inspection}${available?`<form data-rollback="${esc(h.id)}"><label>Type ROLLBACK to confirm<input name="confirmation" placeholder="ROLLBACK" pattern="ROLLBACK" autocomplete="off" required></label><label>gpupdate /force after rollback<select name="refresh"><option value="None">Do not schedule refresh</option>${choices.map(x=>`<option value="${esc(x.value)}">${esc(x.label)}</option>`).join('')}</select><small>Only the recorded operation targets are eligible.</small></label><button type="submit" class="ds-button ds-danger" ${s.service?.writesEnabled===false?'disabled':''}>${icon('undo')}Rollback</button></form>`:''}<button type="button" class="ds-button ds-secondary ds-sm" data-verify="${esc(h.id)}" ${busy||offline?'disabled':''}>${icon('refresh')}Re-verify</button>${refreshAction(s,h)}${(r.refreshResults||[]).length?`<ul class="ds-refresh-results">${r.refreshResults.map(x=>`<li><strong>${esc(x.computer)}</strong><span>${esc(x.state)}</span><small>${esc(x.message)}</small></li>`).join('')}</ul>`:''}</section>`;
  }
  function assuranceStages(s,stages){
    const names={GPO_CONFIGURATION:['GPO configuration','GPO configuration'],GPO_APPLICABILITY:['Target applicability','Target applicability'],AD_SYSVOL_REPLICATION:['Controller replication','Controller replication'],CLIENT_PROCESSING:['Endpoint refresh','Endpoint refresh'],ENDPOINT_CONFIGURATION:['Actual endpoint value','Actual endpoint value']};
    const good=new Set(['GPO_APPLIED','VERIFIED','ENDPOINT_VERIFIED','GPUPDATE_COMPLETED']),bad=new Set(['FAILED','ENDPOINT_MISMATCH','PARTIAL_SUCCESS']),pending=new Set(['GPUPDATE_SCHEDULED','GPUPDATE_STARTED','REPLICATION_PENDING','INSUFFICIENT_EVIDENCE']);
    const supplemental=x=>['GPO_APPLICABILITY','CLIENT_PROCESSING'].includes(x.stage);
    const render=x=>{
      const offline=s.serviceOffline||s.serviceTransition;
      const tone=offline?'neutral':good.has(x.status)?'good':bad.has(x.status)?'bad':supplemental(x)&&['GPUPDATE_SCHEDULED','GPUPDATE_STARTED','INSUFFICIENT_EVIDENCE','NOT_TESTED'].includes(x.status)?'info':pending.has(x.status)?'pending':'neutral';
      const label=good.has(x.status)?'Verified':bad.has(x.status)?'Mismatch / failure':x.status==='GPUPDATE_SCHEDULED'?'Scheduled':x.status==='GPUPDATE_STARTED'?'In progress':x.status==='INSUFFICIENT_EVIDENCE'?'More evidence needed':x.status==='REPLICATION_PENDING'?'Replication pending':'Not verified';
      const name=names[x.stage]||[x.stage,x.stage];
      const explanation=x.stage==='CLIENT_PROCESSING'&&x.status==='GPUPDATE_SCHEDULED'?'The request was scheduled; completion is unconfirmed. This is independent of the measured result.':x.stage==='GPO_APPLICABILITY'&&x.status==='INSUFFICIENT_EVIDENCE'?'A GPO link exists. RSoP is needed to establish whether this GPO won on the endpoint.':'';
      return `<article class="assurance-stage ${tone}"><span class="assurance-indicator" aria-hidden="true">${tone==='good'?'✓':tone==='bad'?'!':tone==='info'?'i':tone==='pending'?'◷':'—'}</span><div><header><strong>${text(s,name[0],name[1])}</strong><span class="assurance-label">${offline?'Recorded: ':''}${label}</span></header>${explanation?`<p class="assurance-context">${explanation}</p>`:''}<details><summary>${'Evidence details'}</summary><p>${esc(x.evidence)}</p><code>${esc(x.stage)} · ${esc(x.status)}</code></details></div></article>`;
    };
    const primary=stages.filter(x=>!supplemental(x)),extra=stages.filter(supplemental);
    return `<div class="assurance-stage-list" aria-label="${'Verification stages'}"><div class="assurance-group-heading"><strong>${'Measured results'}</strong><p>${'Results cover only the selected control and sampled endpoints. They do not establish compliance for other controls or the whole domain.'}</p></div>${primary.map(render).join('')}${extra.length?`<div class="assurance-group-heading"><strong>${'Policy source and refresh'}</strong><p>${'These details are separate from the measured value. A scheduled refresh is not a completed refresh.'}</p></div>${extra.map(render).join('')}`:''}</div>`;
  }
  window.GpoComponents=Object.freeze({esc,text,icon,domainIcon:id=>icon(domains[id]||'shield'),status,breadcrumb,operations,timeline,domainEvidence,skeleton,auditChain,activity,recovery,rollbackCheck,refreshAction,manualCheck,assuranceStages});
})();
