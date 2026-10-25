/* GPO Remediator – evidence-only reporting and read-only environment diagnostics.
   This module never performs a policy mutation. */
(() => {
  'use strict';
  const safe = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const dateText = v => { const d=new Date(v||'');return Number.isFinite(d.getTime())?d.toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'}):'—'; };
  const csvCell = v => {
    let s=String(v??'').replace(/[\x00-\x08\x0B-\x1F]/g,' ').replace(/[\r\n]+/g,' ');
    // Prevent spreadsheet formula injection when files are opened in Excel.
    if(/^[\s]*[=+\-@]/.test(s))s="'"+s;
    return '"'+s.replace(/"/g,'""')+'"';
  };
  const schema='gpo-remediator.recorded-evidence.v1';
  const bad = v => /FAIL|MISMATCH|DRIFT|PARTIAL|REVIEW|ERROR/.test(String(v||'').toUpperCase());
  function record(run){
    const p=run?.plan||{},s=p.selection||{},v=p.preview||{},result=run?.result||{},meta=result.verification||{};
    const effective=String(result.effectiveStatus||'UNKNOWN'), state=String(result.state||'UNKNOWN');
    const verified=!!(result.gpoPublished===true&&result.linkVerified===true&&meta.replicationConverged===true&&
      (effective==='VERIFIED_ON_SAMPLE'||effective==='VERIFIED_ON_ALL_TARGETS'||effective==='DOMAIN_VALUE_MATCHES_ON_SELECTED_DC')&&window.GpoUiDomain.coverageVerified(result)&&!bad(state)&&state!=='ROLLED_BACK');
    const status=bad(state)||bad(effective)?'NEEDS_REVIEW':verified?'EVIDENCE_VERIFIED':'NOT_FULLY_VERIFIED';
    return {id:String(run?.id||''),controlId:String(s.setting||''),date:String(run?.updatedAt||run?.startedAt||''),
      operator:String(p.actor||''),executionUser:String(p.executionUser||''),domain:String(p.domain||''),
      gpo:String(v.gpo?.name||''),gpoId:String(s.gpoId||''),scopeDn:String(s.scopeDn||''),
      before:v.previousValue??null,requested:v.desiredValue??null,observed:result.currentValue??null,
      state,effectiveStatus:effective,status,publication:result.gpoPublished===true,linkVerified:result.linkVerified===true,
      replicationConverged:meta.replicationConverged===true,replicationCheckedAt:meta.checkedAt||null,
      endpointChecks:(result.endpointChecks||[]).map(x=>({host:String(x.hostname||''),state:String(x.state||''),message:String(x.message||''),actualValue:x.actualValue??null})),
      endpointCoverage:result.endpointCoverage??null,refreshCoverage:result.refreshCoverage??null,
      backupId:result.backupId||null,changeReference:run?.approval?.changeReference||null,
      approvedBy:run?.approval?.approvedBy||null,correlationId:run?.correlationId||null,
      note:String(result.message||'')};
  }
  function collect(state,filters={}){
    const entries=(state.history||[]).map(record)
      .filter(x=>!filters.scope||x.scopeDn.toLowerCase().includes(filters.scope.toLowerCase()))
      .filter(x=>!filters.gpo||x.gpoId===filters.gpo)
      .filter(x=>!filters.status||filters.status==='ALL'||x.status===filters.status)
      .filter(x=>!filters.since||!!x.date&&x.date.slice(0,10)>=filters.since)
      .sort((a,b)=>b.date.localeCompare(a.date));
    const catalog=state.catalog?.rules||[],tracked=new Set(entries.map(x=>x.controlId));
    return {schema,generatedAt:new Date().toISOString(),scope:'Recorded operations visible to the signed-in operator, not a full domain compliance assessment',
      benchmark:state.catalog?.meta?.benchmark||'CIS Windows Server 2022 v4.0.0',
      knownControls:catalog.length,controlsWithRecordedOperations:tracked.size,
      controlsWithoutRecordedOperations:Math.max(0,catalog.length-tracked.size),
      count:entries.length,verifiedEvidence:entries.filter(x=>x.status==='EVIDENCE_VERIFIED').length,
      reviewRequired:entries.filter(x=>x.status==='NEEDS_REVIEW').length,unverified:entries.filter(x=>x.status==='NOT_FULLY_VERIFIED').length,
      filters:{...filters},entries};
  }
  function csv(data){
    const cols=['date','controlId','gpo','gpoId','scopeDn','before','requested','observed','state','effectiveStatus','status','publication','linkVerified','replicationConverged','backupId','changeReference','operator','executionUser','correlationId','note'];
    return '\uFEFF'+cols.map(csvCell).join(',')+'\r\n'+data.entries.map(e=>cols.map(k=>csvCell(e[k])).join(',')).join('\r\n')+'\r\n';
  }
  function html(data){
    const rows=data.entries.map(e=>`<tr><td>${safe(dateText(e.date))}</td><td>${safe(e.controlId)}</td><td>${safe(e.gpo)}</td><td>${safe(e.scopeDn)}</td><td>${safe(e.before??'—')} → ${safe(e.requested??'—')}</td><td>${safe(e.observed??'—')}</td><td>${safe(e.status)}<small>${safe(e.effectiveStatus)}</small></td><td>${safe(e.backupId??'—')}</td></tr>`).join('');
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GPO Recorded Evidence</title>'+ '<style>body{font:13px system-ui,Arial;color:#172435;padding:28px}h1{margin-bottom:5px}p{color:#4b5563}.summary{display:flex;gap:22px;margin:22px 0}.summary b{font-size:20px}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #ddd;padding:9px;vertical-align:top;overflow-wrap:anywhere}th{background:#eef2f7}small{display:block;color:#64748b}.foot{margin-top:20px;font-size:11px}@media print{body{padding:0}thead{display:table-header-group}tr{break-inside:avoid}@page{size:A4 landscape;margin:12mm}}</style></head><body>'+`<h1>GPO Remediator — Recorded Evidence</h1><p>${safe(data.benchmark)} · Generated ${safe(dateText(data.generatedAt))}</p><p><strong>Scope restriction:</strong> ${safe(data.scope)}</p><div class="summary"><span>Records <b>${data.count}</b></span><span>Evidence verified <b>${data.verifiedEvidence}</b></span><span>Needs review <b>${data.reviewRequired}</b></span><span>Not fully verified <b>${data.unverified}</b></span><span>Controls without records <b>${data.controlsWithoutRecordedOperations}</b></span></div><table><thead><tr><th>Date</th><th>CIS</th><th>GPO</th><th>OU / domain</th><th>Before → target</th><th>Observed</th><th>Evidence status</th><th>Backup ID</th></tr></thead><tbody>${rows||'<tr><td colspan="8">No matching operations recorded.</td></tr>'}</tbody></table><p class="foot">Evidence verified means recorded endpoint or selected-DC checks passed. Inspect per-operation coverage; legacy plans may contain only samples. It does not establish all endpoints or the entire domain are compliant. Not checked controls are not counted as compliant.</p></body></html>`;
  }
  const help={
    session:['Check delegated sign-in and Kerberos delegation','Reconnect using the approved domain account; verify SPNs and Kerberos remoting to the selected writable DC.'],
    dns:['Check DNS A records','Resolve the writable DC from the management host using the AD DNS server.'],
    srv:['Check AD SRV discovery','Verify _ldap._tcp.dc._msdcs.<domain> SRV records exist and point to domain controllers.'],
    ldap:['Check AD/LDAP access','Verify domain trust, DNS, and delegated account permissions on the selected DC.'],
    modules:['Install DC management modules','Install ActiveDirectory/GroupPolicy PowerShell modules (GPMC) on the approved writable DC.'],
    sysvol:['Check SYSVOL availability','Check DFSR, SYSVOL share, ACLs and replication health on writable DCs.'],
    backup:['Check protected DC backup path','Ensure the delegated execution identity has write rights and sufficient free disk space on the configured local volume.'],
    disk:['Check backup volume free space','Free space or move backups to an approved local volume; do not delete rollback snapshots without retention review.'],
    replication:['Check AD replication','Run repadmin /replsummary and dcdiag /test:replications from an authorized DC.'],
    'gpo-edit':['Check selected GPO rights','Delegate only the required Edit settings privilege on the chosen GPO; verify denies and group membership.'],
    'sysvol-write':['Check GPO SYSVOL ACL','Review effective NTFS permissions for the selected GPO folder.'],
    'link-write':['Check OU gPLink rights','Delegate Write gPLink on the selected OU; preserve existing security filtering.']
  };
  function diagnosis(service,readiness,plan){
    const checks=[];
    checks.push({id:'service',label:'Local backend',state:service?.mode==='WINDOWS'?'PASS':service?'WARN':'UNKNOWN',message:service?.mode==='WINDOWS'?'Windows / AD mode detected.':'Service unavailable or not in Windows mode.',required:true});
    for(const c of readiness?.checks||[])checks.push({id:c.id,label:c.label,state:String(c.state||'UNKNOWN').toUpperCase(),message:c.message||'',required:c.required!==false});
    if(plan?.preview?.preflight?.checks){for(const c of plan.preview.preflight.checks){if(!checks.some(x=>x.id===c.id))checks.push({...c,state:String(c.state||'UNKNOWN').toUpperCase(),context:'Selected GPO/OU plan'});}}
    else checks.push({id:'scope-permissions',label:'Selected GPO / OU permissions',state:'NOT_CHECKED',message:'Generate a control Preview to assess scoped write permissions; domain connectivity alone does not prove rights.',required:false});
    const failed=checks.filter(c=>c.state==='FAIL').length,warn=checks.filter(c=>c.state==='WARN').length;
    return {checkedAt:readiness?.checkedAt||null,checks,failed,warn,ready:readiness?.ready===true&&service?.mode==='WINDOWS'&&failed===0};
  }
  function create({state,say,api,run,render}){
    const f={since:'',scope:'',gpo:'',status:'ALL'};
    let busyHealth=false;
    function download(value,name,type){const blob=new Blob([value],{type});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1200);}
    const label=(a,b)=>say(a,b);
    function reports(){const data=collect(state,f);const gpos=[...new Map((state.history||[]).map(h=>[String(h.plan?.selection?.gpoId||''),String(h.plan?.preview?.gpo?.name||'')])).entries()].filter(x=>x[0]);
      return `<header class="page-header"><div><span class="page-kicker">EVIDENCE CENTER</span><h1>${'Reports & evidence'}</h1><p>${'Evidence from recorded GPO operations. Not a full domain compliance certification.'}</p></div><a href="#/diagnostics" class="page-primary">${'Diagnostics'} →</a></header>
       <section class="ent-metrics"><div><small>${'Recorded runs'}</small><b>${data.count}</b></div><div><small>${'Evidence verified'}</small><b>${data.verifiedEvidence}</b></div><div><small>${'Needs review'}</small><b>${data.reviewRequired}</b></div><div><small>${'Unverified'}</small><b>${data.unverified}</b></div><div><small>${'Controls without records'}</small><b>${data.controlsWithoutRecordedOperations}</b></div></section>
       <section class="content-card ent-panel"><div class="ent-title"><div><h2>${'Report filters'}</h2><p>${'Only operations visible to the signed-in operator are included.'}</p></div></div>
       <div class="ent-filters"><label>${'Since date'}<input type="date" data-ent-filter="since" value="${safe(f.since)}"></label><label>GPO<select data-ent-filter="gpo"><option value="">${'All'}</option>${gpos.map(([id,n])=>`<option value="${safe(id)}" ${f.gpo===id?'selected':''}>${safe(n||id)}</option>`).join('')}</select></label><label>OU / DN<input type="search" data-ent-filter="scope" value="${safe(f.scope)}" placeholder="OU=Servers"></label><label>${'Evidence status'}<select data-ent-filter="status">${[['ALL','All'],['EVIDENCE_VERIFIED','Verified evidence'],['NOT_FULLY_VERIFIED','Not fully verified'],['NEEDS_REVIEW','Needs review']].map(([v,t])=>`<option value="${v}" ${f.status===v?'selected':''}>${safe(t)}</option>`).join('')}</select></label></div><div class="ent-actions"><button data-ent-export="json">JSON</button><button data-ent-export="csv">CSV</button><button data-ent-export="html">HTML</button><button class="primary-action compact" data-ent-print>${'PDF / Print'}</button></div><p class="ent-hint">${'For PDF, choose Save as PDF in the browser print dialog.'}</p></section>
       <section class="content-card ent-panel ent-print-report"><div class="ent-title"><div><h2>${'Before / after and evidence'}</h2><p>${data.count} ${'operation(s)'} · ${'Unassessed controls are not counted as compliant'}</p></div></div><div class="ent-table-wrap"><table class="ent-table"><thead><tr><th>CIS</th><th>GPO · OU</th><th>${'Before / after'}</th><th>${'Observed'}</th><th>${'Status'}</th><th>Backup</th></tr></thead><tbody>${data.entries.slice(0,200).map(e=>`<tr><td><b>${safe(e.controlId)}</b><small>${safe(dateText(e.date))}</small></td><td>${safe(e.gpo)}<small title="${safe(e.scopeDn)}">${safe(e.scopeDn)}</small></td><td>${safe(e.before??'—')} → <strong>${safe(e.requested??'—')}</strong></td><td>${safe(e.observed??'—')}</td><td><span class="ent-status ${e.status==='EVIDENCE_VERIFIED'?'pass':e.status==='NEEDS_REVIEW'?'fail':'warn'}">${safe(e.status.replaceAll('_',' '))}</span><small>${safe(e.effectiveStatus)}</small></td><td><small>${safe(e.backupId??'—')}</small></td></tr>`).join('')||`<tr><td colspan="6">${'No recorded operations match the filters.'}</td></tr>`}</tbody></table></div></section>`;
    }
    function diagnostics(){const diag=diagnosis(state.service,state.readiness,state.plan),hasSession=!!state.gpoSession?.connected;
      return `<header class="page-header"><div><span class="page-kicker">SYSTEM HEALTH</span><h1>${'Diagnostics & self-health'}</h1><p>${'DNS, AD, Kerberos/WinRM, SYSVOL, GPMC, backup, replication and scoped GPO rights.'}</p></div><a href="#/reports" class="page-primary">${'Reports'} →</a></header>
       <section class="content-card ent-panel"><div class="ent-title"><div><h2>${diag.ready?'Required connectivity checks passed':'Diagnostics require attention'}</h2><p>${diag.checkedAt?`${'Last live check'}: ${safe(dateText(diag.checkedAt))}`:'No live diagnostics in this session yet.'}</p></div><button class="primary-action compact" data-ent-diagnose ${busyHealth||!hasSession?'disabled':''}>${busyHealth?'Checking…':'Run all checks'}</button></div>${!hasSession?`<p class="ent-hint">${'Connect a delegated domain account on Dashboard before running AD probes.'}</p>`:''}<div class="ent-metrics"><div><small>PASS</small><b>${diag.checks.filter(x=>x.state==='PASS').length}</b></div><div><small>WARN</small><b>${diag.warn}</b></div><div><small>FAIL</small><b>${diag.failed}</b></div><div><small>NOT CHECKED</small><b>${diag.checks.filter(x=>['UNKNOWN','NOT_CHECKED'].includes(x.state)).length}</b></div></div></section>
       <section class="ent-check-list">${diag.checks.map(c=>{const fix=help[c.id]||['Review environment logs','Open the local Control Center diagnostics and check the matching component logs.'];return `<article class="content-card ent-check"><div class="ent-check-head"><div><b>${safe(c.label||c.id)}</b>${c.context?`<small>${safe(c.context)}</small>`:''}</div><span class="ent-status ${c.state==='PASS'?'pass':c.state==='FAIL'?'fail':'warn'}">${safe(c.state)}</span></div><p>${safe(c.message||'No live evidence recorded.')}</p>${c.state!=='PASS'?`<details><summary>${'Troubleshooting guidance'}</summary><b>${safe(fix[0])}</b><p>${safe(fix[1])}</p></details>`:''}</article>`;}).join('')}</section><p class="ent-hint">${'Scoped permissions are assessed only when a GPO + OU Preview exists. WARN and NOT CHECKED do not mean PASS.'}</p>`;
    }
    function handleClick(e){const exportBtn=e.target.closest('[data-ent-export]');if(exportBtn){const d=collect(state,f),kind=exportBtn.dataset.entExport,stamp=new Date().toISOString().slice(0,10);if(kind==='json')download(JSON.stringify(d,null,2),`gpo-evidence-${stamp}.json`,'application/json');if(kind==='csv')download(csv(d),`gpo-evidence-${stamp}.csv`,'text/csv;charset=utf-8');if(kind==='html')download(html(d),`gpo-evidence-${stamp}.html`,'text/html;charset=utf-8');return true;}
      if(e.target.closest('[data-ent-print]')){window.print();return true;}
      if(e.target.closest('[data-ent-diagnose]')){if(!state.gpoSession?.connected)return true;busyHealth=true;render();run(async()=>{const [readiness,service]=await Promise.all([api('/gpo/readiness'),api('/service')]);state.readiness=readiness;state.service=service;}).finally(()=>{busyHealth=false;render();});return true;}
      return false;}
    function handleChange(e){const field=e.target.closest('[data-ent-filter]');if(!field)return false;f[field.dataset.entFilter]=field.value;render();return true;}
    return {view:route=>route==='#/reports'?reports():diagnostics(),handleClick,handleChange,collect:()=>collect(state,f)};
  }
  window.GpoEnterpriseCenter=Object.freeze({create,record,collect,csv,html,diagnosis});
})();
