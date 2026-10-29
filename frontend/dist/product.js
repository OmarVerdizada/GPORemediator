/* Product surfaces use existing server-authoritative state; no policy writes here. */
(() => {
  'use strict';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const text = (s, _fallback, en) => en;
  const date = (value, lang) => {
    const d = new Date(value);
    if(!Number.isFinite(d.getTime()))return '—';
    return d.toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'});
  };
  const active = run => /^(APPLYING|VERIFYING|REFRESHING|ROLLBACKING|ROLLING_BACK)$/.test(String(run?.result?.state || '').toUpperCase());
  function sortedRuns(runs, order='newest') {
    return [...runs].sort((a,b) => {
      const aTime = Date.parse(a.updatedAt) || 0, bTime = Date.parse(b.updatedAt) || 0;
      if (order === 'attention') { const delta = Number(window.GpoUiDomain.classify(b).attention)-Number(window.GpoUiDomain.classify(a).attention); if(delta) return delta; }
      return order === 'oldest' ? aTime-bTime : bTime-aTime;
    });
  }
  function latestByControl(history) {
    const latest=new Map();
    for(const run of history||[]) {
      const setting=run.plan?.selection?.setting;
      if(!setting)continue;
      const previous=latest.get(setting);
      // Preserve input order for tied or missing dates, as sortedRuns does.
      if(!previous||(Date.parse(run.updatedAt)||0)>(Date.parse(previous.updatedAt)||0))latest.set(setting,run);
    }
    return latest;
  }
  function controlStatus(s, rule, latest=latestByControl(s.history)) {
    const run=latest.get(rule.backendSetting||rule.id);
    if(!run)return {tone:'unknown',label:'Not assessed',run:null};
    const quality=window.GpoUiDomain.classify(run),state=String(run.result?.state||'').toUpperCase();
    if(state==='ROLLED_BACK')return {tone:'unknown',label:'Rolled back',run};
    if(active(run))return {tone:'unknown',label:'In progress',run};
    if(quality.custom)return {tone:'warning',label:'Custom value · benchmark not verified',run};
    if(quality.compliant)return {tone:'good',label:'Sample configuration verified',run};
    if(quality.attention)return {tone:'warning',label:'Needs review',run};
    return {tone:'unknown',label:'Verification pending',run};
  }
  function domainHeader(s, domain, rules, open) {
    const ready=rules.filter(r=>r.implementation==='live').length;
    return `<button type="button" class="ent-domain-head" data-domain="${esc(domain.id)}" aria-expanded="${open}" aria-controls="catalog-domain-${esc(domain.id)}"><span class="domain-icon" aria-hidden="true">${window.GpoComponents.domainIcon(domain.id)}</span><span class="domain-title"><span class="domain-kicker">${'CIS SECTION'} ${esc(domain.id)}</span><strong>${esc(domain.title)}</strong><small>${rules.length} ${'controls'} · ${ready} ${'automation ready'}</small></span><span class="domain-counter"><i>L1</i><b>${rules.filter(r=>r.level==='L1').length}</b></span><span class="domain-counter"><i>L2</i><b>${rules.filter(r=>r.level==='L2').length}</b></span><span class="domain-progress" aria-hidden="true"><i style="width:${Math.round(ready/Math.max(1,rules.length)*100)}%"></i></span><span class="domain-chevron" aria-hidden="true">${open?'−':'+'}</span></button>`;
  }
  function disconnectedControl(s, rule) {
    return `<section class="recipe-offline"><span class="product-eyebrow">${'CONTROL PREPARATION'}</span><h2>${'Review the control before choosing a GPO'}</h2><div class="recipe-tags"><span>${rule.implementation==='live'?'Automation ready':'Manual review'}</span><span>${controlStatus(s,rule).label}</span></div><h3>${'Recommended state'}</h3><p>${esc(rule.recommended||'—')}</p><p>${esc(rule.description||'')}</p><ol><li>${'Confirm whether this is user, computer, or domain scoped.'}</li><li>${'Open the single sign-in screen and choose a real GPO from inventory.'}</li><li>${'Generate the read-only plan before making changes.'}</li></ol><button data-product-action="sign-in">${'Open sign-in'} →</button></section>`;
  }
  function catalogTools(s,count){const filtered=!!s.query||s.level!=='ALL'||s.automation!=='ALL'||s.savedView!=='ALL';return `<div class="product-catalog-tools"><span><strong>${count}</strong> matching controls ${filtered?'<button data-product-action="clear-filters">Clear filters ×</button>':''}</span><button data-product-action="export-catalog">Export CSV</button></div>`;}
  function inspector(s) {
    const h=s.history.find(x=>x.id===s.inspectedOperation); if(!h)return '';
    const p=h.plan||{},r=h.result||{},quality=window.GpoUiDomain.classify(h);
    const checks=[
      ['GPO publication',r.gpoPublished===true,'Value recorded in the GPO'],
      ['Target link',r.linkVerified===true,'Link to the selected scope verified'],
      ['AD / SYSVOL replication',quality.replication==='converged','Controller versions have converged'],
      ['Effective policy',quality.effective==='verified','Result of live verification']
    ];
    return `<div class="product-drawer-backdrop" data-product-close></div><aside class="product-drawer" role="dialog" aria-modal="true" aria-labelledby="operation-detail-title" tabindex="-1"><header><div><span class="product-eyebrow">${'OPERATION DETAILS'}</span><h2 id="operation-detail-title">${esc(p.selection?.setting||'GPO')} · ${esc(p.preview?.gpo?.name||'GPO')}</h2><p>${date(h.updatedAt,s.lang)}</p></div><button data-product-close aria-label="${'Close'}">${window.GpoComponents.icon('close')}</button></header><div class="product-drawer-body"><div class="product-result ${quality.attention?'warning':'neutral'}">${window.GpoComponents.status(s,window.GpoUiDomain.resultState(h)).html}<p>${esc(r.message||'Awaiting result')}</p></div><div class="pr-identities"><div><small>GPO GUID</small>${window.GpoPremium.copyValue(s,p.preview?.gpo?.id,'GPO GUID')}</div><div><small>DN</small>${window.GpoPremium.copyValue(s,p.selection?.scopeDn||p.preview?.scope?.dn,'DN')}</div></div>${window.GpoComponents.recovery(s,h)}<h3>${'Stages'}</h3>${window.GpoComponents.timeline(s,h)}<h3>${'Verification layers'}</h3><div class="product-verification">${checks.map(([title,ok,copy])=>`<div><span class="product-check ${ok?'good':'pending'}">${ok?'✓':'○'}</span><span><strong>${title}</strong><small>${ok?copy:'Not confirmed yet'}</small></span></div>`).join('')}</div><div class="product-value-grid"><div><small>${'BEFORE'}</small><strong>${esc(p.preview?.previousValue??'Not configured')}</strong>${window.GpoComponents.valueSource(p.preview?.previousValueSource,p.preview?.previousValue,p.preview?.gpo)}</div><div><small>${'EXPECTED'}</small><strong>${esc(p.preview?.desiredValue??'—')}</strong></div><div><small>${r.domainPolicy?'ACTUAL AD VALUE':'STORED GPO VALUE'}</small><strong>${esc(r.domainPolicy?.value??r.currentValue??'—')}</strong>${r.domainPolicy?`<small>AD ${esc(r.domainPolicy.property)} · ${esc(r.domainPolicy.domainController)}</small>`:window.GpoComponents.valueSource(r.currentValueSource,r.currentValue,p.preview?.gpo)}</div></div><h3>${'Change context'}</h3><dl class="product-facts">${[
      ['Domain',p.domain],['Controller',p.domainController],['Scope',p.selection?.scopeDn],['Execution identity',p.executionUser],['Change reference',h.approval?.changeReference],['Backup',r.backupId],['Operation ID',h.id],['Correlation ID',h.correlationId]
    ].map(([label,value])=>`<div><dt>${label}</dt><dd>${esc(value||'—')}</dd></div>`).join('')}</dl>${(r.endpointChecks||[]).length?`<h3>${'Endpoint results'}</h3>${r.endpointChecks.map(e=>{const command=window.GpoComponents.manualCheck(s,h,e);return `<div class="product-endpoint"><strong>${esc(e.hostname)}</strong><span>${esc(e.state)}</span><small>${esc(e.message)}</small><pre>${esc(e.actualValue??'—')}</pre>${command?`<div class="manual-check-head"><small>${'Manual PowerShell check on endpoint'}</small><button type="button" data-copy-value="${esc(command)}">${'Copy'}</button></div><pre class="manual-check-command">${esc(command)}</pre>`: ''}</div>`;}).join('')}`:''}${(p.preview?.warnings||[]).length?`<h3>${'Plan warnings'}</h3><ul class="product-warnings">${p.preview.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul>`:''}</div><footer><button data-op-evidence="${esc(h.id)}">↓ ${'Download evidence'}</button><button data-product-action="copy-operation">${'Copy summary'}</button></footer></aside>`;
  }
  function help(s) {
    if(!s.helpOpen)return '';
    return `<div class="product-drawer-backdrop" data-product-close></div><aside class="product-drawer" role="dialog" aria-modal="true" aria-labelledby="product-help-title" tabindex="-1"><header><div><span class="product-eyebrow">${'FIELD GUIDE'}</span><h2 id="product-help-title">${'Operate with confidence'}</h2></div><button data-product-close aria-label="${'Close'}">${window.GpoComponents.icon('close')}</button></header><div class="product-drawer-body"><p class="product-help-intro">${'Every change follows the same clear sequence.'}</p>${[
      ['01 · Connect and check','Connect your domain account once. Resolve required readiness failures.'],
      ['02 · Choose a precise target','Choose the control, GPO and OU/domain scope. Preview does not change policy.'],
      ['03 · Review the plan','Review before/after values, affected objects and warnings. Supply the change reference for approval.'],
      ['04 · Apply and verify','Backup is created before Apply. Publication, replication and effective policy are separate results; check each one.']
    ].map(([title,copy])=>`<section class="product-help-step"><h3>${title}</h3><p>${copy}</p></section>`).join('')}<h3>${'Move faster with the keyboard'}</h3><dl class="product-shortcuts"><div><dt>${'Search the library'}</dt><dd><kbd>/</kbd></dd></div><div><dt>${'Main pages'}</dt><dd><kbd>Alt</kbd> <kbd>1 / 2 / 3</kbd></dd></div><div><dt>${'Close a panel'}</dt><dd><kbd>Esc</kbd></dd></div></dl><div class="product-help-note">${'Catalog coverage is not domain compliance. Compliance is established by live verification results.'}</div></div></aside>`;
  }
  function csv(rules) {
    // Prevent spreadsheet formula execution from imported text fields.
    const cell=value=>'"'+String(value??'').replace(/^[=+@-]/,"'$&").replaceAll('"','""')+'"';
    return '\uFEFF'+[['Control','Title','Level','Automation','Implementation','Recommended'],...rules.map(r=>[r.id,r.title,r.level,r.automation,r.implementation,r.recommended])].map(row=>row.map(cell).join(',')).join('\r\n');
  }
  window.GpoProduct=Object.freeze({domainHeader,controlStatus,latestByControl,disconnectedControl,catalogTools,inspector,help,sortedRuns,active,csv,date});
})();
