/* GPORemediator Studio: presentation enhancements only.
 * Does not call mutate endpoints and never assumes unverified policy compliance. */
(() => {
  'use strict';
  const html = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const time = (value,locale) => {
    const parsed = new Date(value||'');
    return Number.isFinite(parsed.getTime()) ? parsed.toLocaleString('en-GB',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}) : '—';
  };
  const status = run => {
    const result=run?.result||{};
    const s=String(result.state||'').toUpperCase(),effective=String(result.effectiveStatus||'').toUpperCase();
    if(/FAIL|DRIFT|MISMATCH|REVIEW|PARTIAL|ERROR/.test(s+' '+effective))return 'review';
    if(s==='ROLLED_BACK')return 'restored';
    if(window.GpoUiDomain?.classify?.(run)?.compliant)return 'verified';
    return 'pending';
  };
  const dot = kind => `<span class="studio-dot studio-dot-${kind}" aria-hidden="true"></span>`;
  const last = list => [...(list||[])].sort((a,b)=>Date.parse(b.updatedAt||0)-Date.parse(a.updatedAt||0))[0];
  const label = (_fallback,en,lang) => en;
  function dashboard(state){
    const L=(a,b)=>label(a,b,state.lang),counts={verified:0,review:0,pending:0,restored:0};
    for(const h of state.history||[])counts[status(h)]++;
    const online=!!state.gpoSession?.connected&&!state.serviceOffline;
    const name=state.inventory?.domain||state.gpoSession?.domain||null;
    const newest=last(state.history),total=(state.catalog?.rules||[]).length;
    const mapped=(state.catalog?.rules||[]).filter(r=>r.implementation==='live').length;
    return `<section class="studio-overview" aria-label="${'Management overview'}">
      <div class="studio-overview-copy"><div class="studio-overline"><span class="studio-overline-mark"></span>${'POLICY MANAGEMENT / OVERVIEW'}</div>
        <h1>${'Policy operations'}</h1>
        <p>${'Monitor directory readiness, controlled changes and verification evidence in one place.'}</p>
        <div class="studio-overview-cta"><a class="studio-action-primary" href="#/benchmark">${'Browse CIS controls'} <span aria-hidden="true">↗</span></a><a class="studio-action-quiet" href="#/diagnostics">${'System diagnostics'} <span aria-hidden="true">→</span></a></div>
      </div>
      <div class="studio-overview-meta"><div class="studio-overview-status">${dot(online?'good':'quiet')}<span>${online?'Domain session active':'Domain session inactive'}</span></div>
        <strong title="${html(name||'No domain selected')}">${html(name||'No domain selected')}</strong>
        <div class="studio-overview-grid"><span><small>${'Current operator'}</small><b>${html(state.session?.operator||'—')}</b></span><span><small>${'Latest operation'}</small><b>${time(newest?.updatedAt,state.lang)}</b></span></div>
      </div>
    </section>
    <section class="studio-pulse" aria-label="${'Operation metrics'}">
      <a href="#/operations" class="studio-pulse-item studio-pulse-teal"><div><small>${'Evidence verified'}</small><strong>${counts.verified}</strong></div><span>${dot('good')} ${'Checked'}</span></a>
      <a href="#/operations" class="studio-pulse-item studio-pulse-amber"><div><small>${'Needs review'}</small><strong>${counts.review}</strong></div><span>${dot('warn')} ${'Attention'}</span></a>
      <a href="#/operations" class="studio-pulse-item studio-pulse-violet"><div><small>${'Not fully verified'}</small><strong>${counts.pending}</strong></div><span>${dot('purple')} ${'Recorded'}</span></a>
      <a href="#/benchmark" class="studio-pulse-item studio-pulse-blue"><div><small>${'Automated CIS mappings'}</small><strong>${mapped}<em>/${total}</em></strong></div><span>${dot('blue')} ${'Not compliance rate'}</span></a>
    </section>`;
  }
  function catalog(state){
    const L=(a,b)=>label(a,b,state.lang),all=state.catalog?.rules||[];
    const live=all.filter(x=>x.implementation==='live').length;
    return `<div class="studio-catalog-intro" aria-label="${'Catalog workspace'}"><span class="studio-catalog-rail">${'CATALOG WORKSPACE'}</span>
      <div><strong>${'Find the control. Understand the impact. Plan safely.'}</strong>
        <p>${live} ${'controls currently have real GPO mappings. Compliance requires live verification evidence.'}</p></div>
      <a href="#/workspace">${'Batch workflows'} <span aria-hidden="true">↗</span></a></div>`;
  }
  function remediation(state){
    const L=(a,b)=>label(a,b,state.lang),selection=state.selection||{},plan=state.plan;
    const gpo=(state.inventory?.gpos||[]).find(x=>x.id===selection.gpoId),scope=(state.inventory?.scopes||[]).find(x=>x.dn===selection.scopeDn);
    const steps=[
      ['Control',!!state.selectedRule],
      ['GPO / OU',!!gpo&&!!scope],
      ['Preview',!!plan],
      ['Approval',!!state.approval?.reviewed],
      ['Result',false]
    ];
    return `<section class="studio-remediation-context"><div class="studio-context-head"><span class="studio-eyebrow">${'CHANGE CONTEXT'}</span><span class="studio-context-tag">${dot('blue')} ${'Read-only preview first'}</span></div>
      <div class="studio-context-grid"><div><small>CIS CONTROL</small><strong>${html(state.selectedRule?.id||'—')}</strong><span>${html(state.selectedRule?.title||'—')}</span></div>
        <div><small>${'SELECTED GPO'}</small><strong title="${html(gpo?.name||'')}">${html(gpo?.name||'Not selected')}</strong><span>${html(gpo?.id||'—')}</span></div>
        <div><small>${'TARGET OU / DOMAIN'}</small><strong title="${html(scope?.name||'')}">${html(scope?.name||'Not selected')}</strong><span title="${html(scope?.dn||'')}">${html(scope?.dn||'—')}</span></div></div>
      <ol class="studio-steps">${steps.map(([t,done],i)=>`<li class="${done?'done':i===steps.findIndex(x=>!x[1])?'current':''}"><span>${done?'✓':i+1}</span><small>${t}</small></li>`).join('')}</ol></section>`;
  }
  function operations(state){
    const L=(a,b)=>label(a,b,state.lang),list=state.history||[],newest=last(list);
    const reviewed=list.filter(h=>status(h)==='review').length,verified=list.filter(h=>status(h)==='verified').length;
    return `<section class="studio-operation-brief"><div><span class="studio-eyebrow">${'OPERATION ASSURANCE'}</span><h2>${'Every change remains traceable.'}</h2><p>${'Statuses use recorded evidence; a successful Apply alone never proves compliance.'}</p></div>
      <div class="studio-operation-stats"><span>${dot('good')} <b>${verified}</b> ${'verified'}</span><span>${dot('warn')} <b>${reviewed}</b> ${'review'}</span><span>${dot('quiet')} <b>${time(newest?.updatedAt,state.lang)}</b> ${'latest'}</span></div></section>`;
  }
  function workflow(state){const L=(a,b)=>label(a,b,state.lang);
    return `<section class="studio-workflow-brief"><div><span class="studio-eyebrow">${'CONTROLLED EXECUTION'}</span><strong>${'Preview → Approval → Apply → Verify'}</strong><small>${'Write operations always require backend scope, backup and approval checks.'}</small></div><a href="#/diagnostics">${'Check readiness'} ↗</a></section>`;
  }
  window.GpoStudioUI=Object.freeze({dashboard,catalog,remediation,operations,workflow,status});
})();
