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
  function recentControls() {
    try { const ids = JSON.parse(window.GpoClient.storage.get('gr-recent-controls','[]')); return Array.isArray(ids) ? ids.filter(x => typeof x === 'string').slice(0,5) : []; }
    catch { return []; }
  }
  function remember(id) { window.GpoClient.storage.set('gr-recent-controls', JSON.stringify([id,...recentControls().filter(x=>x!==id)].slice(0,5))); }
  function sortedRuns(runs, order='newest') {
    return [...runs].sort((a,b) => {
      const aTime = Date.parse(a.updatedAt) || 0, bTime = Date.parse(b.updatedAt) || 0;
      if (order === 'attention') { const delta = Number(window.GpoUiDomain.classify(b).attention)-Number(window.GpoUiDomain.classify(a).attention); if(delta) return delta; }
      return order === 'oldest' ? aTime-bTime : bTime-aTime;
    });
  }
  function dashboard(s) {
    const steps = [
      {done:s.session?.mode==='WINDOWS',title:'Start Windows / AD',copy:'Domain and controller configuration',action:'settings'},
      {done:!!s.gpoSession?.connected,title:'Single sign-in',copy:'AD execution identity confirmed at sign-in',action:'sign-in'},
      {done:!!s.readiness?.ready,title:'Check readiness',copy:'Kerberos, WinRM, SYSVOL and permissions',action:'readiness'},
      {done:!!s.plan,title:'Prepare your next plan',copy:'Control → GPO → scope → preview',action:'benchmark'}
    ];
    const next = steps.findIndex(x=>!x.done);
    const attention = sortedRuns(s.history.filter(h=>window.GpoUiDomain.classify(h).attention)).slice(0,3);
    const recent = recentControls().map(id=>s.catalog?.rules.find(r=>r.id===id)).filter(Boolean);
    return `<section class="product-desk"><article class="product-checklist"><div class="product-section-head"><div><span class="product-eyebrow">${'YOUR WORKSPACE'}</span><h2>${'A clear next step'}</h2></div><span class="product-counter">${steps.filter(x=>x.done).length} / 4</span></div><div class="product-step-list">${steps.map((x,i)=>`<button data-product-action="${x.action}" class="product-step ${x.done?'complete':i===next?'next':''}"><span class="product-step-number">${x.done?'✓':String(i+1).padStart(2,'0')}</span><span><strong>${x.title}</strong><small>${x.copy}</small></span><b>↗</b></button>`).join('')}</div></article><article class="product-focus"><div class="product-section-head"><div><span class="product-eyebrow">${'FOCUS CENTER'}</span><h2>${attention.length?'Results needing review':'Pick up where you left off'}</h2></div><span class="product-status ${attention.length?'warning':'good'}">${attention.length?'Review':'Ready'}</span></div>${attention.length?attention.map(h=>`<button class="product-recent" data-inspect="${esc(h.id)}"><span class="product-rule-id">${esc(h.plan?.selection?.setting||'GPO')}</span><span><strong>${esc(h.plan?.preview?.gpo?.name||h.id)}</strong><small>${esc(h.result?.message||h.result?.state)}</small></span><b>↗</b></button>`).join(''):recent.length?recent.map(r=>`<button class="product-recent" data-rule="${esc(r.id)}"><span class="product-rule-id">${esc(r.id)}</span><span><strong>${esc(r.title)}</strong><small>${esc(r.level)} · CIS v4.0.0</small></span><b>→</b></button>`).join(''):`<div class="product-welcome"><span>↗</span><h3>${'Start with one control'}</h3><p>${'Recently viewed controls appear here. Start with a read-only plan for a limited scope.'}</p><a href="#/benchmark">${'Explore the library'} →</a></div>`}</article></section>`;
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
  function coverage(s) {
    const rules=s.catalog.rules,ready=rules.filter(r=>r.implementation==='live').length,manual=rules.filter(r=>r.implementation==='manual').length;
    const latest=latestByControl(s.history),checked=rules.filter(r=>latest.has(r.backendSetting||r.id)).length;
    return `<section class="recipe-coverage"><div><span class="product-eyebrow">${'BENCHMARK COVERAGE'}</span><h2>${'Every control at a glance'}</h2><p>${'The catalog is available without a GPO connection. Implementation statuses reflect the last recorded operation, not a domain audit score.'}</p><a href="#/benchmark">${'Browse controls'} →</a></div><dl>${[[rules.length,'Total controls'],[ready,'Automatic GPO'],[manual,'Guided remediation'],[rules.length-checked,'Not assessed']].map(([n,label])=>`<div><dd>${n}</dd><dt>${label}</dt></div>`).join('')}</dl></section>`;
  }
  function recipeCards(s, rules) {
    let section='';
    const latest=latestByControl(s.history);
    return [...rules].sort((a,b)=>a.id.localeCompare(b.id,undefined,{numeric:true})).map(rule=>{
      const group=s.catalog.sections.find(x=>x.id===rule.sectionId),status=controlStatus(s,rule,latest);
      const heading=section!==rule.sectionId?`<h2 class="recipe-section">${esc(rule.sectionId)} <span>${esc(group?.title||'')}</span></h2>`:'';section=rule.sectionId;
      const support=rule.implementation==='live'?'Automation ready':rule.implementation==='manual'?'Manual review':'Mapping unavailable';
      return `${heading}<article class="recipe-card"><header><span class="recipe-number">${esc(rule.id)}</span><div><h3><button data-rule="${esc(rule.id)}">${esc(rule.title)}</button></h3><div class="recipe-tags"><span>${esc(rule.level)}</span><span class="${rule.implementation==='live'?'good':'unknown'}">${support}</span><span class="${status.tone}">${status.label}</span></div></div><button class="fav-mini ${s.favorites.has(rule.id)?'active':''}" data-favorite="${esc(rule.id)}" aria-label="${'Toggle favorite'}">${s.favorites.has(rule.id)?'★':'☆'}</button></header><p class="recipe-description">${esc(rule.description||'No description available.')}</p><details><summary>${'Read full description'}</summary><p>${esc(rule.description||'—')}</p></details><footer><div><small>${'RECOMMENDED STATE'}</small><strong>${esc(rule.recommended||'See benchmark description')}</strong>${status.run?`<small>${'Last record'}: ${date(status.run.updatedAt,s.lang)} · ${esc(status.run.plan?.preview?.gpo?.name||'GPO')}</small>`:''}</div><button data-rule="${esc(rule.id)}">${'Open control'} →</button></footer></article>`;
    }).join('');
  }
  const domainSymbols={'1':'⌾','2':'◇','3':'▤','4':'♧','5':'⚙','6':'⊞','7':'▱','8':'⇄','9':'◫','10':'◎','11':'⌁','12':'⚿','13':'⊘','14':'⊕','15':'◈','16':'⛨','17':'≋','18':'▦','19':'◉'};
  function domainHeader(s, domain, rules, open) {
    const ready=rules.filter(r=>r.implementation==='live').length;
    return `<button type="button" class="ent-domain-head" data-domain="${esc(domain.id)}" aria-expanded="${open}" aria-controls="catalog-domain-${esc(domain.id)}"><span class="domain-icon" aria-hidden="true">${window.GpoComponents.domainIcon(domain.id)}</span><span class="domain-title"><span class="domain-kicker">${'CIS SECTION'} ${esc(domain.id)}</span><strong>${esc(domain.title)}</strong><small>${rules.length} ${'controls'} · ${ready} ${'automation ready'}</small></span><span class="domain-counter"><i>L1</i><b>${rules.filter(r=>r.level==='L1').length}</b></span><span class="domain-counter"><i>L2</i><b>${rules.filter(r=>r.level==='L2').length}</b></span><span class="domain-progress" aria-hidden="true"><i style="width:${Math.round(ready/Math.max(1,rules.length)*100)}%"></i></span><span class="domain-chevron" aria-hidden="true">${open?'−':'+'}</span></button>`;
  }
  function recipes(s, rules) {
    const filtered=!!s.query||s.level!=='ALL'||s.automation!=='ALL'||s.savedView!=='ALL';
    return s.catalog.sections.filter(d=>!d.parentId).sort((a,b)=>a.id.localeCompare(b.id,undefined,{numeric:true})).map(domain=>{
      const matching=rules.filter(r=>r.id.startsWith(domain.id+'.'));
      if(filtered&&!matching.length)return '';
      const searching=!!s.query?.trim(),open=searching?!s.catalogSearchCollapsed?.has(domain.id):!!s.expandedTop?.has(domain.id);
      const groups=[...new Set(matching.map(r=>r.sectionId||r.id.split('.').slice(0,-1).join('.')))].sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
      const saved=s.catalogSections?.[domain.id],selected=saved==='ALL'||groups.includes(saved)?saved:groups[0];
      const visible=searching||selected==='ALL'?matching:matching.filter(r=>(r.sectionId||r.id.split('.').slice(0,-1).join('.'))===selected);
      const navigation=groups.length>1&&!searching?`<div class="catalog-section-bar"><label for="catalog-section-${esc(domain.id)}">${'Subsection'}<select id="catalog-section-${esc(domain.id)}" data-catalog-section="${esc(domain.id)}">${groups.map(id=>`<option value="${esc(id)}" ${selected===id?'selected':''}>${esc(id)} · ${esc(s.catalog.sections.find(x=>x.id===id)?.title||id)} (${matching.filter(r=>(r.sectionId||r.id.split('.').slice(0,-1).join('.'))===id).length})</option>`).join('')}<option value="ALL" ${selected==='ALL'?'selected':''}>${'All subsections'} (${matching.length})</option></select></label><span>${visible.length} / ${matching.length} ${'controls shown'}</span></div>`:'';
      return `<section class="ent-domain recipe-domain domain-tone-${(Number(domain.id)-1)%7} ${open?'open':''}">${domainHeader(s,domain,matching,open)}${open?`<div id="catalog-domain-${esc(domain.id)}" class="ent-domain-body">${matching.length?navigation+recipeCards(s,visible):`${window.GpoDomainGuidance?.render(s,domain,esc,(_fallback,en)=>text(s,_fallback,en))||`<p class="domain-empty">${'This imported category has no standalone controls.'}</p>`}`}</div>`:`<div id="catalog-domain-${esc(domain.id)}" hidden></div>`}</section>`;
    }).join('');
  }
  function disconnectedControl(s, rule) {
    return `<section class="recipe-offline"><span class="product-eyebrow">${'CONTROL PREPARATION'}</span><h2>${'Review the control before choosing a GPO'}</h2><div class="recipe-tags"><span>${rule.implementation==='live'?'Automation ready':'Manual review'}</span><span>${controlStatus(s,rule).label}</span></div><h3>${'Recommended state'}</h3><p>${esc(rule.recommended||'—')}</p><p>${esc(rule.description||'')}</p><ol><li>${'Confirm whether this is user, computer, or domain scoped.'}</li><li>${'Open the single sign-in screen and choose a real GPO from inventory.'}</li><li>${'Generate the read-only plan before making changes.'}</li></ol><button data-product-action="sign-in">${'Open sign-in'} →</button></section>`;
  }
  function catalogTools(s, count) {
    const filtered = !!s.query || s.level!=='ALL' || s.automation!=='ALL' || s.savedView!=='ALL';
    return `<div class="product-catalog-tools"><span><strong>${count}</strong> ${'matching controls'} ${filtered?`<button data-product-action="clear-filters">${'Clear filters'} ×</button>`:''}</span><div><div class="product-view-switch" role="group" aria-label="${'Catalog view'}"><button data-catalog-layout="recipes" aria-pressed="${s.catalogLayout==='recipes'}">${'Recipes'}</button><button data-catalog-layout="tree" aria-pressed="${s.catalogLayout==='tree'}">${'Hierarchy'}</button><button data-catalog-layout="list" aria-pressed="${s.catalogLayout==='list'}">${'List'}</button></div><button data-product-action="export-catalog">↓ ${'Export CSV'}</button></div></div>`;
  }
  function inspector(s) {
    const h=s.history.find(x=>x.id===s.inspectedOperation); if(!h)return '';
    const p=h.plan||{},r=h.result||{},quality=window.GpoUiDomain.classify(h);
    const checks=[
      ['GPO publication',r.gpoPublished===true,'Value recorded in the GPO'],
      ['Target link',r.linkVerified===true,'Link to the selected scope verified'],
      ['AD / SYSVOL replication',quality.replication==='converged','Controller versions have converged'],
      ['Effective policy',quality.effective==='verified','Result of live verification']
    ];
    return `<div class="product-drawer-backdrop" data-product-close></div><aside class="product-drawer" role="dialog" aria-modal="true" aria-labelledby="operation-detail-title" tabindex="-1"><header><div><span class="product-eyebrow">${'OPERATION DETAILS'}</span><h2 id="operation-detail-title">${esc(p.selection?.setting||'GPO')} · ${esc(p.preview?.gpo?.name||'GPO')}</h2><p>${date(h.updatedAt,s.lang)}</p></div><button data-product-close aria-label="${'Close'}">${window.GpoComponents.icon('close')}</button></header><div class="product-drawer-body"><div class="product-result ${quality.attention?'warning':'neutral'}">${window.GpoComponents.status(s,r.state).html}<p>${esc(r.message||'Awaiting result')}</p></div><div class="pr-identities"><div><small>GPO GUID</small>${window.GpoPremium.copyValue(s,p.preview?.gpo?.id,'GPO GUID')}</div><div><small>DN</small>${window.GpoPremium.copyValue(s,p.selection?.scopeDn||p.preview?.scope?.dn,'DN')}</div></div>${window.GpoComponents.recovery(s,h)}<h3>${'Stages'}</h3>${window.GpoComponents.timeline(s,h)}<h3>${'Verification layers'}</h3><div class="product-verification">${checks.map(([title,ok,copy])=>`<div><span class="product-check ${ok?'good':'pending'}">${ok?'✓':'○'}</span><span><strong>${title}</strong><small>${ok?copy:'Not confirmed yet'}</small></span></div>`).join('')}</div><div class="product-value-grid"><div><small>${'BEFORE'}</small><strong>${esc(p.preview?.previousValue??'Not configured')}</strong>${window.GpoComponents.valueSource(p.preview?.previousValueSource,p.preview?.previousValue,p.preview?.gpo)}</div><div><small>${'EXPECTED'}</small><strong>${esc(p.preview?.desiredValue??'—')}</strong></div><div><small>${'CURRENT'}</small><strong>${esc(r.currentValue??'—')}</strong>${window.GpoComponents.valueSource(r.currentValueSource,r.currentValue,p.preview?.gpo)}</div></div><h3>${'Change context'}</h3><dl class="product-facts">${[
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
    ].map(([title,copy])=>`<section class="product-help-step"><h3>${title}</h3><p>${copy}</p></section>`).join('')}<h3>${'Move faster with the keyboard'}</h3><dl class="product-shortcuts"><div><dt>${'Search controls and actions'}</dt><dd><kbd>Ctrl</kbd> <kbd>K</kbd></dd></div><div><dt>${'Search the library'}</dt><dd><kbd>/</kbd></dd></div><div><dt>${'Main pages'}</dt><dd><kbd>Alt</kbd> <kbd>1 / 2 / 3</kbd></dd></div><div><dt>${'Close a panel'}</dt><dd><kbd>Esc</kbd></dd></div></dl><div class="product-help-note">${'Catalog coverage is not domain compliance. Compliance is established by live verification results.'}</div></div></aside>`;
  }
  function csv(rules) {
    // Prevent spreadsheet formula execution from imported text fields.
    const cell=value=>'"'+String(value??'').replace(/^[=+@-]/,"'$&").replaceAll('"','""')+'"';
    return '\uFEFF'+[['Control','Title','Level','Automation','Implementation','Recommended'],...rules.map(r=>[r.id,r.title,r.level,r.automation,r.implementation,r.recommended])].map(row=>row.map(cell).join(',')).join('\r\n');
  }
  window.GpoProduct=Object.freeze({dashboard,coverage,recipes,domainHeader,controlStatus,latestByControl,disconnectedControl,catalogTools,inspector,help,remember,sortedRuns,active,csv,date});
})();
