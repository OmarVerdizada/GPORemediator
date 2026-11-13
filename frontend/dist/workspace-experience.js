/* Read-only presentation. Outcome rules and all policy actions remain in their owners. */
(() => {
  'use strict';
  const esc=value=>window.GpoComponents.esc(value);
  const labels={VERIFIED:'Verified',MISMATCH:'Value differs',UNAVAILABLE:'Unavailable',OUTSIDE_SCOPE:'Outside scope',OBSERVED:'Observed only',RESTORE_MATCH:'Restore sample matches',RESTORE_MISMATCH:'Restore value differs',CHECKING:'Checking'};
  const tone=state=>['VERIFIED','RESTORE_MATCH'].includes(state)?'good':['MISMATCH','RESTORE_MISMATCH'].includes(state)?'bad':'pending';
  function evidenceMatrix(run){
    const result=run?.result||{},checks=result.endpointChecks||[];
    if(!checks.length)return '';
    return `<section class="evidence-comparison" aria-label="Endpoint comparison"><header><div><span class="experience-kicker">TARGET READINGS</span><h3>Evidence by endpoint</h3></div><span class="experience-count">${checks.length} recorded</span></header><p>Each row is an independent reading. Refresh and policy source remain separate checks.</p><div class="evidence-table-wrap"><table class="evidence-matrix"><caption class="sr-only">Recorded endpoint values and verification outcomes</caption><thead><tr><th scope="col">Endpoint</th><th scope="col">Measured value</th><th scope="col">Value check</th></tr></thead><tbody>${checks.map(check=>`<tr data-evidence-state="${esc(check.state)}"><th scope="row" data-label="Endpoint">${esc(check.hostname||'Unnamed target')}</th><td data-label="Measured value"><code>${esc(check.actualValue??'No reading available')}</code></td><td data-label="Value check"><span class="evidence-state ${tone(check.state)}"><i aria-hidden="true">${tone(check.state)==='good'?'✓':tone(check.state)==='bad'?'!':'○'}</i>${esc(labels[check.state]||check.state||'Not checked')}</span></td></tr>`).join('')}</tbody></table></div></section>`;
  }
  function queue(history){
    // Keep the latest result per control + GPO + target. Do not count repeat checks as new targets.
    const latest=new Map();
    for(const h of window.GpoProduct.sortedRuns(history)){
      const s=h.plan?.selection||{},key=JSON.stringify([s.setting,s.gpoId,s.scopeDn,s.endpointScopeDn,s.verificationUser]);
      if(!latest.has(key))latest.set(key,h);
    }
    const rows=[...latest.values()].filter(h=>!window.GpoProduct.active(h)&&!/^ROLL/.test(h.result?.state||''));
    const samples=rows.flatMap(h=>h.result?.endpointChecks||[]);
    const groups=[['Verified',samples.filter(x=>x.state==='VERIFIED').length,'good'],['Different',samples.filter(x=>x.state==='MISMATCH').length,'bad'],['Unresolved',samples.filter(x=>!['VERIFIED','MISMATCH'].includes(x.state)).length,'pending']];
    const next=rows.find(h=>window.GpoUiDomain.outcome(h).mismatch)||rows.find(h=>!window.GpoUiDomain.outcome(h).verified);
    return `<section class="dashboard-panel experience-queue"><header><h2>Endpoint evidence</h2><span>Latest recorded checks</span></header><div class="experience-coverage"><div class="coverage-total"><strong>${samples.length}</strong><span>control / host readings</span></div><div class="coverage-distribution"><div class="coverage-bar" aria-hidden="true">${groups.filter(x=>x[1]).map(([,count,t])=>`<span class="${t}" style="flex-grow:${count}"></span>`).join('')}</div><ul>${groups.map(([label,count,t])=>`<li><i class="${t}" aria-hidden="true"></i>${label}<strong>${count}</strong></li>`).join('')}</ul></div></div>${next?`<button class="experience-next" data-inspect="${esc(next.id)}"><span class="experience-next-icon">${window.GpoComponents.icon('search')}</span><span><small>Next to inspect</small><strong>${esc(next.plan?.selection?.setting)} · ${esc(window.GpoUiDomain.outcome(next).mismatch?'Compare different endpoint values':'Complete the endpoint evidence')}</strong></span>${window.GpoComponents.icon('chevron')}</button>`:'<p class="experience-empty">'+(samples.length?'No unresolved readings in these records.':'Run a policy verification to collect endpoint readings.')+'</p>'}<p class="experience-footnote">Latest result per control, GPO and target. This is recorded evidence, not domain-wide coverage.</p></section>`;
  }
  function executionRail(job,plans,history){
    if(!['RUNNING','QUEUED','VERIFY_SCHEDULED'].includes(job?.state)||!plans.length)return '';
    const completed=new Set(job.completedIds||[]);
    const run=history.find(h=>h.id===job.currentOperationId);
    const sameTarget=(p,h)=>p.selection.setting===h?.plan?.selection?.setting&&p.selection.gpoId===h?.plan?.selection?.gpoId&&p.selection.scopeDn===h?.plan?.selection?.scopeDn;
    // A reviewed rebase gets a new plan ID. Resolve it from the actual server record, never queue position.
    const current=plans.find(p=>p.id===job.currentOperationId)||plans.find(p=>run&&sameTarget(p,run));
    const isProcessed=p=>completed.has(p.id)||history.some(h=>completed.has(h.id)&&sameTarget(p,h));
    const stage=(run?.stages||[]).filter(s=>!s.finishedAt).at(-1)?.phase;
    return `<section class="execution-rail" aria-label="Live control execution"><header><div><span class="experience-kicker">SERVER ACTIVITY</span><h4>${current?'Current control · '+esc(current.selection.setting):job.state==='QUEUED'?'Waiting for worker':'Waiting for the next server stage'}</h4></div><span class="experience-count">${esc(job.action)}</span></header><p>${esc(stage?stage.replaceAll('_',' ').toLowerCase():job.message||'Waiting for server evidence.')}</p><ol>${plans.map(p=>{const state=p===current?'current':isProcessed(p)?'processed':'queued';return `<li data-execution-state="${state}" ${state==='current'?'aria-current="step"':''}><span aria-hidden="true">${state==='current'?window.GpoComponents.icon('activity'):state==='processed'?'✓':'·'}</span><code>${esc(p.selection.setting)}</code><small>${state==='current'?'Processing':state==='processed'?'Processed':'Queued'}</small></li>`;}).join('')}</ol><small class="experience-footnote">Processed means the server returned a result. Inspect GPO and endpoint outcomes below.</small></section>`;
  }
  let previous=new Map();
  const reduced=()=>matchMedia('(prefers-reduced-motion: reduce)').matches;
  function animate(el,kind='fade',delay=0){
    if(!el||reduced()||!el.animate)return;
    el.animate([{opacity:0,translate:kind==='drawer'?'16px 0':'0 6px'},{opacity:1,translate:'0 0'}],{duration:kind==='drawer'?240:200,delay,fill:'backwards',easing:'cubic-bezier(.2,.7,.2,1)'});
  }
  const sections={'#/dashboard':'grid','#/benchmark':'library','#/operations':'activity','#/reports':'report','#/diagnostics':'diagnostics','#/assurance':'key','#/audit':'history'};
  function sectionHeading(root){
    const header=root.querySelector('.dashboard-heading,.library-hero,.page-header,.hero.compact'),symbol=sections[location.hash];
    if(!header||!symbol)return;
    header.classList.add('experience-heading');
    const heading=header.querySelector('h1');if(!heading||header.querySelector('.section-mark'))return;
    const mark=document.createElement('span');mark.className='section-mark';mark.setAttribute('aria-hidden','true');mark.innerHTML=window.GpoComponents.icon(symbol);
    heading.parentElement.prepend(mark);
  }
  function afterRender(root){
    const next=new Map();
    sectionHeading(root);
    const tab=root.querySelector('[role=tab][aria-selected=true]')?.dataset.tab||'',route=location.hash+':'+tab;
    next.set('route',route);
    if(previous.get('route')!==route){
      const main=root.querySelector('#main-content');
      const children=main?.querySelector('.dashboard-page')?.children||main?.children||[];
      [...children].filter(el=>!el.matches('.ds-toast')).slice(0,7).forEach((el,i)=>animate(el,'fade',i*18));
    }
    for(const [selector,key,kind] of [
      ['.product-drawer','drawer','drawer'],['.bulk-dialog','bulk','fade'],['.confirm-dialog','confirm','fade'],
      ['.result-summary','result','fade'],['.live-verification','live','fade'],['.gpo-modal','scope','fade'],
      ['.notification-panel','notifications','drawer'],['.product-help','help','fade'],['.ds-toast','toast','fade']
    ]){
      const el=root.querySelector(selector);if(!el)continue;
      const signature=key==='drawer'?el.querySelector('h2')?.textContent:key==='bulk'?el.dataset.bulkPhase:key==='result'?el.querySelector('.recorded-result-context')?.textContent:key==='toast'?el.textContent:key;
      next.set(key,signature);
      if(!previous.has(key)||previous.get(key)!==signature)animate(key==='bulk'&&previous.has(key)?el.querySelector('.bulk-dialog-body'):el,kind);
    }
    for(const el of root.querySelectorAll('.ent-domain-body[id],.ent-sub-body[id]')){
      const key='expanded:'+el.id;next.set(key,true);if(!previous.has(key))animate(el);
    }
    previous=next;
  }
  // Opening sections uses native details semantics. No delayed actions or focus interception.
  document.addEventListener('click',event=>{
    const el=event.target.closest('summary')?.parentElement;
    if(el?.tagName==='DETAILS'&&!el.open&&el.matches('.verification-details,.bulk-control-card,.ds-activity,.bulk-warnings,.ps-details,.gr-auto-card,.gr-auto-advanced,.ent-check details,.ds-preferences'))
      requestAnimationFrame(()=>{if(el.isConnected&&el.open)for(const child of el.children)if(child.tagName!=='SUMMARY')animate(child);});
  },true);
  // Settings and sign-in live outside the route renderer. Observe their openings only.
  const externalStates=new WeakMap();
  const externalObserver=new MutationObserver(records=>{
    const candidates=new Set();
    for(const record of records){
      if(record.type==='attributes'&&record.target.matches('.operator-sign-in,#gr-auto-panel'))candidates.add(record.target);
      else for(const node of record.addedNodes)if(node.nodeType===1){
        if(node.matches('.operator-sign-in,#gr-auto-panel'))candidates.add(node);
      }
    }
    for(const el of candidates){
      const visible=el.matches('.operator-sign-in')||el.id==='gr-auto-panel'&&el.classList.contains('open');
      if(visible&&!externalStates.get(el))animate(el.matches('.operator-sign-in')?el.querySelector('form'):el.querySelector('.gr-auto-head'));
      externalStates.set(el,visible);
    }
  });
  externalObserver.observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['class']});
  matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change',event=>{
    if(event.matches)for(const animation of document.getAnimations())animation.cancel();
  });
  window.GpoExperience=Object.freeze({queue,evidenceMatrix,executionRail,afterRender});
})();
