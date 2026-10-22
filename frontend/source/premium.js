/* Premium presentation: recorded evidence only, with no policy mutations. */
(() => {
  'use strict';
  const ui=window.GpoComponents,esc=ui.esc;
  function copyValue(s,value,label){
    if(value==null||value==='')return '<span class="pr-missing">—</span>';
    const hint='Copy: '+label;
    return `<span class="pr-identity"><code title="${esc(value)}">${esc(value)}</code><button type="button" class="pr-copy" data-copy-value="${esc(value)}" aria-label="${esc(hint)}" title="${esc(hint)}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/></svg></button></span>`;
  }
  function dashboardHeader(s){
    return `<header class="pr-dashboard-head"><div><span class="eyebrow">${'POLICY OPERATIONS'}</span><h1>${'Control center'}</h1><p>${'Connection, changes and evidence in one workspace.'}</p></div><a class="pr-primary-link" href="#/benchmark">${ui.icon('library')}${'Explore controls'}</a></header>`;
  }
  function heatmap(s){
    const latest=window.GpoProduct.latestByControl(s.history);
    const text=(a,e)=>ui.text(s,a,e),legend=[['good','Verified'],['warning','Needs review'],['pending','Recorded, unconfirmed'],['neutral','Rolled back'],['unknown','Not assessed']];
    return `<section class="pr-heatmap" aria-labelledby="pr-heatmap-title"><header><div><span class="eyebrow">${'CONTROL MAP'}</span><h2 id="pr-heatmap-title">${'405 controls, recorded outcomes'}</h2><p>${'Each cell is a control showing its latest operation. This does not certify compliance across the domain.'}</p></div></header><div class="pr-legend">${legend.map(([tone,label])=>`<span><i class="pr-dot ${tone}" aria-hidden="true"></i>${label}</span>`).join('')}</div><div class="pr-map-domains">${s.catalog.sections.filter(d=>!d.parentId).map(d=>{
      const rules=s.catalog.rules.filter(r=>r.id.startsWith(d.id+'.')).sort((a,b)=>a.id.localeCompare(b.id,undefined,{numeric:true}));
      return `<article class="pr-map-domain"><button class="pr-map-heading" data-dashboard-domain="${esc(d.id)}">${ui.domainIcon(d.id)}<span>${esc(d.id)} · ${esc(d.title)}</span><small>${rules.length}</small></button>${rules.length?`<div class="pr-cells" role="group" aria-label="${esc(d.title)}">${rules.map(r=>{const status=window.GpoProduct.controlStatus(s,r,latest),tone=!status.run?'unknown':status.run.result?.state==='ROLLED_BACK'?'neutral':status.tone==='good'?'good':status.tone==='warning'?'warning':'pending';const label=`${r.id} · ${r.title} · ${status.label}`;return `<button class="pr-cell ${tone}" data-rule="${esc(r.id)}" aria-label="${esc(label)}" title="${esc(label)}"><span aria-hidden="true">${tone==='good'?'✓':tone==='warning'?'!':tone==='neutral'?'↶':tone==='pending'?'·':''}</span></button>`;}).join('')}</div>`:`<p class="pr-map-empty">${'No standalone controls. Open the section for supplemental guidance.'}</p>`}</article>`;
    }).join('')}</div></section>`;
  }
  function emptyIcon(){return `<svg class="pr-empty-art" viewBox="0 0 120 80" width="120" height="80" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="20" y="14" width="80" height="52" rx="8"/><path d="M20 30h80M32 43h24m-24 10h16M75 40l12 5v8c0 6-12 12-12 12S63 59 63 53v-8z"/><path d="m70 51 4 4 7-8"/></svg>`;}
  window.GpoPremium=Object.freeze({copyValue,dashboardHeader,heatmap,emptyIcon});
})();
