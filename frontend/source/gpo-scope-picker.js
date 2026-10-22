/* Live-inventory OU selection. Read only: this component never changes AD/GPO. */
(() => {
  'use strict';
  const esc = x => String(x ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const tx = (lang,_fallback,en) => en;
  const norm = v => String(v||'').toLowerCase();
  // AD distinguished names contain escaped commas and backslashes. Do not use dn.split(',').
  function splitDn(dn){
    const out=[];let part='',escaped=false;
    for(const ch of String(dn||'')){
      if(escaped){part+=ch;escaped=false;continue;}
      if(ch==='\\'){part+=ch;escaped=true;continue;}
      if(ch===','){if(part.trim())out.push(part.trim());part='';continue;}
      part+=ch;
    }
    if(part.trim())out.push(part.trim());
    return out;
  }
  function parentDn(dn){return splitDn(dn).slice(1).join(',');}
  function approved(scopes,kind){
    return (Array.isArray(scopes)?scopes:[]).filter(x=>x&&typeof x.dn==='string'&&
      (x.kind==='OU'||x.kind==='Domain') && (kind==='All'?true:kind==='Domain'?x.kind==='Domain':x.kind==='OU'));
  }
  function available(scopes,kind){
    const list=(Array.isArray(scopes)?scopes:[]).filter(x=>x?.kind==='OU'||x?.kind==='Domain');
    return kind==='Domain'?list.filter(x=>x.kind==='Domain'):list;
  }
  function field(scopes,value,name,kind,lang,showAll=false){
    const item=(showAll?available(scopes,'All'):approved(scopes,kind)).find(x=>norm(x.dn)===norm(value));
    const label=name==='endpointScopeDn'?'Endpoint OU':
      kind==='Domain'?'Domain root':'Target OU';
    const suffix=name==='endpointScopeDn'?'Optional':'Selection required';
    return `<div class="visual-scope-field" data-scope-field="${esc(name)}"><input type="hidden" name="${esc(name)}" value="${esc(item?.dn||'')}"><button type="button" class="visual-scope-trigger ${item?'is-selected':''}" data-scope-open="${esc(name)}" aria-haspopup="dialog"><span class="visual-scope-symbol" aria-hidden="true">${kind==='Domain'?'◎':'▦'}</span><span class="visual-scope-copy"><small>${esc(label)}</small><strong>${esc(item?.name||'Choose from OU directory')}</strong><em>${esc(item?.dn||suffix)}</em></span><span class="visual-scope-arrow" aria-hidden="true">⌄</span></button></div>`;
  }
  function model(scopes,kind,query,expanded){
    const directory=available(scopes,kind);
    const map=new Map(directory.map(x=>[norm(x.dn),{...x,kids:[],parent:null}]));
    const roots=[];
    for(const node of map.values()){
      let p=parentDn(node.dn);
      while(p&&!map.has(norm(p))){p=parentDn(p);}
      if(p&&map.has(norm(p))){node.parent=map.get(norm(p));node.parent.kids.push(node);}else roots.push(node);
    }
    const sort=nodes=>{nodes.sort((a,b)=>String(a.name).localeCompare(String(b.name),undefined,{sensitivity:'base',numeric:true}));nodes.forEach(x=>sort(x.kids));};sort(roots);
    const q=norm(query).trim(),matches=new Set(),total=directory.filter(x=>kind==='All'?true:kind==='Domain'?x.kind==='Domain':x.kind==='OU').length;
    if(q)for(const x of map.values())if((x.kind==='OU'||kind==='Domain'||kind==='All')&&(norm(x.name).includes(q)||norm(x.dn).includes(q))){
      let n=x;while(n){matches.add(norm(n.dn));n=n.parent;}
    }
    const rows=[];
    function visit(node,depth){
      if(q&&!matches.has(norm(node.dn)))return;
      rows.push({node,depth,hasChildren:node.kids.length>0,open:q?true:expanded.has(norm(node.dn))});
      if(q||expanded.has(norm(node.dn)))node.kids.forEach(x=>visit(x,depth+1));
    }
    roots.forEach(x=>visit(x,0));
    return {rows,total,matches:q?directory.filter(x=>(kind==='Domain'||kind==='All'||x.kind==='OU')&&(norm(x.name).includes(q)||norm(x.dn).includes(q))).length:null};
  }
  function modal(scopes,fieldName,query,expanded,selection,lang,domainPolicySensitive=false,showAll=false){
    if(!fieldName)return '';
    const requiredKind=fieldName==='scopeDn'&&domainPolicySensitive?'Domain':'OU';
    const kind=showAll?'All':requiredKind;
    const {rows,total,matches}=model(scopes,kind,query,expanded||new Set());
    const eligible=x=>requiredKind==='Domain'?x.kind==='Domain':x.kind==='OU';
    const limit=240;
    return `<div class="visual-scope-backdrop" data-scope-close></div><section class="visual-scope-modal" role="dialog" aria-modal="true" aria-labelledby="visual-scope-title"><header class="visual-scope-head"><div><span class="visual-scope-kicker">ACTIVE DIRECTORY · READ ONLY</span><h2 id="visual-scope-title">${requiredKind==='Domain'?'Domain account policy scope':'Select target scope'}</h2><p>${showAll?(requiredKind==='Domain'?'All discovered scopes are visible for context. This password/lockout control can select only the domain root.':'All discovered scopes are visible for context. This control can select only an OU.'):(requiredKind==='Domain'?'This password/lockout control targets the domain root. Only the domain is shown; OU targeting does not apply to this control.':'This tree contains only discovered AD OUs. Choosing an OU does not apply a policy.')}</p></div><button type="button" class="visual-scope-close" data-scope-close aria-label="${'Close'}">×</button></header><div class="visual-scope-search"><span aria-hidden="true">⌕</span><input id="scope-search" type="search" value="${esc(query)}" placeholder="${requiredKind==='Domain'?'Search domain name or DN…':'Search OU name or DN…'}" aria-label="${requiredKind==='Domain'?'Search domain':'Search OUs'}" autocomplete="off"><small>${matches===null?total:matches} ${'matches'}</small></div><div class="visual-scope-list" role="tree" aria-label="${'Domain OU tree'}">${rows.slice(0,limit).map(({node,depth,hasChildren,open})=>{
      const selected=norm(selection?.[fieldName==='domainRoot'?'scopeDn':fieldName])===norm(node.dn);
      return `<div class="visual-scope-row ${selected?'is-current':''}" role="treeitem" aria-level="${depth+1}" ${hasChildren?`aria-expanded="${open}"`:''} style="--scope-depth:${Math.min(depth,12)}"><button type="button" class="visual-scope-expand" ${hasChildren?`data-scope-expand="${esc(node.dn)}"`:'disabled'} aria-label="${hasChildren?(open?'Collapse':'Expand'):''}">${hasChildren?(open?'▾':'▸'):'·'}</button><button type="button" class="visual-scope-item" ${eligible(node)?`data-scope-choose="${esc(node.dn)}"`:'disabled'}><span class="visual-scope-node-icon" aria-hidden="true">${node.kind==='Domain'?'◎':'▦'}</span><span class="visual-scope-node-copy"><strong>${esc(node.name)}</strong><small>${esc(node.dn)}</small></span>${selected?'<b class="visual-scope-current">✓</b>':eligible(node)?'<span class="visual-scope-pick">＋</span>':''}</button></div>`;
    }).join('')||`<p class="visual-scope-empty">${'No matching scope. Try another search.'}</p>`}${rows.length>limit?`<p class="visual-scope-hint">${'Showing first 240 rows. Narrow your search.'}</p>`:''}</div><footer class="visual-scope-foot"><span>${requiredKind==='Domain'?'Domain root for account policy · the selected GPO will use priority 1':'No manual DN entry · GPO and OU are validated in preview'}</span>${fieldName==='endpointScopeDn'?`<button type="button" data-scope-clear>${'Clear endpoint'}</button>`:''}<button type="button" data-scope-close>${'Close'}</button></footer></section>`;
  }
  window.GpoScopePicker=Object.freeze({splitDn,parentDn,approved,field,model,modal});
})();
