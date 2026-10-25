/* Read-only target access and endpoint explanation. Pilot writes use the reviewed runner. */
(() => {
 'use strict';
 function create({state,esc,api,run,render}){
  const c={gpo:'',scope:'',control:'',firstLink:false,gpoSearch:'',runSearch:'',operation:'',host:'',hostSearch:'',access:null,explanation:null,scopeModal:null,scopeQuery:'',scopeExpanded:new Set(),scopePage:0,error:''};
  const options=(items,value,label,selected)=>items.map(x=>'<option value="'+esc(value(x))+'"'+(value(x)===selected?' selected':'')+'>'+esc(label(x))+'</option>').join('');
  const busy=()=>state.busy?' disabled':'';
  const badge=value=>'<span class="ps-badge ps-'+(/DENIED|CONFLICT|ERROR/.test(value)?'danger':/ALLOWED|SELECTED_GPO/.test(value)?'success':'warning')+'">'+esc(String(value||'UNKNOWN').replaceAll('_',' '))+'</span>';
  const selectedRun=()=>state.history.find(x=>x.id===c.operation);
  const setting=()=>state.settings.find(x=>x.id===c.control);
  function accessView(){
   if(!c.access)return '';
   return '<section class="content-card assurance-card"><div class="ps-section-heading"><h2>Effective access report</h2>'+badge(c.access.ready?'ALLOWED':'REVIEW_REQUIRED')+'</div><p>'+esc(c.access.executionUser)+' · '+esc(c.access.domainController)+' · '+esc(c.access.checkedAt)+'</p><p>'+esc(c.access.note)+'</p><div class="ent-table-wrap" tabindex="0" role="region" aria-label="Exact target permissions"><table class="ent-table"><thead><tr><th>Component / target</th><th>Required right</th><th>State</th><th>Administrator action</th></tr></thead><tbody>'+
    (c.access.checks||[]).map(x=>'<tr><td><strong>'+esc(x.label)+'</strong><small>'+esc(x.target)+'</small>'+(x.required===false?'<small>Separate capability; does not block GPO work</small>':'')+'</td><td>'+esc(x.requiredRight)+'</td><td>'+badge(x.state)+'</td><td>'+esc(x.remedy)+'</td></tr>').join('')+'</tbody></table></div></section>';
  }
  function explanationView(){
   const d=c.explanation;if(!d)return '';
   const run=selectedRun(),impact=run?.plan?.preview?.impact;
   return '<section class="content-card assurance-card"><div class="ps-section-heading"><h2>Why did this policy apply or fail?</h2>'+badge(d.state)+'</div><p>'+esc(d.hostname)+' · '+esc(d.checkedAt)+'</p><p>'+esc(d.note||'')+'</p>'+
    '<div class="ps-alert">Restart requirement in mapping: '+(d.requiresRestart?'Yes':'No')+'. Endpoint restart indicators: '+esc(d.pendingRestart?.state||'UNKNOWN')+'. Indicators can relate to other changes; no restart is triggered.</div>'+
    '<ul>'+(d.findings||[]).map(x=>'<li><strong>'+esc(x.state)+'</strong> — '+esc(x.message)+'</li>').join('')+'</ul>'+
    (impact?'<details class="ps-details"><summary>Preview inheritance and filtering context</summary><p>Recorded at Preview; this is not a fresh client processing decision.</p><pre>'+esc(JSON.stringify({inheritance:impact.inheritance,blockInheritance:impact.blockInheritance,securityFiltering:impact.securityFiltering,wmiFilter:impact.wmiFilter,conflicts:impact.conflicts},null,2))+'</pre></details>':'')+
    '<div class="ent-table-wrap" tabindex="0" role="region" aria-label="Per-setting policy sources"><table class="ent-table"><thead><tr><th>Setting</th><th>Recorded source</th><th>Result / limitations</th></tr></thead><tbody>'+
    (d.items||[]).map(x=>'<tr><td>'+esc(x.key)+'<small>'+esc(x.name||'')+'</small></td><td>'+esc(x.winningName||x.winningGpo||'Unknown')+'<small>Precedence: '+esc(x.precedence??'—')+'</small></td><td>'+badge(x.state)+'<small>'+esc(x.message)+'</small></td></tr>').join('')+'</tbody></table></div>'+
    '<details class="ps-details"><summary>Native effective values</summary><pre>'+esc(JSON.stringify(d.effectiveChecks||[],null,2))+'</pre></details>'+
    '<details class="ps-details"><summary>Recorded GPO filtering ('+(d.gpos||[]).length+')</summary><pre>'+esc(JSON.stringify(d.gpos||[],null,2))+'</pre></details>'+
    '<details class="ps-details"><summary>Recent GroupPolicy Operational events ('+(d.events||[]).length+')</summary>'+
    (d.events||[]).map(x=>'<details><summary>'+esc(x.time)+' · '+esc(x.id)+' · '+esc(x.level)+'</summary><pre>'+esc(x.message)+'</pre></details>').join('')+'</details></section>';
  }
  let context='';
  function view(){
   const current=[state.inventory?.domain,state.inventory?.domainController,state.inventory?.executionUser].join('|').toLowerCase();
   if(current!==context){c.access=null;c.explanation=null;c.gpo='';c.scope='';c.operation='';c.host='';context=current;}
   const inventory=state.inventory||{gpos:[],scopes:[]};
   if(!c.control)c.control=state.settings.find(x=>x.scope==='Computer'&&x.automation==='Automated')?.id||'';
   const gpos=inventory.gpos.filter(x=>(x.name+' '+x.id).toLowerCase().includes(c.gpoSearch.toLowerCase())||x.id===c.gpo);
   const runs=state.history.filter(x=>(x.plan?.preview?.gpo?.name+' '+x.plan?.selection?.setting+' '+x.id).toLowerCase().includes(c.runSearch.toLowerCase())||x.id===c.operation).slice(0,100);
   const operation=selectedRun(),hosts=(operation?.plan?.preview?.verificationComputers||operation?.plan?.preview?.refreshComputers||[]).filter(x=>x.toLowerCase().includes(c.hostSearch.toLowerCase())||x===c.host).slice(0,100);
   const map=setting(),quote=x=>"'"+String(x||'').replaceAll("'","''")+"'";
   const pilot='powershell.exe -NoProfile -File .\\scripts\\Invoke-LivePilot.ps1 -GpoId '+quote(c.gpo||'PILOT-GPO-GUID')+' -OuDn '+quote(c.scope||'OU=Pilot,DC=example,DC=local')+' -ControlId '+quote(c.control||'CONTROL-ID')+' -MaxComputers 5 -Confirmation '+quote('RUN PILOT');
   return '<header class="page-header"><div><span class="page-kicker">TARGET ASSURANCE</span><h1>Permissions & policy explanation</h1><p>Inspect exact delegated rights, logged policy sources and client processing evidence. These actions change no AD policy or delegation.</p></div></header>'+
    (c.error?'<p class="ps-alert ps-danger" role="alert">'+esc(c.error)+'</p>':'')+
    '<section class="content-card assurance-card"><h2>1 · Inspect the execution account</h2><form id="assurance-access" class="wf-grid"><label>Find GPO<input id="assurance-gpo-search" data-assurance="gpoSearch" value="'+esc(c.gpoSearch)+'" placeholder="Name or GUID"></label><label>GPO<select id="assurance-gpo" data-assurance="gpo" required><option value="">Choose a discovered GPO</option>'+options(gpos.slice(0,100),x=>x.id,x=>x.name,c.gpo)+'</select><small>Showing up to 100 matches; search to narrow the list.</small></label><div><span>OU / domain</span>'+window.GpoScopePicker.field(inventory.scopes,c.scope,'assurance-scope','All','en',true)+'</div><label>Control<select id="assurance-control" data-assurance="control">'+options(state.settings,x=>x.id,x=>x.id+' · '+x.title,c.control)+'</select></label><label class="assurance-link-intent"><input type="checkbox" data-assurance="firstLink"'+(c.firstLink?' checked':'')+'> Require highest link priority</label><button class="primary"'+(!state.inventory?' disabled':busy())+'>Check exact permissions</button></form></section>'+accessView()+
    '<section class="content-card assurance-card"><h2>2 · Explain a recorded plan</h2><form id="assurance-explain" class="wf-grid"><label>Find operation<input id="assurance-run-search" data-assurance="runSearch" value="'+esc(c.runSearch)+'" placeholder="Control, GPO or operation ID"></label><label>Recorded operation<select id="assurance-operation" data-assurance="operation" required><option value="">Choose an operation</option>'+options(runs,x=>x.id,x=>x.plan.selection.setting+' · '+x.plan.preview.gpo.name+' · '+x.id.slice(0,8),c.operation)+'</select></label><label>Find pinned endpoint<input id="assurance-host-search" data-assurance="hostSearch" value="'+esc(c.hostSearch)+'"></label><label>Endpoint<select id="assurance-host" data-assurance="host"><option value="">'+(operation?.plan?.selection?.accountScope==='Domain'?'Selected DC / domain context':'Choose a pinned endpoint')+'</option>'+options(hosts,x=>x,x=>x,c.host)+'</select><small>Up to 100 matches. A fresh preview is required for a new endpoint.</small></label><button class="primary"'+(!state.inventory?' disabled':busy())+'>Read RSoP and processing events</button></form><p>Logged RSoP can be stale. Source attribution does not replace fresh value checks, restart/service requirements or runtime enforcement checks.</p></section>'+explanationView()+
    '<section class="content-card assurance-card"><h2>3 · Run a dedicated live pilot</h2><p>Use a dedicated, unprotected GPO linked only to a pilot OU with 1–5 enabled computers. Authorize this GPO/OU and enable the change gate first. The runner rejects domain account and restart-dependent controls, captures baseline values, applies, refreshes, verifies, restores the snapshot, then compares endpoint values.</p><pre class="assurance-command">'+esc(pilot)+'</pre><p>Run this on the management host in the live environment. A credential prompt is shown there; passwords are not saved. Review the chosen control ('+esc(map?.title||'none')+') before running. Reports remain private in LocalAppData.</p></section>'+
    '<section class="content-card assurance-card"><h2>4 · Install or update a complete release</h2><p>Use Install-GpoRemediator.cmd -PackagePath FULL.zip -ExpectedSha256 TRUSTED_HASH. The installer validates every application component, stages an immutable version and changes the active pointer only after validation. -StopRunning requests an idle-safe service stop; active jobs are never killed. -Rollback activates the previous compatible version. ProgramData configuration, databases and backups remain outside version folders.</p></section>'+
    (c.scopeModal?window.GpoScopePicker.modal(inventory.scopes,c.scopeModal,c.scopeQuery,c.scopeExpanded,{'assurance-scope':c.scope},'en',false,true,'All',c.scopePage):'');
  }
  function execute(fn){if(state.busy)return;c.error='';run(async()=>{try{await fn();}catch(e){c.error=e.message;throw e;}});}
  function handleClick(e){
   if(location.hash!=='#/assurance')return false;
   if(e.target.closest('[data-scope-open]')){c.scopeModal='assurance-scope';c.scopePage=0;c.scopeQuery='';c.scopeExpanded=new Set((state.inventory?.scopes||[]).filter(x=>x.kind==='Domain').map(x=>x.dn.toLowerCase()));render();document.getElementById('scope-search')?.focus();return true;}
   if(e.target.closest('[data-scope-close]')){c.scopeModal=null;render();return true;}
   const branch=e.target.closest('[data-scope-expand]');if(branch){const key=branch.dataset.scopeExpand.toLowerCase();c.scopeExpanded.has(key)?c.scopeExpanded.delete(key):c.scopeExpanded.add(key);c.scopePage=0;render();return true;}
   const choice=e.target.closest('[data-scope-choose]');if(choice){c.scope=choice.dataset.scopeChoose;c.scopeModal=null;c.access=null;render();return true;}
   const page=e.target.closest('[data-list-page]');if(page&&page.dataset.listPage==='scope'){c.scopePage=Number(page.dataset.page);render();return true;}
   return false;
  }
  function handleInput(e){
   if(location.hash!=='#/assurance')return false;
   if(e.target.id==='scope-search'){c.scopeQuery=e.target.value;c.scopePage=0;render();return true;}
   const key=e.target.dataset.assurance;if(!key)return false;c[key]=e.target.type==='checkbox'?e.target.checked:e.target.value;
   if(['gpo','scope','control','firstLink'].includes(key))c.access=null;
   if(key==='operation'){c.host='';c.explanation=null;}if(key==='host')c.explanation=null;
   render();return true;
  }
  function handleSubmit(e){
   if(e.target.id==='assurance-access'){e.preventDefault();if(!c.scope){c.error='Choose an OU/domain.';render();return true;}
    execute(async()=>{const m=setting(),key=[context,c.gpo,c.scope,c.control,c.firstLink].join('|');const report=await api('/gpo/access-report',{gpoId:c.gpo,scopeDn:c.scope,setting:c.control,value:m?.suggested||0,accountScope:m?.scope==='User'?'Users':m?.domainPolicySensitive&&/^DC=/i.test(c.scope)?'Domain':'LocalComputers',firstLink:c.firstLink||!!m?.domainPolicySensitive&&/^DC=/i.test(c.scope),refresh:'None'});if(key===[context,c.gpo,c.scope,c.control,c.firstLink].join('|'))c.access=report;});return true;}
   if(e.target.id==='assurance-explain'){e.preventDefault();execute(async()=>{const key=[context,c.operation,c.host].join('|'),report=await api('/gpo/'+c.operation+'/explain',{hostname:c.host});if(key===[context,c.operation,c.host].join('|'))c.explanation=report;});return true;}
   return false;
  }
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&c.scopeModal){c.scopeModal=null;e.preventDefault();render();}});
  return {view,handleClick,handleInput,handleSubmit};
 }
 window.GpoAssurance={create};
})();
