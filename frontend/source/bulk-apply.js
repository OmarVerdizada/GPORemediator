/* Optional batch workspace. Single-control forms and their mutation handlers
   remain independent. All mutations use the existing durable server workflow. */
(()=>{'use strict';
const esc=v=>window.GpoComponents.esc(v),active=j=>['QUEUED','RUNNING','VERIFY_SCHEDULED'].includes(j?.state);
const eligible=(s,r)=>!!s.settings?.find(m=>m.id===(r.backendSetting||r.id));
const picked=s=>s.bulkSelected||new Set();
const widgets={
 toolbar(s){return `<div class="bulk-catalog-tools"><button type="button" class="ds-button ds-secondary" data-bulk-mode>${s.bulkMode?'Exit bulk selection':'Bulk apply'}</button>${s.bulkMode?`<span>${picked(s).size} / 20 selected</span><button type="button" class="ds-button ds-primary" data-bulk-open ${!picked(s).size?'disabled':''}>Review selected controls</button><button type="button" class="ds-button ds-secondary" data-bulk-clear>Clear selection</button>`:''}</div>`;},
 checkbox(s,r){return s.bulkMode?`<label class="bulk-control-select"><input type="checkbox" data-bulk-select="${esc(r.id)}" aria-label="Select control ${esc(r.id)}" ${picked(s).has(r.id)?'checked':''} ${!eligible(s,r)?'disabled':''}></label>`:'';},
 section(s,id,rules){if(!s.bulkMode)return '';const supported=rules.filter(r=>eligible(s,r));return `<div class="bulk-section-tools"><label>Control group<select data-bulk-range="${esc(id)}">${Array.from({length:Math.ceil(supported.length/20)},(_,i)=>`<option value="${i}" ${Number(s.bulkRanges?.[id]||0)===i?'selected':''}>${i*20+1}–${Math.min(i*20+20,supported.length)} of ${supported.length}</option>`).join('')}</select></label><button type="button" class="ds-button ds-secondary ds-sm" data-bulk-group="${esc(id)}" ${!supported.length?'disabled':''}>Use this group</button><small>Up to 20 controls per reviewed batch.</small></div>`;}
};
function create({state,api,run,render,matchesRule}){
 state.bulkSelected=new Set();state.bulkMode=false;state.bulkRanges={};
 let open=false,phase='target',job=null,source=null,plans=[],pending=false,polling=false,error='',pollError='',revision=0,previewKey='',resultSignature='',queryTimer;
 const draft={gpoId:'',scopeDn:'',endpointScopeDn:'',verificationUser:'',gpoQuery:'',scopeQuery:'',endpointQuery:'',refresh:false,reviewContext:'',reference:'',approver:'',confirmation:'',impact:false,protected:false};
 const values=new Map(),expanded=new Set();
 const mapping=id=>state.settings.find(m=>m.id===id);
 const selected=()=>[...state.bulkSelected].map(id=>mapping(id)).filter(Boolean);
 const offline=()=>state.serviceOffline||state.serviceTransition||!state.gpoSession?.connected||state.session?.mode!=='WINDOWS';
 const userSelected=()=>selected().some(m=>m.scope==='User');
 function entry(m){if(!values.has(m.id))values.set(m.id,{value:m.suggested??0,customValue:m.inputDefault??'',itemValues:null});return values.get(m.id);}
 function selections(){return selected().map(m=>{const e=entry(m),accountScope=m.scope==='User'?'Users':m.domainPolicySensitive&&!/^OU=/i.test(draft.scopeDn)?'Domain':'LocalComputers';return {gpoId:draft.gpoId,scopeDn:draft.scopeDn,setting:m.id,value:e.value,customValue:e.customValue,itemValues:e.itemValues,
  accountScope,firstLink:accountScope==='Domain',refresh:draft.refresh?(accountScope==='Domain'?'Pdc':'Scope'):'None',endpointScopeDn:m.scope==='User'?draft.endpointScopeDn:null,verificationUser:m.scope==='User'?draft.verificationUser.trim()||null:null,reviewContext:m.automation!=='Automated'?draft.reviewContext.trim():null};});}
 const key=()=>JSON.stringify([selections(),state.gpoSession?.sessionId,state.service?.processId]);
 function invalidate(){revision++;plans=[];job=null;source=null;previewKey='';resultSignature='';phase='target';error='';pollError='';draft.confirmation='';draft.impact=false;draft.protected=false;}
 function saveInput(target){
  const row=target.closest('[data-bulk-control]');if(row){const m=mapping(row.dataset.bulkControl),e=entry(m);e.customValue=row.querySelector('[name=customValue]')?.value??e.customValue;e.value=Number(row.querySelector('[name=value]')?.value??e.value);
   const effective=m.automation==='Automated'?m:{...m,automation:'Automated',handler:m.handler==='Manual'?'SecurityTemplate':m.handler};
   const copy={...e,reviewContext:m.automation!=='Automated'?draft.reviewContext:null};window.GpoValueEditor.capture(row,effective,copy);e.itemValues=copy.itemValues;
  }else if(target.dataset.bulkField){draft[target.dataset.bulkField]=target.type==='checkbox'?target.checked:target.value;}
 }
 function options(items,query,selectedValue,value,label){const q=query.toLowerCase(),chosen=items.find(x=>x[value]===selectedValue),rows=items.filter(x=>x[value]!==selectedValue&&(`${x[label]} ${x[value]}`).toLowerCase().includes(q)).slice(0,chosen?199:200);if(chosen)rows.unshift(chosen);return rows.map(x=>`<option value="${esc(x[value])}" ${x[value]===selectedValue?'selected':''}>${esc(x[label])} · ${esc(x[value])}</option>`).join('');}
 function targetForm(){const inventory=state.inventory||{},gpos=(inventory.gpos||[]).filter(g=>g.selectable),scopes=(inventory.scopes||[]).filter(x=>['OU','Domain'].includes(x.kind)),manual=selected().some(m=>m.automation!=='Automated');
  return `<form data-bulk-form><div class="bulk-target-grid"><label>GPO search<input id="bulk-gpo-query" data-bulk-field="gpoQuery" value="${esc(draft.gpoQuery)}" placeholder="Filter available GPOs"></label><label>Selected GPO<select id="bulk-gpoId" data-bulk-field="gpoId" required><option value="">Choose a GPO</option>${options(gpos,draft.gpoQuery,draft.gpoId,'id','name')}</select></label><label>Scope search<input id="bulk-scope-query" data-bulk-field="scopeQuery" value="${esc(draft.scopeQuery)}" placeholder="Name or distinguished name"></label><label>Target OU / domain<select id="bulk-scopeDn" data-bulk-field="scopeDn" required><option value="">Choose a target</option>${options(scopes,draft.scopeQuery,draft.scopeDn,'dn','name')}</select></label></div><p class="ds-caption">An OU may contain both users and computers. Each control writes its own User or Computer Configuration. Domain account policies use the domain root; an OU target configures local computer accounts.</p>${userSelected()?`<div class="bulk-target-grid"><label>User-session endpoint search<input id="bulk-endpoint-query" data-bulk-field="endpointQuery" value="${esc(draft.endpointQuery)}"></label><label>Computer OU for user-session checks<select id="bulk-endpointScopeDn" data-bulk-field="endpointScopeDn" ${draft.refresh?'required':''}><option value="">No endpoint checks</option>${options(scopes.filter(x=>x.kind==='OU'),draft.endpointQuery,draft.endpointScopeDn,'dn','name')}</select></label><label>Verification user (DOMAIN\\user or UPN)<input id="bulk-verificationUser" data-bulk-field="verificationUser" value="${esc(draft.verificationUser)}" maxlength="256"></label></div>`:''}${manual?`<label>Environment review for the selected reviewed controls<textarea id="bulk-reviewContext" data-bulk-field="reviewContext" maxlength="2048" required>${esc(draft.reviewContext)}</textarea></label>`:''}<label class="batch-field-check"><input type="checkbox" id="bulk-refresh" data-bulk-field="refresh" ${draft.refresh?'checked':''}> Run gpupdate after all GPO writes succeed</label><p class="ds-caption">Refresh targets are resolved separately for domain, computer and signed-in user policies. Endpoint verification is reported per control.</p><div class="bulk-control-editors">${selected().map(m=>{const e=entry(m),editable=m.automation==='Automated'?m:{...m,automation:'Automated',handler:m.handler==='Manual'?'SecurityTemplate':m.handler};return `<details data-bulk-control="${esc(m.id)}" ${expanded.has(m.id)||m.requiresInput?'open':''}><summary>${esc(m.id)} · ${esc(state.catalog.rules.find(r=>r.id===m.id)?.title||m.displayName||m.id)} <small>${m.scope==='User'?'User Configuration':m.domainPolicySensitive?'Account policy':'Computer Configuration'}${m.automation!=='Automated'?' · Review required':''}</small></summary>${window.GpoValueEditor.render({...state,selection:e},editable).replace(/data-policy-value="(\d+)"/g,(_,i)=>`id="bulk-value-${m.id}-${i}" data-policy-value="${i}"`).replace('name="customValue"',`id="bulk-custom-${m.id}" name="customValue"`)}</details>`;}).join('')}</div><div class="bulk-actions"><button type="submit" class="ds-button ds-primary" ${offline()||pending||!selected().length?'disabled':''}>Generate bulk preview</button><button type="button" class="ds-button ds-secondary" data-bulk-close>Close</button></div></form>`;
 }
 function planRows(){return `<div class="bulk-table-wrap"><table class="bulk-table"><thead><tr><th>Order / control</th><th>Before · stored GPO</th><th>Requested</th><th>Link at target</th></tr></thead><tbody>${plans.map((p,i)=>`<tr><td data-label="Order / control"><strong>${i+1} · ${esc(p.selection.setting)}</strong><small>${esc(state.catalog.rules.find(r=>r.id===p.selection.setting)?.title||mapping(p.selection.setting)?.displayName||p.selection.setting)}</small><small>${esc(p.preview.gpo.name)}</small>${p.selection.accountScope==='Users'?`<small>User checks: ${esc(p.selection.endpointScopeDn||'No endpoint OU')} · ${esc(p.selection.verificationUser||'Signed-in sessions')}</small>`:''}<small>Refresh: ${esc(p.selection.refresh||'None')}</small></td><td data-label="Before · stored GPO">${esc(p.preview.previousValue??'Not configured')}<small>Source GPO: ${esc(p.preview.previousValueSource?.gpoName||(p.preview.previousValue!=null?p.preview.gpo.name:'—'))}</small>${p.preview.domainPolicy?`<small>Actual AD ${esc(p.preview.domainPolicy.property)}: ${esc(p.preview.domainPolicy.value)}</small>`:''}</td><td data-label="Requested">${esc(p.preview.desiredValue)}</td><td data-label="Link at target">${p.preview.existingLink?.enabled?`Enabled · priority ${esc(p.preview.existingLink.order)}`:'Will be linked'}${p.selection.firstLink&&p.preview.existingLink?.order!==1?'<small>Requested priority: 1</small>':''}</td></tr>`).join('')}</tbody></table></div>${plans.map(p=>`<details class="bulk-warnings"><summary>${esc(p.selection.setting)} · Plan details and warnings</summary><p>${esc(p.selection.scopeDn)}</p>${(p.preview.warnings||[]).map(w=>`<p>${esc(w)}</p>`).join('')}</details>`).join('')}`;}
 function review(){
  const protectedGpo=plans.some(p=>p.preview.gpo.protected);
  const conflicts=plans.flatMap(p=>window.GpoComponents.planConflicts(p.preview).map(c=>({...c,control:p.selection.setting})));
  const blocked=conflicts.some(c=>c.blocksApply);
  return `<h3>Review the complete batch</h3><p>${plans.length} controls · ${esc(plans[0]?.preview.gpo.name)} · ${esc(plans[0]?.selection.scopeDn)}</p>${window.GpoComponents.conflictList(conflicts)}${planRows()}<form data-bulk-approval><label>Change reference<input id="bulk-reference" data-bulk-field="reference" value="${esc(draft.reference)}" maxlength="128" required></label><label>Approver reference (optional)<input id="bulk-approver" data-bulk-field="approver" value="${esc(draft.approver)}" maxlength="256"></label><label class="batch-field-check"><input type="checkbox" id="bulk-impact" data-bulk-field="impact" ${draft.impact?'checked':''} required> I reviewed all values, existing links and affected targets.</label>${protectedGpo?`<label class="batch-field-check"><input type="checkbox" id="bulk-protected" data-bulk-field="protected" ${draft.protected?'checked':''} required> I approve editing this protected built-in GPO.</label>`:''}<label>Type APPLY<input id="bulk-confirmation" data-bulk-field="confirmation" value="${esc(draft.confirmation)}" pattern="APPLY" autocomplete="off" required></label><p>One backup is retained before each changed control. A failure stops later writes. Batch rollback restores the first changed control's full GPO snapshot and every changed AD account-policy snapshot.</p><div class="bulk-actions"><button class="ds-button ds-primary" type="submit" ${offline()||pending||!state.service?.writesEnabled||blocked||plans.some(p=>p.writeAuthorized===false)?'disabled':''}>Apply ${plans.length} controls</button><button type="button" class="ds-button ds-secondary" data-bulk-edit>Edit targets / values</button></div></form>`;}
 function result(){
  const completed=(source||job)?.completedIds||[];
  const runs=completed.map(id=>(state.history||[]).find(h=>h.id===id)).filter(Boolean);
  const undone=h=>h.batchStepRestored||['ROLLED_BACK','BATCH_ROLLED_BACK'].includes(h.result?.state);
  const recoveryTarget=[...runs].reverse().find(h=>h.result?.backupId&&!undone(h));
  const records=new Map(runs.map(h=>[h.plan.selection.setting,{h,o:window.GpoUiDomain.outcome(h)}]));
  const saved=runs.filter(h=>!undone(h)&&h.result?.gpoPublished&&h.result?.linkVerified).length;
  const restored=runs.filter(undone).length;
  const verified=[...records.values()].filter(({h,o})=>!undone(h)&&o.verified).length;
  const mismatch=[...records.values()].filter(({h,o})=>!undone(h)&&o.mismatch).length;
  const pendingChecks=Math.max(0,saved-verified-mismatch);
  const title=active(job)?(job.action==='rollback'?'Restoring batch snapshot':job.action==='verify'?'Re-checking selected controls':'Applying selected controls'):
    restored?(recoveryTarget?'Batch partly rolled back':'Batch snapshot restored'):
    mismatch?'Endpoint values differ':plans.length&&verified===plans.length?'Batch endpoint values verified':
    plans.length&&saved===plans.length?'GPO settings saved':'Batch requires review';
  const counts=[['GPO saved',saved],['Endpoint verified',verified],['Endpoint pending',pendingChecks],['Endpoint mismatch',mismatch]];
  if(restored)counts.push(['Rolled back',restored]);
  const rows=plans.map(p=>{
    const id=p.selection.setting,{h,o}=records.get(id)||{},r=h?.result;
    const controlTitle=state.catalog.rules.find(rule=>rule.id===id)?.title;
    const e=o?.endpoints;
    const isRestored=h&&undone(h);
    const publication=!h?'Not started':isRestored?'Snapshot restored':r.gpoPublished&&r.linkVerified?(r.state==='NO_CHANGE'?'Already configured':'Published'):'Needs review';
    const evidence=!h?'Awaiting execution':isRestored?(o.restoreMismatch?'Endpoint value differs':o.restoreSampleMatch?'Saved endpoint sample matches':'Endpoint undo pending'):
      o.verified?'Requested value verified':o.mismatch?'Value mismatch':e?.observed?'Configuration observed':e?.unavailable?'Endpoint unavailable':'Verification pending';
    const notes=(r?.endpointChecks||[]).filter(check=>['OBSERVED','UNAVAILABLE','MISMATCH','RESTORE_MISMATCH'].includes(check.state));
    const coverage=e?[e.verified&&`${e.verified} verified`,e.observed&&`${e.observed} observed`,e.unavailable&&`${e.unavailable} unavailable`,e.mismatch&&`${e.mismatch} mismatch`].filter(Boolean).join(' · '):'';
    const action=h?.id===recoveryTarget?.id?'Review rollback':'Details';
    return `<tr><td data-label="Control"><strong>${esc(id)}</strong>${controlTitle?`<small>${esc(controlTitle)}</small>`:''}</td><td data-label="GPO result">${publication}</td><td data-label="Endpoint evidence"><strong>${evidence}</strong>${coverage?`<small>${esc(coverage)}</small>`:''}${notes.length?`<details class="bulk-endpoint-notes"><summary>Host evidence</summary>${notes.map(check=>`<p><strong>${esc(check.hostname)}</strong> · ${esc(check.actualValue??check.message??check.state)}</p>`).join('')}</details>`:''}</td><td data-label="Action">${h?`<button type="button" class="ds-button ds-secondary ds-sm" data-bulk-inspect="${esc(h.id)}">${action}</button>`:'—'}</td></tr>`;
  }).join('');
  return `<div class="bulk-job-result" role="status"><h3>${title}</h3><p>${esc(job?.message||'Waiting for server results.')}</p>${active(job)?'<p class="bulk-live"><span class="checking-dot"></span> Updating from the server</p>':''}<dl class="bulk-metrics">${counts.map(([label,count])=>`<div><dt>${label}</dt><dd>${count}</dd></div>`).join('')}</dl></div><div class="bulk-table-wrap"><table class="bulk-table"><thead><tr><th>Control</th><th>GPO result</th><th>Endpoint evidence</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div><div class="bulk-actions">${!active(job)&&source?.completedIds?.length&&!restored?`<button type="button" class="ds-button ds-secondary" data-bulk-verify ${offline()?'disabled':''}>Re-verify batch</button>`:''}${!active(job)&&source&&recoveryTarget?`<button type="button" class="ds-button ds-danger" data-bulk-recover ${offline()?'disabled':''}>Rollback batch</button>`:''}<button type="button" class="ds-button ds-secondary" data-bulk-close>Close</button>${!active(job)?'<button type="button" class="ds-button ds-secondary" data-bulk-new>Start another batch</button>':''}</div>`;
 }
 function recovery(){return `<h3>Confirm full batch rollback</h3><p>This restores the earliest remaining GPO snapshot and its recorded batch AD account values. It can affect every existing GPO link. Current drift and permissions are checked again before restore.</p><form data-bulk-recovery><label>Type ROLLBACK<input id="bulk-confirmation" data-bulk-field="confirmation" pattern="ROLLBACK" required autocomplete="off"></label><label class="batch-field-check"><input id="bulk-refresh" data-bulk-field="refresh" type="checkbox" ${draft.refresh?'checked':''}> Refresh the recorded policy targets after a verified snapshot restore</label><p class="ds-caption">An older Not configured snapshot does not certify an endpoint undo. Endpoint observations remain separate.</p><div class="bulk-actions"><button type="submit" class="ds-button ds-danger" ${offline()||pending?'disabled':''}>Restore batch snapshot</button><button type="button" class="ds-button ds-secondary" data-bulk-cancel-recovery>Cancel</button></div></form>`;}
 function overlay(){if(!open)return '';if(phase==='target')for(const detail of document.querySelectorAll('.bulk-dialog [data-bulk-control]'))detail.open?expanded.add(detail.dataset.bulkControl):expanded.delete(detail.dataset.bulkControl);return `<div class="bulk-backdrop" data-bulk-close></div><section class="bulk-dialog" data-bulk-phase="${phase}" role="dialog" aria-modal="true" aria-labelledby="bulk-dialog-title" tabindex="-1"><header><div><span class="card-kicker">BULK POLICY CHANGE</span><h2 id="bulk-dialog-title">${phase==='target'?'Prepare selected controls':phase==='review'?'Preview & approval':phase==='recovery'?'Batch recovery':'Bulk operation'}</h2></div><button type="button" data-bulk-close aria-label="Close bulk apply">${window.GpoComponents.icon('close')}</button></header><div class="bulk-dialog-body">${offline()?'<p class="bulk-error">Live actions require the active domain connection. Recorded results remain available.</p>':''}${(error||pollError)?`<p class="bulk-error" role="alert">${esc(error||pollError)}</p>`:''}${pending?'<p role="status">Submitting to the server…</p>':phase==='target'?targetForm():phase==='review'?review():phase==='recovery'?recovery():job?.action==='preview'?`<h3>${active(job)?'Checking selected controls':'Bulk preview needs review'}</h3><p>${esc(job.message)}</p>${!active(job)?'<button type="button" class="ds-button ds-secondary" data-bulk-edit>Review targets / values</button>':''}`:result()}</div></section>`;}
 function history(){const rows=(state.workflowJobs||[]).filter(j=>j.action==='apply'&&j.batchId);return rows.length?`<section class="bulk-history"><h2>Bulk operations</h2>${rows.slice(0,20).map(j=>`<div><strong>${j.planIds?.length||0} controls · ${esc(j.state.replaceAll('_',' '))}</strong><small>${esc(j.updatedAt)}</small><button type="button" class="ds-button ds-secondary ds-sm" data-bulk-job="${esc(j.id)}">View bulk result</button></div>`).join('')}</section>`:'';}
 async function submit(path,payload){if(pending)return;pending=true;error='';pollError='';render();try{job=await api(path,payload);phase='working';}catch(e){error=e.message+' Check Operations for an accepted workflow before retrying; no write is automatically replayed.';}finally{pending=false;render();}}
 async function poll(){
  if(!job||polling||pending||offline()||document.hidden)return;
  polling=true;
  const id=job.id,current=revision;
  const stillCurrent=()=>current===revision&&job?.id===id&&!pending;
  try{
   const next=await api('/workflows/'+id);
   if(!stillCurrent())return;
   let changed=JSON.stringify(next)!==JSON.stringify(job);
   if(next.action==='preview'&&next.state==='COMPLETED'&&phase!=='review'){
    const ready=await api('/batches/'+next.batchId);
    if(!stillCurrent())return;
    if(!ready.plans?.length||ready.plans.some(p=>p.selection.gpoId!==draft.gpoId||p.selection.scopeDn!==draft.scopeDn))
     throw Error('Batch preview context changed. Generate a fresh preview.');
    plans=ready.plans;
    previewKey=key();
    phase='review';
    changed=true;
   }else if(next.action!=='preview'){
    const history=await api('/gpo/history');
    if(!stillCurrent())return;
    const ids=new Set((next.action==='apply'?next:source||next).completedIds||[]);
    const signature=JSON.stringify(history.filter(run=>ids.has(run.id)));
    changed ||= signature!==resultSignature;
    resultSignature=signature;
    state.history=history;
    if(next.action==='apply')source=next;
   }
   job=next;
   const recovered=!!pollError;
   pollError='';
   if(open&&(changed||recovered))render();
  }catch(e){
   if(!stillCurrent())return;
   const message='Live updates unavailable: '+e.message;
   if(message!==pollError){
    pollError=message;
    if(open)render();
   }
  }finally{polling=false;}
 }
 function handleInput(e){const t=e.target;if(!t.closest('.bulk-dialog'))return false;if(t.dataset.bulkField||t.closest('[data-bulk-control]'))saveInput(t);if(t.dataset.bulkField?.endsWith('Query')){clearTimeout(queryTimer);queryTimer=setTimeout(render,180);}return true;}
 function handleChange(e){const t=e.target;if(t.dataset.bulkRange){state.bulkRanges[t.dataset.bulkRange]=Number(t.value);return true;}if(t.dataset.bulkSelect){if(t.checked&&state.bulkSelected.size>=20){t.checked=false;state.notice='Select up to 20 controls per batch.';render();return true;}t.checked?state.bulkSelected.add(t.dataset.bulkSelect):state.bulkSelected.delete(t.dataset.bulkSelect);invalidate();render();return true;}if(!t.closest('.bulk-dialog'))return false;saveInput(t);if(phase==='target'&&t.dataset.bulkField&&['gpoId','scopeDn','endpointScopeDn','refresh'].includes(t.dataset.bulkField)){clearTimeout(queryTimer);if(t.dataset.bulkField==='scopeDn'&&userSelected()&&!draft.endpointScopeDn&&/^OU=/i.test(draft.scopeDn))draft.endpointScopeDn=draft.scopeDn;render();}return true;}
 function handleClick(e){const t=e.target;
  if(t.closest('[data-bulk-mode]')){state.bulkMode=!state.bulkMode;render();return true;}
  if(t.closest('[data-bulk-clear]')){state.bulkSelected.clear();invalidate();render();return true;}
  const group=t.closest('[data-bulk-group]');if(group){const id=group.dataset.bulkGroup,offset=Number(document.querySelector(`[data-bulk-range="${CSS.escape(id)}"]`)?.value||0)*20;state.bulkSelected=new Set(state.catalog.rules.filter(r=>r.id.startsWith(id+'.')&&eligible(state,r)&&matchesRule(r)).slice(offset,offset+20).map(r=>r.id));invalidate();render();return true;}
  if(t.closest('[data-bulk-open]')){open=true;render();return true;}
  if(t.closest('[data-bulk-close]')){open=false;render();return true;}
  if(t.closest('[data-bulk-edit]')){invalidate();open=true;render();return true;}
  if(t.closest('[data-bulk-new]')){state.bulkSelected.clear();invalidate();open=false;state.bulkMode=true;location.hash='#/benchmark';render();return true;}
  const restore=t.closest('[data-bulk-recover]');if(restore){draft.confirmation='';phase='recovery';render();return true;}
  if(t.closest('[data-bulk-cancel-recovery]')){phase='working';render();return true;}
  if(t.closest('[data-bulk-verify]')){run(()=>submit('/workflows/verify',{requestId:crypto.randomUUID(),planIds:source.completedIds,consent:{confirmation:''},refresh:'None',verificationDelays:[]}));return true;}
  const inspect=t.closest('[data-bulk-inspect]');if(inspect){open=false;state.inspectedOperation=inspect.dataset.bulkInspect;render();return true;}
  const member=t.closest('[data-bulk-from-operation]');if(member){run(async()=>{const all=await api('/workflows'),saved=all.find(j=>j.action==='apply'&&j.batchId&&j.completedIds.includes(member.dataset.bulkFromOperation));if(!saved)throw Error('The batch receipt is not available. Open Operations.');const batch=await api('/batches/'+saved.batchId);source=saved;job=[...all].filter(j=>j.action==='rollback'&&j.sourceWorkflowId===saved.id).sort((a,b)=>String(b.updatedAt).localeCompare(String(a.updatedAt)))[0]||saved;plans=batch.plans;state.inspectedOperation=null;open=true;phase='working';render();});return true;}
  const record=t.closest('[data-bulk-job]');if(record){run(async()=>{const saved=await api('/workflows/'+record.dataset.bulkJob),batch=await api('/batches/'+saved.batchId);source=saved;job=(state.workflowJobs||[]).filter(j=>j.action==='rollback'&&j.sourceWorkflowId===saved.id).sort((a,b)=>String(b.updatedAt).localeCompare(String(a.updatedAt)))[0]||saved;plans=batch.plans;open=true;phase='working';render();});return true;}
  if(t.closest('.bulk-dialog')){const reset=t.closest('[data-recommended-values]'),row=t.closest('[data-bulk-control]');if(reset&&row){values.delete(row.dataset.bulkControl);render();}return true;}
  return false;
 }
 function handleSubmit(e){const form=e.target;if(!form.matches('[data-bulk-form],[data-bulk-approval],[data-bulk-recovery]'))return false;e.preventDefault();if(pending||active(job))return true;
  if(form.matches('[data-bulk-form]')){for(const field of form.querySelectorAll('[data-bulk-field],[data-policy-value],[name=customValue]'))saveInput(field);const selection=selections();if(!selection.length||selection.length>20)return true;run(()=>submit('/workflows/preview',{requestId:crypto.randomUUID(),batch:{selections:selection}}));}
  if(form.matches('[data-bulk-approval]')){if(previewKey!==key()){error='Targets or connection changed. Generate a fresh preview.';render();return true;}run(async()=>{await submit('/workflows/apply',{requestId:crypto.randomUUID(),batchId:job.batchId,planIds:plans.map(p=>p.id),refresh:draft.refresh?'Auto':'None',verificationDelays:[],consent:{confirmation:draft.confirmation,acknowledgeImpact:draft.impact,acknowledgeProtected:draft.protected,changeReference:draft.reference.trim(),approvedBy:draft.approver.trim()}});if(job?.action==='apply')source=job;});}
  if(form.matches('[data-bulk-recovery]'))run(()=>submit('/workflows/rollback',{requestId:crypto.randomUUID(),planIds:[],sourceWorkflowId:source.id,refresh:draft.refresh?'Auto':'None',verificationDelays:[],consent:{confirmation:draft.confirmation}}));return true;
 }
 function close(){open=false;render();document.querySelector('[data-bulk-open],[data-bulk-mode]')?.focus();}
 return {overlay,history,poll,handleInput,handleChange,handleClick,handleSubmit,close};
}
window.GpoBulkApply=Object.freeze({widgets,create});
})();
