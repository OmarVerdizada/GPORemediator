/* GPO Remediator Enterprise UI — CIS v4.0.0. Operator UI for the hardened Windows/AD workflow chain. */
(() => {
'use strict';
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const client=window.GpoClient;
document.addEventListener('click',e=>{if(e.target.closest('.skip-link')){e.preventDefault();document.getElementById('main-content')?.focus();}});
const state={session:null,service:null,gpoSession:null,inventory:null,readiness:null,readinessError:'',settings:[],history:[],audit:null,auditQuery:'',auditIntegrity:'unknown',catalog:null,plan:null,busy:false,notice:'',query:'',level:'ALL',automation:'ALL',savedView:'ALL',expandedTop:new Set(),expandedSub:new Set(),catalogSearchCollapsed:new Set(),catalogSearchSubCollapsed:new Set(),selectedRule:null,tab:'overview',opsFilter:'ALL',opsQuery:'',theme:client.storage.get('gr-theme','system'),lang:'en',approval:{reference:'',approver:'',reviewed:false},applyDraft:{confirmation:'',impact:false,protected:false},notificationOpen:false,confirmAction:null,gpoSearch:'',gpoPickerOpen:false,scopeModal:null,scopeQuery:'',scopeExpanded:new Set(),serviceTransition:false,serviceOffline:false,healthProbeBusy:false,writeGateBlocked:false,modeRecoveryBusy:false,buildLabel:'3.17.3',selection:{gpoId:'',scopeDn:'',endpointScopeDn:'',verificationUser:'',setting:'',value:14,customValue:'',accountScope:'LocalComputers',refresh:'None',firstLink:false}};
let page,bar;
Object.assign(state,{opsSort:'newest',opsLayout:client.storage.get('gr-ops-layout','table'),inspectedOperation:null,helpOpen:false,lastHealthAt:null});
const writeResumeKey='gr-write-resume-v3';
function saveWriteResume(){
  const payload={version:3,createdAt:Date.now(),activationAttempts:Number(readWriteResume()?.activationAttempts||0)+1,route:location.hash||'#/control',selectedRuleId:state.selectedRule?.id||'',selection:state.selection,plan:state.plan,approval:state.approval,tab:state.tab||'remediation'};
  client.storage.set(writeResumeKey,JSON.stringify(payload));
}
function readWriteResume(){
  try{const raw=client.storage.get(writeResumeKey,'');if(!raw)return null;const x=JSON.parse(raw);if(!x||x.version!==3||Date.now()-Number(x.createdAt||0)>30*60*1000){client.storage.set(writeResumeKey,'');return null;}return x;}catch{client.storage.set(writeResumeKey,'');return null;}
}
function clearWriteResume(){client.storage.set(writeResumeKey,'');}
function resetApplyDraft(){state.applyDraft={confirmation:'',impact:false,protected:false};}
function restoreWriteResume({consume=false}={}){
  const r=readWriteResume();if(!r||!state.catalog)return false;
  const rule=state.catalog.rules.find(x=>x.id===r.selectedRuleId);if(rule)state.selectedRule=rule;
  if(r.selection)state.selection={...state.selection,...r.selection};
  state.plan=null;resetApplyDraft();
  if(r.approval)state.approval={...state.approval,...r.approval,reviewed:false};
  state.tab=r.tab||'remediation';
  if(consume)clearWriteResume();
  return true;
}
async function restoreDelegatedAfterRestart(){
  const restored=await client.reconnectDelegated();
  if(!restored)return false;
  state.session=restored.session;state.inventory=restored.inventory;state.gpoSession=restored.gpoSession;
  state.service=await client.request('/api/service',{timeout:5000});state.readiness=null;state.readinessError='';
  return true;
}
async function refreshFinalPlanAfterRestart(){
  if(!state.selection?.gpoId||!state.selection?.scopeDn||!state.selectedRule?.backendSetting)return false;
  state.targetAccessError=null;state.plan=await api('/gpo/preview',state.selection);clearTimeout(targetAccessTimer);++targetAccessSequence;state.targetAccessChecking=null;state.targetAccessError=null;state.targetAccessReady=targetKey();
  state.approval={...state.approval,reviewed:false};resetApplyDraft();clearWriteResume();
  return true;
}
async function waitForManagedRestart(previousProcessId){
  state.serviceTransition=true;state.serviceOffline=false;state.plan=null;
  state.approval.reviewed=false;resetApplyDraft();render();
  const deadline=Date.now()+75000;
  try{
    while(Date.now()<deadline){
      await new Promise(r=>setTimeout(r,1200));
      let service;
      try{service=await client.request('/api/service',{timeout:3000});}catch{continue;}
      if(service?.mode==='SETUP')throw Object.assign(new Error('Windows / AD service returned to Setup mode. Check windows-startup-error.log in Local Control Center.'),{code:'WINDOWS_MODE_REQUIRED'});
      if(!service?.processId||service.processId===previousProcessId||service.mode!=='WINDOWS')continue;
      state.service=service;
      // Connection/preview errors after the restart must reach the operator.
      // Retrying this block would repeatedly log in and hide the real failure.
      const restored=await restoreDelegatedAfterRestart();
      if(!restored){
        state.notice='Service restart completed. Reconnect the delegated account once; your selections are preserved.';
        location.hash='#/dashboard';return;
      }
      if(!state.service?.writesEnabled){
        state.writeGateBlocked=true;state.tab='remediation';location.hash='#/control';
        throw Object.assign(new Error('The backend does not report the write gate as enabled. Inspect Settings and Local Control Center.'),{code:'WRITE_GATE_TRANSITION_BLOCKED'});
      }
      await refreshFinalPlanAfterRestart();
      state.writeGateBlocked=false;state.tab='remediation';location.hash='#/control';
      state.notice='The delegated account was restored and the final preview was generated under the production boundary. Review and approve the new plan.';
      return;
    }
    throw Object.assign(new Error('Windows / AD restart did not complete within 75 seconds.'),{code:'SERVICE_UNREACHABLE'});
  }finally{state.serviceTransition=false;render();}
}
async function waitForWindowsPromotion(previousProcessId){
  state.serviceTransition=true;state.serviceOffline=false;render();
  const deadline=Date.now()+90000;
  let lastIssue='';
  while(Date.now()<deadline){
    await new Promise(r=>setTimeout(r,1000));
    try{
      const service=await client.request('/api/service',{timeout:3000});
      state.service=service;state.serviceOffline=false;
      if(service?.mode==='WINDOWS'&&service?.ready!==false&&(!previousProcessId||service.processId!==previousProcessId)){
        state.serviceTransition=false;state.modeRecoveryBusy=false;
        location.replace(location.origin+'/#/dashboard');location.reload();return;
      }
      if(service?.mode==='SETUP'&&service?.processId!==previousProcessId&&service?.startupIssue){
        lastIssue=service.startupIssue;state.serviceTransition=false;state.modeRecoveryBusy=false;
        throw Object.assign(new Error('Windows / AD backend returned to configuration mode: '+lastIssue),{code:'WINDOWS_MODE_REQUIRED'});
      }
    }catch(e){if(e?.code==='WINDOWS_MODE_REQUIRED')throw e;state.serviceOffline=true;}
  }
  state.serviceTransition=false;state.modeRecoveryBusy=false;
  const detail=lastIssue?` ${lastIssue}`:'';
  throw Object.assign(new Error('Windows / AD mode did not become active within 90 seconds. Check windows-startup-error.log and bootstrap.log in Local Control Center.'+detail),{code:'WINDOWS_MODE_REQUIRED'});
}
async function startWindowsModeFromSetup(){
  if(state.modeRecoveryBusy)return;
  state.modeRecoveryBusy=true;
  const cfg=await api('/setup/config');
  if(!cfg?.domain||!cfg?.domainController){state.modeRecoveryBusy=false;window.dispatchEvent(new CustomEvent('gr:open'));throw Object.assign(new Error('Domain and writable DC are not saved. Complete these two fields in Settings first.'),{code:'WINDOWS_CONFIG_REQUIRED'});}
  const previous=state.service?.processId;
  const payload={domain:cfg.domain,domainController:cfg.domainController,backupPath:cfg.backupPath,urls:location.origin,approvedGpoIds:Array.isArray(cfg.approvedGpoIds)?cfg.approvedGpoIds:['*'],authorizedOus:Array.isArray(cfg.authorizedOus)?cfg.authorizedOus:[],allowedHosts:Array.isArray(cfg.allowedHosts)?cfg.allowedHosts:[],autoRestart:true};
  state.notice='Configuration is being saved and the launcher is switching to Windows / AD mode. This transition will run once.';render();
  try{await api('/setup/config',payload);}catch(e){state.modeRecoveryBusy=false;throw e;}
  await waitForWindowsPromotion(previous);
}
async function enableWritesAndContinue(){
  if(state.writeGateBlocked)throw Object.assign(new Error('The previous change-gate transition did not complete. Your plan is preserved; inspect Settings and service state first.'),{code:'WRITE_GATE_TRANSITION_BLOCKED'});
  if(!state.gpoSession?.connected)throw Object.assign(new Error('Connect the delegated domain account before enabling change mode.'),{code:'GPO_LOGIN_REQUIRED'});
  if(!state.plan?.selection?.gpoId||!state.plan?.selection?.scopeDn)throw Object.assign(new Error('Create a read-only remediation plan first. The change gate is authorized only for the selected GPO and scope.'),{code:'PLAN_REQUIRED'});
  const cfg=await api('/setup/config');
  const approved=Array.isArray(cfg?.approvedGpoIds)?cfg.approvedGpoIds:[];
  const scopes=Array.isArray(cfg?.authorizedOus)?cfg.authorizedOus:[];
  const gpoId=String(state.plan.selection.gpoId).replace(/[{}]/g,'').toLowerCase();
  const selectedScopes=[...new Set([state.plan.selection.scopeDn,state.plan.selection.endpointScopeDn].filter(Boolean))];
  const needsNarrowing=!approved.length||!scopes.length||approved.includes('*')||scopes.includes('*')||!approved.some(x=>String(x).replace(/[{}]/g,'').toLowerCase()===gpoId)||!selectedScopes.every(dn=>scopes.some(x=>String(x).toLowerCase()===String(dn).toLowerCase()));
  saveWriteResume();
  if(needsNarrowing){
    state.notice='Production authorization is being prepared automatically for this plan: only the selected GPO and AD scope will be writable. You do not need to enter GUID/OU values manually in Settings. The service will then restart once.';render();
    const payload={domain:cfg.domain,domainController:cfg.domainController,backupPath:cfg.backupPath,urls:location.origin,approvedGpoIds:[state.plan.selection.gpoId],authorizedOus:selectedScopes,allowedHosts:Array.isArray(cfg.allowedHosts)?cfg.allowedHosts:[],autoRestart:false};
    await api('/setup/config',payload);
  }
  state.notice='The change gate is being enabled. The plan and selections are preserved; the service will perform exactly one managed restart.';
  const previous=state.service?.processId;
  let result;
  try{result=await api('/setup/write-mode',{enable:true,confirmation:'ENABLE WRITES',autoRestart:true});}
  catch(e){clearWriteResume();throw e;}
  if(!result?.restartScheduled)throw Object.assign(new Error('The write gate was saved, but a managed restart was not scheduled. Do not enable it again; inspect the service lifecycle in Local Control Center.'),{code:'LAUNCHER_REQUIRED'});
  await waitForManagedRestart(previous);
}
window.GpoI18n.setLanguage(state.lang);
const tr=k=>window.GpoI18n.t(k);
const statusText=v=>({PUBLISHED:'Published',NO_CHANGE:'No change',DRIFT_DETECTED:'Drift detected',REFRESH_COMPLETED:'gpupdate completed',VERIFIED_ON_ALL_TARGETS:'Verified on all pinned endpoints',REFRESH_SCHEDULED:'gpupdate scheduled',REFRESH_PARTIAL:'gpupdate incomplete / failed',REFRESH_NOT_CONFIGURED:'gpupdate not configured',VERIFY_MISMATCH:'Verification mismatch',REVIEW_REQUIRED:'Review required',ROLLED_BACK:'Rolled back',ROLLBACK_REVIEW_REQUIRED:'Rollback review required',ROLLBACK_DRIFT_DETECTED:'Drift detected after rollback',FAILED_SAFE:'Safely stopped',ENDPOINT_MISMATCH:'Endpoint mismatch',REPLICATION_PENDING:'Replication pending',VERIFIED_ON_SAMPLE:'Verified on endpoint sample',DOMAIN_VALUE_MATCHES_ON_SELECTED_DC:'Effective on selected DC',ENDPOINT_VERIFICATION_PENDING:'Endpoint verification pending'}[String(v||'').toUpperCase()]||String(v||'Unknown'));
const stateClass=v=>({danger:'bad',success:'ok',neutral:'pending',pending:'pending'}[window.GpoComponents.status(state,v).tone]);
const errorGuidance=e=>{const c=String(e?.code||'');if(/SERVICE_RESTARTED|SERVICE_UNREACHABLE|WINDOWS_MODE_REQUIRED/.test(c))return 'Check that Local Control Center is running REAL AD / WINDOWS mode; if the service restarted, reconnect the delegated domain identity.';if(/DNS/.test(c))return 'Point the management host to AD DNS and verify the DC FQDN resolves.';if(/WINRM/.test(c))return 'Check the WinRM HTTP listener and TCP/5985 firewall rule on the DC.';if(/KERBEROS/.test(c))return 'Check AD DNS, time sync, KDC/TCP 88 and the DC WSMAN/HTTP SPNs.';if(/LOGIN|CREDENTIAL|AUTH|OPERATOR/.test(c))return 'Check the account and delegated permissions, then reconnect.';if(/REPLICATION|SYSVOL/.test(c))return 'Check AD/SYSVOL replication and Verify again before changing anything.';if(/GPO_CHANGED|PLAN_STALE|DRIFT/.test(c))return 'Live state changed. Do not reuse the old plan; create a fresh plan.';if(/ACCESS|PERMISSION|DENIED/.test(c))return 'Check edit/gPLink permissions for the selected GPO and target.';if(/REFRESH|ENDPOINT/.test(c))return 'Check target host connectivity and effective policy separately.';return 'Review live state and Operations evidence before retrying.';};
function clearDelegatedState(){state.inventory=null;state.gpoSession=null;state.readiness=null;state.readinessError='';state.plan=null;}
async function syncServiceAfterFault(previousProcessId=state.service?.processId){
  try{
    const [session,service]=await Promise.all([
      client.request('/api/session',{timeout:5000}),
      client.request('/api/service',{timeout:5000})
    ]);
    const changed=!!previousProcessId&&!!service?.processId&&service.processId!==previousProcessId;
    state.session=session;state.service=service;state.serviceOffline=false;
    if(changed||session.mode!=='WINDOWS'){
      clearDelegatedState();
      if(session.mode!=='WINDOWS'){state.settings=[];state.history=[];syncBackendMappings();}
    }
    return {online:true,changed,session,service};
  }catch{state.serviceOffline=true;return {online:false,changed:false,session:null,service:null};}
}
async function api(path,body){
  const previousProcessId=state.service?.processId;
  try{return await client.request('/api'+path,{body,csrfToken:state.session?.csrfToken});}
  catch(e){
    if(e.code==='GPO_LOGIN_REQUIRED'){
      clearDelegatedState();
      // Retry only a read that was explicitly rejected before execution.
      // Apply/rollback and other writes are never replayed automatically.
      if(body===undefined&&await restoreDelegatedAfterRestart())
        return client.request('/api'+path,{csrfToken:state.session?.csrfToken});
      window.dispatchEvent(new CustomEvent('gr:connection-expired'));
    }
    if(e.code==='SERVICE_UNREACHABLE'&&state.serviceTransition){
      clearDelegatedState();state.serviceOffline=true;e.code='SERVICE_RESTARTING';e.message='The Windows / AD service is restarting in a controlled transition. Wait a few seconds; the page will recover when the service returns.';
      throw e;
    }
    if(e.code==='WINDOWS_MODE_REQUIRED'||e.code==='SERVICE_UNREACHABLE'){
      const status=await syncServiceAfterFault(previousProcessId);
      if(status.online&&status.session?.mode!=='WINDOWS'){
        e.code='WINDOWS_MODE_REQUIRED';
        e.message='Windows / AD service is not active; the application is in Setup mode. Check windows-startup-error.log and bootstrap.log in Local Control Center, restore Windows mode, then reconnect.';
      }else if(status.online&&status.changed){
        e.code='SERVICE_RESTARTED';
        e.message='The service restarted. Delegated domain credentials are not persisted; reconnect.';
      }
    }
    throw e;
  }
}
async function loadCatalog(){if(state.catalog)return;const catalog=await client.request('/benchmark-v4.json?v=1.1.0');if(!Array.isArray(catalog.rules)||!Array.isArray(catalog.sections))throw Error('Invalid benchmark catalog. Rebuild the frontend package.');state.catalog=catalog;}
function syncBackendMappings(){if(!state.catalog)return;const byId=new Map(state.settings.map(x=>[x.id,x]));for(const r of state.catalog.rules){const m=byId.get(r.id);const writable=!!m&&m.automation==='Automated'&&m.handler!=='Manual';r.backendSetting=m?.id||null;r.implementation=writable?'live':m?'manual':'unavailable';r.backendMapping=m||null;if(m&&m.automation!=='Automated')r.automation=m.automation;}state.catalog.meta.liveMappings=state.catalog.rules.filter(r=>r.implementation==='live').length;}
const say=(_fallback,en)=>window.GpoI18n.pair(_fallback,en);
const {topSections,children,directRules,descendants,matchesRule,riskFor,implLabel,badges,topDomainForRule,sectionTitle,renderSubsection,renderRuleRow,renderDomain,benchmarkView}=window.GpoCatalogView.create({state,esc,say,tr});
const {ensureSelection,selectedGpo,targetForm,controlView,relevantHistory,targetIssue,targetKey,accessFeedback}=window.GpoControlView.create({state,esc,say,tr,riskFor,badges,topDomainForRule,sectionTitle,renderConnection,uiIcon,stateClass,statusText});
const assurance=window.GpoAssurance.create({state,esc,api,run,render});
const operationMonitor=window.GpoOperationMonitor.create({state,api,render});
const enterpriseCenter=window.GpoEnterpriseCenter.create({state,esc,say,api,run,render});
const successful=h=>GpoUiDomain.classify(h).compliant;
const needsReview=h=>/FAIL|MISMATCH|REVIEW|PARTIAL|DRIFT/.test(String(h.result?.state||''));
function renderConnection(compact=false){
  if(state.serviceOffline)return `<div class="conn bad"><span class="conn-orb"></span><div><small>${'LOCAL BACKEND'}</small><strong>${'Service unavailable'}</strong><span>${'The Local Control Center is checking service state. The page will refresh automatically when the service returns.'}</span></div><button data-refresh>${'Retry'}</button></div>`;
  const i=(state.session?.mode==='WINDOWS'&&!state.service?.stopping&&state.gpoSession)?state.inventory:null;
  if(i){const exp=state.gpoSession?.expiresAt?new Date(state.gpoSession.expiresAt):null;const mins=exp?Math.max(0,Math.ceil((exp-Date.now())/60000)):null;return `<div class="conn ${state.readiness?.ready?'ok':'warn'}"><span class="conn-orb"></span><div><small>${state.readiness?.ready?'Execution session ready':'Signed in · readiness check required'}</small><strong>${esc(i.domain)}</strong><span>${esc(i.domainController)} · ${esc(i.executionUser)}${mins!=null?` · ${'session'} ${mins} min`:''}</span></div><div class="conn-actions"><button data-readiness title="Runs read-only AD/GPO readiness checks">${'Check readiness'}</button><button data-disconnect title="Clears delegated credentials from memory">${tr('logout')}</button></div></div>`;}
  if(state.session?.mode!=='WINDOWS'){const issue=state.service?.startupIssue?`<small class="conn-detail">${esc(state.service.startupIssue)}</small>`:'';return `<div class="conn warn recovery"><span class="conn-orb"></span><div><strong>${'Windows / AD mode is not active'}</strong><span>${'If domain configuration is present, promote the service directly to Windows / AD mode. The UI will not create another Setup loop.'}</span>${issue}</div><div class="conn-actions"><button class="primary-inline" data-start-windows ${state.modeRecoveryBusy?'disabled':''}>${state.modeRecoveryBusy?'Starting…':'Start Windows / AD'}</button><button data-settings>${'Settings'}</button></div></div>`;}
  return `<section class="conn login identity-connect"><div class="identity-copy"><span class="identity-badge">${'SINGLE SIGN-IN'}</span><strong>${'Execution session is inactive'}</strong><p>${'Open the application\'s single sign-in screen to continue.'}</p></div><button type="button" class="primary" data-domain-sign-in>${'Open sign-in'}</button></section>`;
}
function uiIcon(name){return window.GpoComponents.icon(name);}
function dashboardView(){
 const history=window.GpoProduct.sortedRuns(state.history),jobs=(state.workflowJobs||[]).filter(j=>['QUEUED','RUNNING','VERIFY_SCHEDULED'].includes(j.state));
 const active=history.filter(window.GpoProduct.active),review=history.filter(h=>GpoUiDomain.classify(h).attention),pending=history.filter(h=>!window.GpoProduct.active(h)&&!GpoUiDomain.classify(h).attention&&!GpoUiDomain.classify(h).compliant&&!/ROLL/.test(h.result?.state||''));
 const verified=history.filter(h=>GpoUiDomain.classify(h).compliant),attention=[...review,...pending].slice(0,4),recent=history.slice(0,6);
 const action={apply:'Applying change',verify:'Verifying policy',refresh:'Refreshing policy',rollback:'Restoring snapshot'};
 const jobRuns=new Set(jobs.flatMap(j=>j.planIds||[])),untracked=active.filter(h=>!jobRuns.has(h.id));
 const activeCount=jobs.length+untracked.length;
 const item=h=>{const quality=GpoUiDomain.classify(h),status=window.GpoProduct.active(h)||/ROLL/.test(h.result?.state||'')?GpoUiDomain.resultState(h):quality.compliant?'VERIFIED_ON_SAMPLE':quality.attention?'REVIEW_REQUIRED':'ENDPOINT_VERIFICATION_PENDING';return `<button type="button" class="dashboard-result-row" data-inspect="${esc(h.id)}"><span class="dashboard-control">${esc(h.plan?.selection?.setting||'GPO')}</span><span class="dashboard-result-target"><strong>${esc(h.plan?.preview?.gpo?.name||'Recorded operation')}</strong><small>${esc(h.plan?.selection?.scopeDn||'Target unavailable')}</small></span><span>${window.GpoComponents.status(state,status).html}<small class="dashboard-time">${esc(window.GpoProduct.date(h.updatedAt,state.lang))}</small></span></button>`;};
 const checks=state.readiness?.checks||[],failures=checks.filter(x=>x.state!=='PASS'&&x.required!==false);
 return `<div class="dashboard-page"><header class="dashboard-heading"><div><span class="eyebrow">DOMAIN OPERATIONS</span><h1>Dashboard</h1><p>Connection, ongoing work and recorded policy results.</p></div><a class="primary-action" href="#/benchmark">Choose a control →</a></header>
 <section class="dashboard-connection" aria-label="Domain connection">${renderConnection()}${state.serviceOffline||state.serviceTransition?'':`<div class="dashboard-connection-foot"><span>${state.service?.writesEnabled?'Changes enabled':'Read-only mode'}</span><a href="#/diagnostics">Connection details →</a></div>`}</section>
 ${state.operationMonitorError?`<p class="verification-explanation" role="status">Live updates unavailable: ${esc(state.operationMonitorError)}. Displaying the latest recorded results.</p>`:''}
 <section class="dashboard-summary" aria-label="Recorded operation summary"><div><span>Active jobs</span><strong>${activeCount}</strong></div><div><span>Needs review</span><strong>${review.length}</strong></div><div><span>Verified results</span><strong>${verified.length}</strong></div></section><p class="dashboard-disclaimer">Results cover recorded checks, not full domain compliance.</p>
 <div class="dashboard-columns"><div class="dashboard-main"><section class="dashboard-panel"><header><h2>Active operations</h2><a href="#/operations">All operations →</a></header>${activeCount?`<div class="dashboard-active-list">${jobs.map(j=>{const h=history.find(h=>(j.planIds||[]).includes(h.id)),stage=(h?.stages||[]).filter(x=>!x.finishedAt).at(-1)?.phase;return `<article class="dashboard-active-row"><span class="checking-dot" aria-hidden="true"></span><div><strong>${action[j.action]||'Policy operation'}</strong><small>${esc(h?.plan?.preview?.gpo?.name||j.currentControl||'Waiting for worker')} · ${esc(stage?stage.replaceAll('_',' ').toLowerCase():j.state==='QUEUED'?'Queued':'Running')}</small></div>${h?`<button data-inspect="${esc(h.id)}">Details</button>`:'<span class="dashboard-queued">Queued</span>'}</article>`;}).join('')}${untracked.map(h=>`<article class="dashboard-active-row"><span class="checking-dot" aria-hidden="true"></span><div><strong>${esc(h.plan?.preview?.gpo?.name||'Policy operation')}</strong><small>${esc(h.result?.state||'Running')}</small></div><button data-inspect="${esc(h.id)}">Details</button></article>`).join('')}</div>`:'<div class="dashboard-empty"><strong>No active operations</strong><p>Approved changes and read-only checks appear here while they run.</p></div>'}</section>
 <section class="dashboard-panel"><header><h2>Recent results</h2><span>${recent.length?Math.min(history.length,6)+' latest':'No records'}</span></header>${recent.length?recent.map(item).join(''):'<div class="dashboard-empty"><strong>Start with a read-only plan</strong><p>Choose a CIS control, GPO and target to prepare your first change.</p><a href="#/benchmark">Open benchmark →</a></div>'}</section></div>
 <aside class="dashboard-panel dashboard-attention"><header><h2>Needs attention</h2></header>${failures.length?`<div class="dashboard-readiness-warning"><strong>Connection checks need review</strong><ul>${failures.slice(0,3).map(c=>`<li>${esc(c.label)}: ${esc(c.message)}</li>`).join('')}</ul><a href="#/diagnostics">Review diagnostics →</a></div>`:''}${attention.length?attention.map(h=>`<button class="dashboard-attention-row" data-inspect="${esc(h.id)}"><strong>${esc(h.plan?.selection?.setting||'GPO')} · ${esc(h.plan?.preview?.gpo?.name||'Recorded operation')}</strong><span>${esc(GpoUiDomain.classify(h).attention?'Review required':'Verification incomplete')}</span><small>${esc(h.result?.diagnosis?.[0]||h.result?.message||'Inspect the recorded evidence.')}</small></button>`).join(''):!failures.length?'<div class="dashboard-empty"><strong>No recorded issues</strong><p>Live verification establishes the value for each selected target.</p></div>':''}</aside></div></div>`;
}

function operationsView(){return operationViews().operationsView();}
function auditView(){return operationViews().auditView();}
function operationViews(){return window.GpoOperationView.create({state,esc,say,tr,successful,statusText,stateClass});}
function notifications(){const items=[];const exp=state.gpoSession?.expiresAt?new Date(state.gpoSession.expiresAt):null,mins=exp?Math.max(0,Math.ceil((exp-Date.now())/60000)):null;if(mins!=null&&mins<=5)items.push(['Session expiring',say(`Delegated AD session expires in ${mins} minute(s).`,`Delegated AD session expires in ${mins} minute(s).`)]);if(state.session?.mode!=='WINDOWS')items.push(['Windows / AD inactive','Start Windows / AD mode from Control Center or this page.']);if(!state.inventory)items.push(['AD not connected','Connect before generating a real remediation plan.']);const review=state.history.filter(h=>/FAIL|REVIEW|PARTIAL|DRIFT|MISMATCH/.test(String(h.result?.state||'').toUpperCase())).length;if(review)items.push(['Operations need review',`${review} operation(s) require attention.`]);if(state.readiness&&!state.readiness.ready)items.push(['Environment needs attention','One or more required backend readiness checks did not pass.']);return items;}
function notifications(){const items=[];const exp=state.gpoSession?.expiresAt?new Date(state.gpoSession.expiresAt):null,mins=exp?Math.max(0,Math.ceil((exp-Date.now())/60000)):null;if(mins!=null&&mins<=5)items.push(['Session expiring',say(`Delegated AD session expires in ${mins} minute(s).`,`Delegated AD session expires in ${mins} minute(s).`)]);if(state.session?.mode!=='WINDOWS')items.push(['Windows / AD inactive','Start Windows / AD mode from Control Center or this page.']);if(!state.inventory)items.push(['AD not connected','Connect before generating a real remediation plan.']);const review=state.history.filter(h=>GpoUiDomain.classify(h).attention).length;if(review)items.push(['Operations need review',`${review} operation(s) require attention.`]);if(state.readiness&&!state.readiness.ready)items.push(['Environment needs attention','One or more required backend readiness checks did not pass.']);return items;}
function overlays(){const notes=notifications(),c=state.confirmAction;return `${state.notificationOpen?`<div class="overlay-backdrop" data-close-overlay></div><aside class="notification-panel"><div class="overlay-head"><div><span>NOTIFICATION CENTER</span><h2>Attention & status</h2></div><button data-close-overlay aria-label="Close">×</button></div><div class="notification-list">${notes.map((n,i)=>`<div><b>${i+1}</b><span><strong>${esc(n[0])}</strong><small>${esc(n[1])}</small></span></div>`).join('')||`<div class="panel-empty">${'No notifications need attention.'}</div>`}</div></aside>`:''}${c?`<div class="overlay-backdrop confirm-backdrop"></div><div class="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title"><span class="confirm-icon">!</span><h2 id="confirm-title">${c.kind==='apply'?'Confirm GPO change':c.kind==='gpupdate'?'Confirm gpupdate /force':'Confirm rollback'}</h2><p>${c.kind==='apply'?'This changes the selected GPO. A backup is created first; review the scope and values one final time.':c.kind==='gpupdate'?(window.GpoUiDomain.isUserPolicy(state.history.find(h=>h.id===c.id),state.settings)?'This schedules user policy refresh on the recorded session endpoint OU computers. Signed-in users on those hosts can receive a refresh; Windows determines which policies apply. Scheduling does not prove completion. The backend rechecks live GPO publication and link state first.':'This refreshes the recorded endpoints. After rollback, both computer and signed-in user policy refresh are scheduled, and the restored snapshot is checked again. Scheduling does not prove completion.'):'This imports all saved policy settings into the same GPO and restores the selected link. GPO security and WMI filtering are preserved. Rollback is blocked if external changes are detected.'}</p>${c.kind==='apply'?`<dl class="ds-confirm-context"><div><dt>GPO</dt><dd>${esc(state.plan?.preview?.gpo?.name)}</dd></div><div><dt>${'Target'}</dt><dd>${esc(state.plan?.selection?.scopeDn)}</dd></div><div><dt>${'New value'}</dt><dd>${esc(state.plan?.preview?.desiredValue)}</dd></div><div><dt>${'Risk'}</dt><dd>${esc(riskFor(state.selectedRule).name)}</dd></div></dl>`:''}${c.kind==='rollback'?`<dl class="ds-confirm-context">${[["GPO",state.history.find(h=>h.id===c.id)?.plan?.preview?.gpo?.name],['Backup',state.history.find(h=>h.id===c.id)?.result?.backupId],['Operation ID',c.id],['gpupdate /force',c.refresh==='Scope'?'Scope computers':c.refresh==='Pdc'?'PDC emulator':'Not scheduled']].map(([label,value])=>`<div><dt>${label}</dt><dd>${esc(value||'—')}</dd></div>`).join('')}</dl>`:''}${c.kind==='gpupdate'?`<label class="refresh-target-label">${'Refresh targets'}<select id="refresh-target">${window.GpoUiDomain.refreshChoices(state.history.find(h=>h.id===c.id),state.settings).map(x=>`<option value="${esc(x.value)}" selected>${esc(x.label)}</option>`).join('')}</select><small>${'Only hosts authorized in Settings are refreshed. After rollback, the restored policy is checked.'}</small></label>`:''}<div class="confirm-actions"><button data-confirm-cancel>${'Cancel'}</button><button class="danger-action" data-confirm-run>${c.kind==='apply'?'Apply change':c.kind==='gpupdate'?'Run gpupdate':'Rollback'}</button></div></div>`:''}`;}
const renderOverlays=overlays;
overlays=function(){
 let html=renderOverlays(),c=state.confirmAction;
 if(c?.kind==='gpupdate'){
   const run=state.history.find(h=>h.id===c.id),user=run?.plan?.selection?.accountScope==='Users';
   if(run?.result?.state==='ROLLED_BACK')html=html.replace(/<h2 id="confirm-title">[\s\S]*?<\/h2><p>[\s\S]*?<\/p>/,'<h2 id="confirm-title">Confirm gpupdate /force after rollback</h2><p>This schedules both computer and signed-in user policy refresh on the recorded endpoints. The backend checks the restored snapshot and current scope before scheduling. Scheduling does not prove completion.</p>');
   if(user&&run?.result?.state!=='ROLLED_BACK')html=html.replace(/<option value="Pdc">[\s\S]*?<\/option>/,'').replace(/<option value="Scope">/,'<option value="Scope" selected>');
 }
 if(c&&(state.serviceOffline||state.serviceTransition))html=html.replace('<button class="danger-action" data-confirm-run>','<button class="danger-action" data-confirm-run disabled>');
 return html;
};
async function rollbackAndRefresh(action){
  await operationMonitor.submitSingle('rollback',action.id,{confirmation:action.confirmation},action.refresh||'None');
}
async function downloadEvidence(){const r=state.selectedRule,h=relevantHistory(r||{})[0];if(!r||!h)return;const payload=await api('/gpo/'+h.id+'/evidence');const blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`gpo-evidence-${r.id.replaceAll('.','-')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
async function loadAudit(){state.audit=await api('/audit');}
function exportAudit(){if(!state.audit)return;const payload={exportedAt:new Date().toISOString(),integrityValid:state.audit.integrityValid,events:state.audit.events||[]},blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`gpo-audit-${new Date().toISOString().slice(0,10)}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
function applyTheme(){window.GpoPreferences.apply(state);}
function noticeTone(message){const m=String(message||'').toLowerCase();if(/fail|error|unable|blocked|invalid/.test(m))return'error';if(/warning|review|required|pending/.test(m))return'warning';if(/success|connected|generated|completed|verified|loaded/.test(m))return'success';return'info';}
function productFooter(){return `<footer class="product-footer"><span>GPO Remediator · CIS v4.0.0</span><span>${esc(state.buildLabel)}</span></footer>`;}
function busyLayer(){return state.busy?`<div class="busy-layer" role="status" aria-live="polite"><div class="busy-card"><span class="busy-spinner"></span><div><strong>${'Processing request'}</strong><small data-request-progress>${'Keep this window open.'}</small><button type="button" data-cancel-request hidden>${'Stop waiting'}</button></div></div></div>`:'';}
let catalogRenderTimer;
function queueCatalogRender(){clearTimeout(catalogRenderTimer);catalogRenderTimer=setTimeout(render,160);}
let renderedRoute=null;
function render(){if(!page)return;const preferencesOpen=!!bar?.querySelector('.ds-preferences')?.open;const drawerScroll=page.querySelector('.product-drawer-body')?.scrollTop;const focused=document.activeElement,focusId=(page.contains(focused)||bar?.contains(focused))?focused.id:null,caret=focused?.selectionStart,selectionEnd=focused?.selectionEnd,selectionDirection=focused?.selectionDirection;if(!state.catalog){page.innerHTML=`<section class="content-card" role="status"><h1>GPO Remediator</h1><p>${esc(state.notice||'Loading benchmark catalog…')}</p>${state.busy?window.GpoComponents.skeleton(state):''}<button data-refresh ${state.busy?'disabled':''}>${'Retry'}</button><button data-settings>${tr('settings')}</button></section>${busyLayer()}`;client.localize(page);return;}applyTheme();window.GpoPreferences.install(state,render,installNav);const real=state.session?.mode==='WINDOWS';const serviceLabel=state.serviceOffline?'Service offline':state.serviceTransition?'Service restarting':(real?'Windows / AD':'Setup');bar.innerHTML=`<div class="service-left"><span class="agent-mark ${state.serviceOffline?'offline':state.serviceTransition?'pending':''}"></span><div><strong>GPO Remediator</strong><small>${'Policy Operations'} · ${serviceLabel} · ${state.serviceOffline||state.serviceTransition?'write status unavailable':real&&state.service?.writesEnabled?'changes enabled':'read-only'}</small></div></div><div class="service-right"><button data-refresh title="${tr('refresh')}" aria-label="${tr('refresh')}">${uiIcon('refresh')} <span>${tr('refresh')}</span></button>${window.GpoPreferences.menu(state)}<button data-notifications class="product-notification-button" aria-label="${'Notifications'}">${uiIcon('alert')}${notifications().length?`<span class="product-notification-count">${notifications().length}</span>`:''}</button><button data-settings aria-label="${tr('settings')}">${uiIcon('settings')} <span>${tr('settings')}</span></button></div>`;if(preferencesOpen)bar.querySelector('.ds-preferences').open=true;const route=window.GpoRouter.current();const main=((route==='#/dashboard'||route==='#/settings')?dashboardView():route==='#/benchmark'?benchmarkView():route==='#/control'?controlView():route==='#/audit'?auditView():route==='#/assurance'?assurance.view():(route==='#/reports'||route==='#/diagnostics')?enterpriseCenter.view(route):operationsView());const toast=state.notice?`<div class="ds-toast ${noticeTone(state.notice)}" role="status" aria-live="polite"><span>${uiIcon(noticeTone(state.notice)==='error'?'alert':'activity')}</span><span>${esc(state.notice)}</span><button data-dismiss-notice aria-label="${'Dismiss notification'}">${uiIcon('close')}</button></div>`:'';page.innerHTML=`<main id="main-content" tabindex="-1" class="product-main" aria-busy="${state.busy?'true':'false'}">${toast}${main}</main>${productFooter()}${overlays()}${window.GpoProduct.inspector(state)}${window.GpoProduct.help(state)}${busyLayer()}`;if(renderedRoute!==route){page.querySelector('main')?.classList.add('route-enter');renderedRoute=route;}updateNav();syncProductModal();if(drawerScroll!=null)page.querySelector('.product-drawer-body')?.scrollTo(0,drawerScroll);client.localize(page);client.localize(bar);client.localize(document.querySelector('.sidebar'));window.GpoPreferences.decorate(page);window.GpoPreferences.decorate(bar);if(focusId){const input=document.getElementById(focusId);input?.focus({preventScroll:true});if(caret!=null&&input?.setSelectionRange)input.setSelectionRange(caret,selectionEnd??caret,selectionDirection||'none');}}
function updateProgress(){const request=client.progress(),label=page?.querySelector('[data-request-progress]'),cancel=page?.querySelector('[data-cancel-request]');if(label&&request)label.textContent=`${request.label} · ${Math.floor((Date.now()-request.started)/1000)} / ${Math.round(request.timeout/1000)} ${'seconds'}`;if(cancel){cancel.hidden=!request?.cancelable;cancel.disabled=!request?.cancelable;}}
async function run(fn){if(state.busy)return;state.busy=true;state.notice='';let timer;try{render();timer=setInterval(updateProgress,250);await fn();}catch(e){if(/^(GPO_EDIT_ACCESS_DENIED|OU_LINK_ACCESS_DENIED|SYSVOL_WRITE_ACCESS_DENIED|GPO_ACCESS_UNVERIFIED)$/.test(e.code||'')){state.plan=null;clearTimeout(targetAccessTimer);++targetAccessSequence;state.targetAccessChecking=null;state.targetAccessError={code:e.code,message:e.message,gpoId:state.selection.gpoId,scopeDn:state.selection.scopeDn,setting:state.selection.setting,key:targetKey()};}state.notice=e.code==='SERVICE_RESTARTING'?(e.message||'Service restarting'):(e.message||'Error')+' — '+errorGuidance(e)+(e.correlationId?' · '+'Request ID: '+e.correlationId:'');}finally{clearInterval(timer);state.busy=false;render();}}
async function refresh(){
  await loadCatalog();
  const previousProcessId=state.service?.processId;
  const [session,service]=await Promise.all([api('/session'),api('/service')]);
  const serviceChanged=!!previousProcessId&&!!service?.processId&&service.processId!==previousProcessId;
  state.session=session;state.service=service;state.serviceOffline=false;state.serviceTransition=false;installNav(document.querySelector('.sidebar nav'));
  if(serviceChanged)clearDelegatedState();
  if(state.session.mode!=='WINDOWS'){state.settings=[];state.history=[];clearDelegatedState();syncBackendMappings();return;}
  [state.settings,state.history]=await Promise.all([api('/gpo/settings'),api('/gpo/history')]);syncBackendMappings();
  try{[state.inventory,state.gpoSession]=await Promise.all([api('/gpo/inventory'),api('/gpo/session')]);
    if(state.gpoSession?.connected){try{state.readiness=await api('/gpo/readiness');state.readinessError='';}catch(e){state.readiness=null;state.readinessError=e.message;}}
  }
  catch(e){if(e.code==='GPO_LOGIN_REQUIRED')clearDelegatedState();else throw e;}
}
async function checkReadiness(){
  state.readinessError='';
  state.notice='Checking connection: Kerberos, WinRM, AD, SYSVOL, backup, and GPMC are being validated live…';
  render();
  const expectedProcessId=state.service?.processId;
  try{
    const status=await syncServiceAfterFault(expectedProcessId);
    if(!status.online)throw Object.assign(new Error('The backend service is currently unreachable. Check service status, windows-startup-error.log and bootstrap.log in Local Control Center.'),{code:'SERVICE_UNREACHABLE'});
    if(status.session?.mode!=='WINDOWS')throw Object.assign(new Error('Windows / AD mode is not active. Use the “Start Windows / AD” action above to promote the service into operational mode.'),{code:'WINDOWS_MODE_REQUIRED'});
    if(status.changed)throw Object.assign(new Error('The service restarted. Reconnect the delegated domain session.'),{code:'SERVICE_RESTARTED'});
    if(!state.gpoSession||!state.inventory)throw Object.assign(new Error('No delegated domain session is active. Reconnect.'),{code:'GPO_LOGIN_REQUIRED'});
    state.readiness=await api('/gpo/readiness');
    if(!state.readiness.ready)state.notice='Connection checks need attention. Review the results below.';
  }catch(e){state.readinessError=e.message;state.notice=e.message;}
}
async function healthTick(){
  if(state.healthProbeBusy||state.busy||document.hidden)return;
  state.healthProbeBusy=true;
  const previous=state.service?.processId,previousMode=state.session?.mode,previousNotice=state.notice;
  try{
    const [service,session]=await Promise.all([client.request('/api/service',{timeout:5000}),client.request('/api/session',{timeout:5000})]);
    const changed=!!previous&&!!service?.processId&&service.processId!==previous;
    const recovered=state.serviceOffline||state.serviceTransition;
    state.service=service;state.session=session;state.lastHealthAt=Date.now();state.serviceOffline=false;state.serviceTransition=false;
    if(session.mode!=='WINDOWS'){if(previousMode!==session.mode)clearDelegatedState();}
    else if(changed){
      clearDelegatedState();
      if(await restoreDelegatedAfterRestart()){
        state.notice='Service and domain connection restored. Generate a fresh plan before making changes.';
      }else state.notice='Service recovered. Reconnect your domain account.';
    }else if(!state.gpoSession&&client.ephemeralCredential.available()){
      if(await restoreDelegatedAfterRestart())render();
    }else if(state.gpoSession?.connected){
      // Renew the delegated idle lease while the console is visible. This is a
      // local status request; it does not run PowerShell or change domain policy.
      try{state.gpoSession=await client.request('/api/gpo/session',{timeout:5000});}
      catch(e){if(e.code==='GPO_LOGIN_REQUIRED'){
        const restored=await restoreDelegatedAfterRestart();
        if(!restored){clearDelegatedState();state.notice='Domain session expired. Reconnect.';}
      }else throw e;}
    }
    if(location.hash==='#/operations'||state.inspectedOperation||service.activeJobs>0||state.history.some(window.GpoProduct.active)){const history=await client.request('/api/gpo/history',{timeout:5000});const historyChanged=JSON.stringify(state.history)!==JSON.stringify(history);if(historyChanged&&!state.busy&&!document.activeElement?.closest('form')&&!state.confirmAction&&!state.scopeModal&&!state.inspectedOperation&&!state.helpOpen){state.history=history;render();}}
    if(recovered||changed||previousMode!==session.mode||state.notice!==previousNotice){if(recovered&&!changed)state.notice='Backend service is available again.';render();}
  }catch{
    if(!state.serviceOffline){state.serviceOffline=true;state.notice=state.serviceTransition?'Windows / AD service is restarting…':'Backend service is temporarily unavailable. Connection checks will retry; your selections are preserved.';render();}
  }finally{state.healthProbeBusy=false;}
}
let targetAccessSequence=0,targetAccessTimer;
function paintTargetAccess(){const box=page?.querySelector('#target-access-feedback');if(box){box.innerHTML=accessFeedback();client.localize(box);}}
function queueTargetAccess(){
 clearTimeout(targetAccessTimer);const sequence=++targetAccessSequence;state.targetAccessError=null;state.targetAccessReady=null;state.targetAccessChecking=null;
 if(!state.selection.gpoId||!state.selection.scopeDn||!state.selectedRule?.backendSetting||targetIssue()){paintTargetAccess();return;}
 const key=targetKey(),selection=JSON.parse(JSON.stringify(state.selection));state.targetAccessChecking=key;paintTargetAccess();
 targetAccessTimer=setTimeout(async()=>{try{const result=await api('/gpo/target-access',selection);if(sequence===targetAccessSequence&&key===targetKey()&&result.authorized)state.targetAccessReady=key;}catch(error){if(sequence===targetAccessSequence&&key===targetKey()){state.targetAccessError={key,code:error.code,message:error.message};state.plan=null;if(state.approval)state.approval.reviewed=false;const stale=page?.querySelector('.plan-card');if(stale)stale.outerHTML=planBlock(state.selectedRule);}}finally{if(sequence===targetAccessSequence){state.targetAccessChecking=null;paintTargetAccess();}}},300);
}
function captureForm(){const f=page.querySelector('#gpo-selection');if(!f)return;const st=state.settings.find(x=>x.id===state.selectedRule?.backendSetting),user=String(st?.scope||'').toLowerCase()==='user';state.selection.scopeDn=f.elements.scopeDn?.value??state.selection.scopeDn;state.selection.refresh=f.elements.refresh?.value??state.selection.refresh;state.selection.accountScope=st?.domainPolicySensitive&&!/^OU=/i.test(state.selection.scopeDn)?'Domain':user?'Users':'LocalComputers';state.selection.endpointScopeDn=user?(f.elements.endpointScopeDn?.value||''):'';state.selection.verificationUser=user?(f.elements.verificationUser?.value.trim()||''):'';if(f.elements.value)state.selection.value=Number(f.elements.value.value);if(f.elements.customValue)state.selection.customValue=f.elements.customValue.value;if(f.elements.reviewContext)state.selection.reviewContext=f.elements.reviewContext.value;window.GpoValueEditor?.capture(f,st,state.selection);state.selection.firstLink=st?.domainPolicySensitive&&state.selection.accountScope==='Domain'?true:!!f.elements.firstLink?.checked;state.selection.setting=state.selectedRule?.backendSetting||'';}
function invalidateSelection(){
  captureForm();state.plan=null;resetApplyDraft();state.approval.reviewed=false;
  const stale=page.querySelector('.plan-card');if(stale)stale.outerHTML=planBlock(state.selectedRule);
  page.querySelectorAll('.refresh-choice').forEach(el=>el.classList.toggle('selected',!!el.querySelector('input:checked')));
}
function renderCatalogAt(selector,top){render();const target=page.querySelector(selector);if(target){window.scrollBy({top:target.getBoundingClientRect().top-top,behavior:'instant'});target.focus({preventScroll:true});}}
function selectRule(id){state.manualScriptAction='Preview';state.selectedRule=state.catalog.rules.find(r=>r.id===id);state.plan=null;state.tab='overview';state.selection.gpoId='';state.selection.scopeDn='';state.selection.endpointScopeDn='';state.selection.verificationUser='';state.selection.customValue='';state.selection.itemValues=null;state.selection.reviewContext=null;state.selection.value=state.settings.find(x=>x.id===state.selectedRule?.backendSetting)?.suggested??0;state.selection.refresh='None';state.selection.firstLink=false;state.approval={reference:'',approver:'',reviewed:false};state.gpoSearch='';state.gpoPickerOpen=false;ensureSelection();location.hash='#/control';render();}
function updateNav(){document.querySelectorAll('[data-gpo-nav]').forEach(a=>{const active=a.hash===location.hash||(location.hash==='#/control'&&a.hash==='#/benchmark');const newlySelected=active&&!a.classList.contains('selected');a.classList.toggle('selected',active);if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');if(newlySelected&&matchMedia('(max-width:700px)').matches)a.scrollIntoView({block:'nearest',inline:'nearest',behavior:'instant'});});}
function installNav(nav){nav.setAttribute('aria-label','Main navigation');nav.replaceChildren();const items=[['#/dashboard',uiIcon('grid'),tr('dashboard')],['#/benchmark',uiIcon('library'),tr('benchmark')],['#/operations',uiIcon('activity'),tr('operations')],['#/reports',uiIcon('library'),'Reports'],['#/diagnostics',uiIcon('activity'),'Diagnostics'],['#/assurance',uiIcon('shield'),'Access & evidence']];items.push(['#/audit',uiIcon('shield'),'Audit']);for(const [href,icon,label] of items){const a=document.createElement('a');a.href=href;a.className='nav-link';a.dataset.gpoNav='';a.setAttribute('aria-label',label);a.title=label;a.innerHTML=`<span class="nav-icon">${icon}</span><span class="nav-text"><span class="ds-nav-full">${label}</span><span class="ds-nav-mobile">${({"#/assurance":"Access","#/dashboard":"Overview","#/benchmark":"Controls","#/operations":"Jobs","#/audit":"Audit","#/reports":"Reports","#/diagnostics":"Health"})[href]}</span></span>`;nav.append(a);}const set=document.createElement('button');set.className='nav-link';set.dataset.settingsNav='';set.setAttribute('aria-label',tr('settings'));set.title=tr('settings');set.innerHTML=`<span class="nav-icon">${uiIcon("settings")}</span><span class="nav-text"><span class="ds-nav-full">${tr('settings')}</span><span class="ds-nav-mobile">${'Settings'}</span></span>`;set.onclick=()=>window.dispatchEvent(new CustomEvent('gr:open'));nav.append(set);}
async function completeDomainSignIn(){
  state.gpoSession=await api('/gpo/session');state.service=await api('/service');
  const resumed=restoreWriteResume({consume:true});
  if(resumed&&state.plan?.executionUser&&state.gpoSession?.executionUser&&String(state.plan.executionUser).toLowerCase()!==String(state.gpoSession.executionUser).toLowerCase()){
    state.plan=null;resetApplyDraft();state.notice='The delegated account changed. Your GPO/scope selection was restored, but regenerate the preview plan for safety.';
  }else if(resumed&&!state.service?.writesEnabled){
    state.writeGateBlocked=true;state.notice='The plan was restored, but the backend did not report the write gate as active after restart. Automatic retry is blocked to avoid a loop; your form data is preserved. Inspect Settings and Local Control Center.';
  }else if(resumed&&state.service?.writesEnabled){
    state.writeGateBlocked=false;state.plan=await api('/gpo/preview',state.selection);state.targetAccessError=null;state.approval={...state.approval,reviewed:false};resetApplyDraft();
    state.notice='The domain account was restored and the final preview was refreshed under the current production boundary. The stale pre-restart plan will not be used for Apply; review the final plan once and continue.';
  }else{
    state.writeGateBlocked=false;state.notice='Domain session created. This account will be reused throughout the active workflow. Running readiness checks now…';
  }
  await checkReadiness();if(!resumed&&state.readiness?.ready)state.notice='Domain connection and all required readiness checks passed. You can start remediation.';if(resumed){state.tab='remediation';location.hash='#/control';}

}
function mount(){const workspace=document.querySelector('.workspace'),nav=document.querySelector('.sidebar nav');if(!workspace||!nav)return;document.body.classList.add('operator-custom-page');installNav(nav);if(!document.getElementById('service-bar')){bar=document.createElement('div');bar.id='service-bar';workspace.prepend(bar);page=document.createElement('section');page.id='operator-modules';workspace.insertBefore(page,bar.nextSibling);
page.addEventListener('click',e=>{const pager=e.target.closest('[data-list-page]');if(pager&&location.hash!=='#/assurance'){const key=pager.dataset.listPage;if(['ops','audit','gpo','scope'].includes(key)){state[key+'Page']=Number(pager.dataset.page);render();return;}}if(e.target.closest('[data-reviewed-execution]')){const m=state.settings.find(x=>x.id===state.selectedRule?.backendSetting);state.selection.reviewContext='';state.selection.itemValues=window.GpoValueEditor.defaults(m);state.plan=null;state.tab='remediation';render();return;}if(e.target.closest('[data-recommended-values]')){const m=state.settings.find(x=>x.id===state.selectedRule?.backendSetting);state.selection.itemValues=state.selection.reviewContext!=null?window.GpoValueEditor.defaults(m):null;state.selection.value=m?.suggested??0;state.selection.customValue=m?.inputDefault??'';state.plan=null;resetApplyDraft();render();return;}const manualAction=e.target.closest('[data-manual-action]');if(manualAction){state.manualScriptAction=manualAction.dataset.manualAction==='Apply'?'Apply':'Preview';render();page.querySelector(`[data-manual-action="${state.manualScriptAction}"]`)?.focus({preventScroll:true});return;}const manualDownload=e.target.closest('[data-manual-download]');if(manualDownload){const script=manualDownload.closest('[data-manual-procedure]')?.querySelector('.manual-script-source code')?.textContent;if(script){const url=URL.createObjectURL(new Blob(['\uFEFF',script],{type:'text/plain;charset=utf-8'})),a=document.createElement('a');a.href=url;a.download='GPO-'+manualDownload.dataset.manualDownload;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}return;}if(assurance.handleClick(e))return;if(enterpriseCenter.handleClick(e))return;const copy=e.target.closest('[data-copy-value]');if(copy){navigator.clipboard.writeText(copy.dataset.copyValue).then(()=>{state.notice='Copied.';render();setTimeout(()=>{if(state.notice==='Copied.'){state.notice='';page.querySelector('.ds-toast')?.remove();}},2000);}).catch(()=>{state.notice='Clipboard unavailable. Select and copy the value.';render();});return;}if(e.target.closest('[data-dismiss-notice]')){state.notice='';render();return;}if(e.target.closest('[data-control-start]')){state.tab='remediation';render();return;}const breadcrumb=e.target.closest('[data-breadcrumb-domain],[data-dashboard-domain]');if(breadcrumb){const id=breadcrumb.dataset.breadcrumbDomain||breadcrumb.dataset.dashboardDomain;state.expandedTop=new Set([id]);state.query='';state.level='ALL';state.automation='ALL';state.savedView='ALL';location.hash='#/benchmark';render();page.querySelector(`[data-domain="${CSS.escape(id)}"]`)?.focus();return;}const opsLayout=e.target.closest('[data-ops-layout]');if(opsLayout){state.opsLayout=opsLayout.dataset.opsLayout;client.storage.set('gr-ops-layout',state.opsLayout);render();return;}if(e.target.closest('[data-cancel-request]')){client.cancelReadOnly();return;}const dom=e.target.closest('[data-domain]');if(dom){const id=dom.dataset.domain,top=dom.getBoundingClientRect().top;if(state.query.trim()){state.catalogSearchCollapsed.has(id)?state.catalogSearchCollapsed.delete(id):state.catalogSearchCollapsed.add(id);}else{const was=state.expandedTop.has(id);state.expandedTop.clear();if(!was)state.expandedTop.add(id);}renderCatalogAt(`[data-domain="${CSS.escape(id)}"]`,top);return;}const sub=e.target.closest('[data-subsection]');if(sub){const id=sub.dataset.subsection,top=sub.getBoundingClientRect().top;if(state.query.trim()){state.catalogSearchSubCollapsed.has(id)?state.catalogSearchSubCollapsed.delete(id):state.catalogSearchSubCollapsed.add(id);}else{state.expandedSub.has(id)?state.expandedSub.delete(id):state.expandedSub.add(id);}renderCatalogAt(`[data-subsection="${CSS.escape(id)}"]`,top);return;}const rule=e.target.closest('[data-rule]');if(rule){selectRule(rule.dataset.rule);return;}const view=e.target.closest('[data-view]');if(view){state.savedView=view.dataset.view;render();return;}const tab=e.target.closest('[data-tab]');if(tab){state.tab=tab.dataset.tab;render();return;}if(e.target.closest('[data-back]')){location.hash='#/benchmark';return;}if(e.target.closest('[data-settings]')){window.dispatchEvent(new CustomEvent('gr:open'));return;}const scopeOpen=e.target.closest('[data-scope-open]');if(scopeOpen){state.scopeModal=scopeOpen.dataset.scopeOpen;state.scopePage=0;state.scopeQuery='';state.gpoPickerOpen=false;state.scopeExpanded=new Set((state.inventory?.scopes||[]).filter(x=>x.kind==='Domain').map(x=>x.dn.toLowerCase()));const selected=state.selection[state.scopeModal];if(selected){let p=selected;while(p){state.scopeExpanded.add(p.toLowerCase());p=window.GpoScopePicker.parentDn(p);}}render();page.querySelector('#scope-search')?.focus();return;}if(e.target.closest('[data-scope-close]')){state.scopeModal=null;state.scopeQuery='';render();return;}const scopeBranch=e.target.closest('[data-scope-expand]');if(scopeBranch){state.scopePage=0;const dn=scopeBranch.dataset.scopeExpand.toLowerCase();state.scopeExpanded.has(dn)?state.scopeExpanded.delete(dn):state.scopeExpanded.add(dn);render();return;}const scopeChoice=e.target.closest('[data-scope-choose]');if(scopeChoice&&state.scopeModal){const field=state.scopeModal,st=state.settings.find(x=>x.id===state.selectedRule?.backendSetting),kind='All';const item=window.GpoScopePicker.approved(state.inventory?.scopes,kind).find(x=>x.dn.toLowerCase()===scopeChoice.dataset.scopeChoose.toLowerCase());if(!item){state.notice='OU was not found in the live domain inventory. Rediscover the directory.';state.scopeModal=null;render();return;}if(state.selection[field]!==item.dn){if(field==='scopeDn'&&state.selection.endpointScopeDn===state.selection.scopeDn)state.selection.endpointScopeDn=item.dn;state.selection[field]=item.dn;state.plan=null;resetApplyDraft();if(field==='scopeDn')state.selection.verificationUser='';}state.scopeModal=null;state.scopeQuery='';ensureSelection();render();queueTargetAccess();return;}if(e.target.closest('[data-scope-clear]')&&state.scopeModal==='endpointScopeDn'){state.selection.endpointScopeDn='';state.plan=null;resetApplyDraft();state.scopeModal=null;state.scopeQuery='';render();return;}if(state.busy)return;if(e.target.closest('[data-domain-sign-in]')){run(async()=>{await window.GpoOperatorSignIn.open();state.inventory=await api('/gpo/inventory');await completeDomainSignIn();});return;}if(e.target.closest('[data-load-audit]')){run(loadAudit);return;}if(e.target.closest('[data-export-audit]')){exportAudit();return;}if(e.target.closest('[data-refresh]')){run(refresh);return;}if(e.target.closest('[data-start-windows]')){run(startWindowsModeFromSetup);return;}if(e.target.closest('[data-gpo-close]')){state.gpoPickerOpen=false;state.gpoSearch='';render();return;}if(e.target.closest('[data-gpo-toggle]')){state.scopeModal=null;state.gpoPickerOpen=!state.gpoPickerOpen;render();return;}const gp=e.target.closest('[data-gpo]');if(gp){state.selection.gpoId=gp.dataset.gpo;state.gpoPickerOpen=false;state.gpoSearch='';state.plan=null;resetApplyDraft();render();queueTargetAccess();return;}if(e.target.closest('[data-readiness]')){run(checkReadiness);return;}if(e.target.closest('[data-discover]'))run(async()=>{state.inventory=await api('/gpo/discover',{});state.notice='GPO inventory refreshed.';await checkReadiness();});if(e.target.closest('[data-disconnect]'))run(async()=>{await api('/gpo/disconnect',{});client.ephemeralCredential.clear();state.inventory=null;state.gpoSession=null;state.readiness=null;state.readinessError='';state.plan=null;resetApplyDraft();state.writeGateBlocked=false;clearWriteResume();});if(e.target.closest('[data-enable-write]')){run(enableWritesAndContinue);return;}const of=e.target.closest('[data-ops-filter]');if(of){state.opsFilter=of.dataset.opsFilter;state.opsPage=0;render();return;}const rollbackInspect=e.target.closest('[data-rollback-inspect]');if(rollbackInspect){const id=rollbackInspect.dataset.rollbackInspect,h=state.history.find(x=>x.id===id),session=state.gpoSession,processId=state.service?.processId;if(h)run(async()=>{const result=await api('/gpo/'+encodeURIComponent(id)+'/rollback-preview');state.rollbackChecks??=Object.create(null);state.rollbackChecks[id]={result,updatedAt:h.updatedAt,state:h.result?.state,session,processId,at:Date.now()};});return;}const v=e.target.closest('[data-verify]');if(v)run(async()=>{await operationMonitor.submitSingle('verify',v.dataset.verify,{confirmation:''});});const gu=e.target.closest('[data-gpupdate]');if(gu){state.inspectedOperation=null;state.confirmAction={kind:'gpupdate',id:gu.dataset.gpupdate};render();return;}const rp=e.target.closest('[data-replan]');if(rp)run(async()=>{const p=await api('/gpo/'+rp.dataset.replan+'/replan',{});state.plan=p;const rule=state.catalog.rules.find(x=>(x.backendSetting||x.id)===p.selection.setting);if(rule)state.selectedRule=rule;state.selection={...state.selection,...p.selection};state.approval={reference:'',approver:'',reviewed:false};resetApplyDraft();state.tab='remediation';state.notice='A fresh remediation plan was created from the live state. Review it before Apply.';location.hash='#/control';render();page.querySelector('.plan-card')?.scrollIntoView({block:'start',behavior:'smooth'});});const oe=e.target.closest('[data-op-evidence]');if(oe)run(async()=>{const payload=await api('/gpo/'+oe.dataset.opEvidence+'/evidence');const blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`gpo-evidence-${oe.dataset.opEvidence}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);});const op=e.target.closest('[data-op]');if(op){location.hash='#/operations';return;}if(e.target.closest('[data-evidence]')){run(async()=>{await downloadEvidence();state.notice='Report downloaded.';});return;}if(e.target.closest('[data-close-overlay]')){state.notificationOpen=false;render();return;}if(e.target.closest('[data-confirm-cancel]')){state.confirmAction=null;render();return;}if(e.target.closest('[data-confirm-run]')&&state.confirmAction){const a={...state.confirmAction,refresh:page.querySelector('#refresh-target')?.value??state.confirmAction.refresh};state.confirmAction=null;if(a.kind==='apply'){if(state.plan?.id!==a.id){state.notice='Plan changed. Review the new plan.';render();return;}run(async()=>{await operationMonitor.submitSingle('apply',a.id,a.payload,state.plan?.selection?.refresh||'None');state.plan=null;resetApplyDraft();state.tab='verification';});return;}if(a.kind==='gpupdate')run(async()=>{await operationMonitor.submitSingle('refresh',a.id,{confirmation:''},a.refresh);state.tab='verification';});if(a.kind==='rollback')run(()=>rollbackAndRefresh(a));return;}});
page.addEventListener('input',e=>{if(assurance.handleInput(e))return;if(e.target.id==='audit-search'){state.auditQuery=e.target.value;state.auditPage=0;render();return;}if(e.target.id==='catalog-search'){state.query=e.target.value;state.catalogSearchCollapsed.clear();state.catalogSearchSubCollapsed.clear();queueCatalogRender();return;}if(e.target.id==='gpo-search'){state.gpoSearch=e.target.value;state.gpoPage=0;render();return;}if(e.target.id==='scope-search'){state.scopeQuery=e.target.value;state.scopePage=0;render();return;}if(e.target.id==='ops-search'){state.opsQuery=e.target.value;state.opsPage=0;render();return;}if(e.target.id==='approval-ref')state.approval.reference=e.target.value;if(e.target.id==='approval-by')state.approval.approver=e.target.value;if(e.target.id==='approval-ok'){state.approval.reviewed=e.target.checked;render();}if(e.target.closest('#gpo-apply')){if(e.target.name==='confirmation')state.applyDraft.confirmation=e.target.value;if(e.target.name==='impact')state.applyDraft.impact=e.target.checked;if(e.target.name==='protected')state.applyDraft.protected=e.target.checked;}if(e.target.name==='reviewContext'){const count=page.querySelector('#review-context-count'),length=e.target.value.trim().length;if(count)count.textContent=e.target.value.length+' / 2048 characters · saved with the plan';e.target.setCustomValidity(!length?'Enter the environment review.':'');}if(e.target.closest('#gpo-selection'))invalidateSelection();});
page.addEventListener('change',e=>{if(assurance.handleInput(e))return;if(enterpriseCenter.handleChange(e))return;if(e.target.id==='catalog-level'){state.level=e.target.value;render();}if(e.target.id==='catalog-automation'){state.automation=e.target.value;render();}if(e.target.closest('#gpo-selection')){invalidateSelection();if(e.target.name==='firstLink')queueTargetAccess();}});
page.addEventListener('submit',e=>{if(assurance.handleSubmit(e))return;e.preventDefault();const f=e.target;if(f.id==='gpo-selection'){captureForm();const review=f.elements.reviewContext;if(review){review.setCustomValidity(!review.value.trim()?'Enter the environment review.':'');if(!review.reportValidity())return;}clearTimeout(targetAccessTimer);++targetAccessSequence;state.targetAccessChecking=null;if(!state.selection.scopeDn){state.notice='Choose the GPO target OU from the directory before preview.';render();return;}if(!state.selectedRule?.backendSetting){state.notice='No automated mapping exists for this control.';render();return;}run(async()=>{state.plan=await api('/gpo/preview',state.selection);state.targetAccessError=null;state.writeGateBlocked=false;resetApplyDraft();state.notice=state.service?.writesEnabled&&state.plan.writeAuthorized?'Plan ready. Target write access was checked for this connection. Review and approve before Apply. No policy has been changed.':'Plan ready. No policy has been changed. Enable the change gate, then review and approve before Apply.';});}if(f.id==='gpo-apply'&&state.plan){state.confirmAction={kind:'apply',id:state.plan.id,payload:{confirmation:f.elements.confirmation.value,acknowledgeImpact:f.elements.impact.checked,acknowledgeProtected:!!f.elements.protected?.checked,changeReference:state.approval.reference.trim(),approvedBy:state.approval.approver.trim()}};render();}if(f.dataset.rollback){const id=f.dataset.rollback,confirmation=f.elements.confirmation.value,h=state.history.find(x=>x.id===id);if(!h||window.GpoComponents.rollbackCheck(state,h)?.canRestore!==true){state.notice='Check rollback availability again before confirming restore.';render();return;}if(confirmation!=='ROLLBACK'){state.notice='Type ROLLBACK to continue.';render();return;}state.inspectedOperation=null;state.confirmAction={kind:'rollback',id,confirmation,refresh:f.elements.refresh?.value||'None'};render();}});
bar.addEventListener('click',e=>{if(e.target.closest('[data-notifications]')){state.notificationOpen=true;render();return;}if(e.target.closest('[data-settings]'))window.dispatchEvent(new CustomEvent('gr:open'));if(e.target.closest('[data-refresh]'))run(refresh);if(e.target.closest('[data-theme]')){state.theme=state.theme==='dark'?'light':'dark';client.storage.set('gr-theme',state.theme);render();}if(e.target.closest('[data-lang]')){state.lang='en';window.GpoI18n.setLanguage(state.lang);client.storage.set('gr-lang',state.lang);nav.querySelectorAll('[data-gpo-nav],[data-settings-nav]').forEach(x=>x.remove());installNav(nav);render();}});}
updateNav();}
async function init(){await window.GpoOperatorSignIn.ensure();mount();installProductInteractions();window.GpoRouter.ensure();window.addEventListener('gr:refresh',()=>run(refresh));window.addEventListener('gr:service-restarting',()=>{state.serviceTransition=true;state.serviceOffline=false;clearDelegatedState();state.notice='Windows / AD service is restarting in a controlled transition…';render();});window.addEventListener('gr:service-ready',()=>{state.serviceTransition=false;state.serviceOffline=false;});window.addEventListener('gr:connection-expired',()=>{clearDelegatedState();state.notice='The session expired. Opening the single sign-in screen.';render();run(async()=>{await window.GpoOperatorSignIn.open();state.inventory=await api('/gpo/inventory');await completeDomainSignIn();});});window.addEventListener('hashchange',()=>{if(window.GpoRouter.ensure()!==location.hash)return;mount();render();window.scrollTo({top:0,left:0,behavior:'instant'});page.querySelector('main')?.focus({preventScroll:true});if(location.hash==='#/audit'&&!state.audit)run(loadAudit);});window.addEventListener('keydown',e=>{if(e.target.id==='scope-search'&&e.key==='Enter'){e.preventDefault();return;}if(page.querySelector('.product-drawer,.confirm-dialog'))return;if(e.key==='Escape'&&(state.notificationOpen||state.gpoPickerOpen||state.scopeModal||state.confirmAction)){state.scopeModal=null;state.scopeQuery='';state.notificationOpen=false;state.gpoPickerOpen=false;state.confirmAction=null;render();return;}if(e.altKey&&['1','2','3'].includes(e.key)&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)){e.preventDefault();window.GpoRouter.navigate(['#/dashboard','#/benchmark','#/operations'][Number(e.key)-1]);return;}if(e.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)){e.preventDefault();window.GpoRouter.navigate('#/benchmark');setTimeout(()=>document.getElementById('catalog-search')?.focus(),60);}});await run(refresh);const pendingResume=readWriteResume();if(pendingResume&&state.gpoSession?.connected)await run(completeDomainSignIn);if(pendingResume&&state.session?.mode==='WINDOWS'&&!state.gpoSession){state.notice='The service restart is complete and your plan selection is preserved. Reconnect through the single sign-in screen; the final preview will be refreshed.';location.hash='#/dashboard';render();}setInterval(healthTick,15000);setInterval(()=>operationMonitor.poll(),3000);operationMonitor.poll();if(location.hash==='#/audit')await run(loadAudit);}

let productDialogOpen=false,productReturnFocus=null;
function syncProductModal(){
  const modal=page.querySelector('.product-drawer,.confirm-dialog');
  document.body.classList.toggle('product-modal-open',!!modal);
  page.querySelector('.product-main')?.toggleAttribute('inert',!!modal);
  bar?.toggleAttribute('inert',!!modal);
  document.querySelector('.sidebar')?.toggleAttribute('inert',!!modal);
  if(modal&&(!productDialogOpen||!modal.contains(document.activeElement)))modal.querySelector('[data-product-close],[data-confirm-cancel]')?.focus();
  productDialogOpen=!!modal;
}
function closeProductPanel(){state.inspectedOperation=null;state.helpOpen=false;render();if(productReturnFocus){document.querySelector(productReturnFocus)?.focus();productReturnFocus=null;}}
function downloadProductFile(content,name,type){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function installProductInteractions(){
  document.addEventListener('click',e=>{
    const close=e.target.closest('[data-product-close]');if(close){closeProductPanel();return;}
    const inspect=e.target.closest('[data-inspect]');if(inspect){state.helpOpen=false;state.inspectedOperation=inspect.dataset.inspect;productReturnFocus='[data-inspect="'+CSS.escape(inspect.dataset.inspect)+'"]';render();return;}
    const action=e.target.closest('[data-product-action]')?.dataset.productAction;if(!action)return;
    if(action==='help'){state.inspectedOperation=null;state.helpOpen=true;productReturnFocus='[data-product-action="help"]';render();}
    if(action==='settings')window.dispatchEvent(new CustomEvent('gr:open'));
    if(action==='benchmark')location.hash='#/benchmark';
    if(action==='connect'||action==='sign-in'){location.hash='#/dashboard';page.querySelector('[data-domain-sign-in]')?.click();}
    if(action==='readiness'){if(state.inventory)run(checkReadiness);else{state.notice='Connect your domain account first.';render();}}
    if(action==='clear-filters'){state.query='';state.level='ALL';state.automation='ALL';state.savedView='ALL';render();}
    if(action==='export-catalog')downloadProductFile(window.GpoProduct.csv(state.catalog.rules.filter(matchesRule)),'cis-controls.csv','text/csv;charset=utf-8');
    if(action==='copy-operation'){const h=state.history.find(x=>x.id===state.inspectedOperation);if(h)navigator.clipboard.writeText([h.id,h.result?.state,h.plan?.preview?.gpo?.name,h.plan?.selection?.scopeDn,h.result?.message].filter(Boolean).join('\n')).then(()=>{state.notice='Operation summary copied.';closeProductPanel();}).catch(()=>{state.notice='Clipboard unavailable. Download the evidence file.';closeProductPanel();});}
  });
  document.addEventListener('click',e=>{if(!e.target.closest('.ux-more-tabs'))page.querySelectorAll('.ux-more-tabs[open]').forEach(x=>x.removeAttribute('open'));});
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){const more=page.querySelector('.ux-more-tabs[open]');if(more){e.preventDefault();more.removeAttribute('open');more.querySelector('summary')?.focus();}}});
  document.addEventListener('keydown',e=>{if(!e.target.matches('[data-domain]')||!['ArrowDown','ArrowUp','Home','End'].includes(e.key))return;const headers=[...page.querySelectorAll('[data-domain]')],index=headers.indexOf(e.target);e.preventDefault();const next=e.key==='Home'?0:e.key==='End'?headers.length-1:Math.max(0,Math.min(headers.length-1,index+(e.key==='ArrowDown'?1:-1)));headers[next]?.focus();});
  document.addEventListener('change',e=>{if(e.target.id==='ops-sort'){state.opsSort=e.target.value;state.opsPage=0;render();}});
  document.addEventListener('keydown',e=>{
    const modal=page.querySelector('.product-drawer,.confirm-dialog');if(!modal)return;
    if(e.key==='Escape'){e.preventDefault();if(state.confirmAction){state.confirmAction=null;render();}else closeProductPanel();return;}
    if(e.key==='Tab'){const controls=[...modal.querySelectorAll('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),[tabindex="0"]')];const first=controls[0],last=controls.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last?.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first?.focus();}}
  });
  window.addEventListener('gr:open',()=>{if(state.helpOpen||state.inspectedOperation){state.helpOpen=false;state.inspectedOperation=null;render();}});
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
