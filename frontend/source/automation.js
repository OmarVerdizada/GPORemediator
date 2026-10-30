(() => {
  'use strict';
  const state={session:null,config:null,readiness:null,discovery:null,service:null,gpoSession:null,serviceOffline:false,busy:false,notice:'',connectionExpired:false,tab:'setup',loaded:false};
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let panel,backdrop,returnFocus,draft=null;
  async function api(path,body){
    if(!state.session)state.session=await window.GpoClient.request('/api/session');
    try{return await window.GpoClient.request('/api'+path,{body,csrfToken:state.session.csrfToken});}
    catch(e){if(e.code==='CSRF_INVALID')state.session=null;if(e.code==='GPO_LOGIN_REQUIRED'){state.connectionExpired=true;state.gpoSession=null;}if(e.code==='SERVICE_UNREACHABLE')state.serviceOffline=true;throw e;}
  }
  function capture(){if(state.busy)return;const form=panel.querySelector('form');if(form)draft=Object.fromEntries(new FormData(form));}
  function render(){
    const openDetails=new Set([...panel.querySelectorAll('details[open]')].map(el=>el.className));
    const c=draft||state.config||{}, warnings=state.discovery?.warnings||[];
    const connectionState=state.serviceOffline?'Service offline':state.session?.mode==='SETUP'?'Configuration mode':state.gpoSession?.connected?'AD connected':'Windows / AD active';
    const field=(name,label,placeholder='')=>`<label class="gr-auto-field">${label}<input name="${name}" required value="${esc(c[name]||'')}" placeholder="${esc(placeholder)}"></label>`;
    const area=(name,label,placeholder='')=>`<label class="gr-auto-field gr-auto-span2">${label}<textarea name="${name}" placeholder="${esc(placeholder)}">${esc(Array.isArray(c[name])?c[name].join('\n'):(c[name]||''))}</textarea></label>`;
    const windowsReady=state.session?.mode==='WINDOWS'&&!state.serviceOffline, delegated=!!state.gpoSession?.connected&&!state.connectionExpired, writes=!!state.service?.writesEnabled&&windowsReady;const wildcardScope=(state.config?.approvedGpoIds||[]).includes('*')||(state.config?.authorizedOus||[]).includes('*');
    panel.innerHTML=`<div class="gr-auto-head"><div><span class="gr-auto-eyebrow">CONTROL PLANE</span><h2>Settings</h2><p>AD environment and production change gate</p></div><button data-close class="gr-auto-close" aria-label="Close">×</button></div><div class="gr-auto-body" aria-busy="${state.busy}">
      <div class="gr-auto-rail"><div class="${windowsReady&&delegated?'done':'current'}"><span>1</span><b>Single sign-in / AD</b><small>${delegated?'Session active':windowsReady?'Sign-in required':'Configuration / offline'}</small></div><i></i><div class="${writes?'done':delegated?'current':''}"><span>2</span><b>Change gate</b><small>${writes?'Enabled':'Read-only'}</small></div></div>
      ${state.busy?'<p role="status" class="gr-auto-progress">Processing request…</p>':''}${state.notice?`<div class="gr-auto-note" role="status">${esc(state.notice)}</div>`:''}
      ${warnings.length?`<div class="gr-auto-note warn">${warnings.map(esc).join('<br>')}</div>`:''}${state.session?.mode==='SETUP'?'<div class="gr-auto-note warn"><strong>Note:</strong> AD preflight checks DNS, Kerberos and WinRM connectivity. Save this form and start Windows / AD mode to connect to the domain.</div>':''}
      ${state.session?.mode==='WINDOWS'?'<details class="gr-auto-card gr-auto-connection"><summary>AD environment settings</summary>':''}<form id="windows-setup" class="gr-auto-card"><div class="gr-auto-title-row"><div><h3>AD environment settings</h3><p>Configure the domain and writable DC here. Enter credentials on the single sign-in screen; these settings use that same domain session.</p></div><span class="gr-auto-state ${state.serviceOffline?'offline':''}">${connectionState}</span></div><div class="gr-auto-grid">
      ${field('domain','AD DNS domain','example.local')}${field('domainController','Writable DC FQDN','dc01.example.local')}</div><p class="gr-auto-help">A writable DC is required. Use Auto-detect if you do not know its name, then review the result. GPO operations run on this server. Configure endpoint targets separately.</p>
      <div class="gr-auto-note"><strong>Windows / AD requirements:</strong> the management host must use AD DNS; the DC FQDN must resolve; TCP/5985 must be reachable; Kerberos requires synchronized time and an available KDC; the DC must have the ActiveDirectory and GroupPolicy/GPMC modules.</div>
      <details class="gr-auto-advanced"><summary>GPO, OU and endpoint scope</summary><div class="gr-auto-grid gr-auto-advanced-grid">${area('approvedGpoIds','Authorized GPO GUIDs','*')}${area('authorizedOus','Authorized OU / domain DNs','DC=example,DC=local')}<label class="gr-auto-field gr-auto-span2">Endpoint targets<select name="endpointTargeting"><option value="SelectedOu" ${c.endpointTargeting==='SelectedOu'||(!c.endpointTargeting&&!(c.allowedHosts||[]).length)?'selected':''}>Selected OU automatically</option><option value="ExplicitHosts" ${c.endpointTargeting==='ExplicitHosts'||(!c.endpointTargeting&&(c.allowedHosts||[]).length)?'selected':''}>Explicit host list</option></select><small>Automatic mode discovers enabled computers in the selected OU and child OUs. A separately approved gpupdate targets these computers; verification checks every pinned endpoint in pages. An OU may contain users and computers. User session endpoints can be overridden when needed.</small></label>${area('allowedHosts','Explicit hosts — explicit mode only','server01.example.local')}</div><p class="gr-auto-help">In the GPO/OU fields, <b>*</b> allows read-only discovery. To authorize writes, create a remediation preview and choose <b>Approve this GPO + scope and continue</b> to restrict write authorization to the reviewed plan.</p></details>
      <div class="gr-auto-actions"><button class="gr-auto-btn primary">${state.session?.mode==='WINDOWS'?'Save and update service mode':'Save and start Windows / AD'}</button><button type="button" class="gr-auto-btn" data-detect>Auto-detect</button>${state.session?.mode==='WINDOWS'&&state.service?.writesEnabled?'<span class="gr-auto-inline-warning">Configuration changes reset the change gate to read-only and require a managed restart.</span>':''}</div></form>${state.session?.mode==='WINDOWS'?'</details>':''}
      ${state.session?.mode==='WINDOWS'?`<div class="gr-auto-card gr-auto-permission"><div class="gr-auto-title-row"><div><h3>Production change gate</h3><p>Preview and Verify are always read-only. Apply and Rollback require this gate to be enabled.</p></div><span class="gr-auto-state ${writes?'on':''}">${writes?'Enabled':'Disabled'}</span></div>${state.serviceOffline?'<div class="gr-auto-note warn">The backend is not responding. Check service status in the Local Control Center.</div>':(!state.gpoSession?.connected||state.connectionExpired)?'<div class="gr-auto-note warn">The execution session is inactive. Open the sign-in screen to continue.</div><button class="gr-auto-btn primary" data-reconnect>Open sign-in</button>':'<button class="gr-auto-btn" data-readiness>Check readiness</button>'}
      <details class="gr-auto-card"><summary>Grant persistent backup access</summary><p>A local administrator on the selected DC can grant the execution user or a delegated group inheritable Modify access once. Existing grants are preserved across restarts. This does not grant domain or GPO rights.</p><label class="gr-auto-field">Domain user or group<input id="backup-grant-identity" placeholder="DOMAIN\\\\DelegatedGroup"></label><button class="gr-auto-btn" type="button" data-backup-grant>Grant backup Modify</button></details>${(!state.gpoSession?.connected||state.connectionExpired||state.serviceOffline)?'':(state.readiness?.checks||[]).map(c=>`<div class="gr-auto-row"><div><strong>${esc(c.label)} · ${esc(c.state||c.status)}</strong><small>${esc(c.message)}</small></div></div>`).join('')}
      ${(!state.gpoSession?.connected||state.connectionExpired||state.serviceOffline)?'':`${wildcardScope&&!writes?'<div class="gr-auto-note info"><strong>Plan-bound authorization:</strong> Discovery is currently unrestricted. Select a GPO and scope in Remediation and create a preview to authorize that specific selection. No manual GUID or OU entry is required.</div><button class="gr-auto-btn primary" data-plan-scope>Open remediation plan</button>':`<button class="gr-auto-btn ${writes?'':'primary'}" data-write>${writes?'Disable writes':'Enable writes'}</button>`}`}</div>`:''}</div>`;
    panel.querySelectorAll('details').forEach(el=>{if(openDetails.has(el.className))el.open=true;});
    window.GpoClient.localize(panel);
    const targeting=panel.querySelector('[name=endpointTargeting]'),manual=panel.querySelector('[name=allowedHosts]');
    if(targeting&&manual)manual.disabled=targeting.value!=='ExplicitHosts';
    if(state.busy)panel.querySelectorAll('button:not([data-close]),input,textarea').forEach(x=>x.disabled=true);
  }
  async function load(){
    if(state.loaded||state.busy)return;state.busy=true;render();
    try{
      [state.config,state.service]=await Promise.all([api('/setup/config'),api('/service')]);state.serviceOffline=false;
      if(state.session?.mode==='WINDOWS'){try{state.gpoSession=await window.GpoClient.request('/api/gpo/session',{timeout:5000});state.connectionExpired=false;}catch(e){if(e.code==='GPO_LOGIN_REQUIRED'||e.status===401){state.gpoSession=null;state.connectionExpired=false;}else if(e.code==='SERVICE_UNREACHABLE'){state.serviceOffline=true;state.gpoSession=null;}else throw e;}}else state.gpoSession=null;
      try{state.discovery=await api('/setup/discover');}catch(e){state.notice=e.message;}
      if(!state.config.exists&&state.discovery){const d=state.discovery,domainDn=String(d.domain||'').split('.').filter(Boolean).map(part=>`DC=${part}`).join(',');state.config={...state.config,domain:d.domain,domainController:d.domainController,backupPath:d.backupPath,approvedGpoIds:['*'],authorizedOus:domainDn?[domainDn]:[],allowedHosts:[]};}
      state.loaded=true;
    }catch(e){state.notice=e.message;}finally{state.busy=false;render();}
  }
  function setRootBlocked(blocked){const root=document.getElementById('root');if(!root)return;root.inert=!!blocked;if(blocked)root.setAttribute('aria-hidden','true');else{root.removeAttribute('inert');root.removeAttribute('aria-hidden');}}
  function open(){if(panel.classList.contains('open'))return;returnFocus=document.activeElement;state.loaded=false;state.config=null;state.service=null;state.gpoSession=null;state.readiness=null;state.notice='';draft=null;setRootBlocked(true);document.body.style.overflow='hidden';panel.classList.add('open');backdrop.classList.add('open');render();load();panel.querySelector('[data-close]')?.focus();}
  function close(){capture();setRootBlocked(false);document.body.style.overflow='';panel.classList.remove('open');backdrop.classList.remove('open');returnFocus?.focus();window.dispatchEvent(new CustomEvent('gr:refresh'));}
  async function action(fn){if(state.busy)return;capture();state.busy=true;state.notice='';render();try{await fn();}catch(e){state.notice=e.message;}finally{state.busy=false;render();}}
  async function restart(result){
    if(!result.restartScheduled){state.loaded=false;state.session=null;state.gpoSession=null;draft=null;state.notice='Saved. Restart the application to activate the changes.';return;}
    state.notice='Saved. Restarting the Windows / AD service…';state.serviceOffline=false;window.dispatchEvent(new CustomEvent('gr:service-restarting'));render();
    const previous=state.service?.processId,deadline=Date.now()+75000;
    while(Date.now()<deadline){await new Promise(resolve=>setTimeout(resolve,1200));try{
      const service=await window.GpoClient.request('/api/service',{timeout:3000});
      if(service.processId!==previous){
        state.service=service;state.serviceOffline=false;state.session=await window.GpoClient.request('/api/session',{timeout:5000});
        if(service.mode==='WINDOWS'){
          state.gpoSession=null;state.notice='Service restart completed. Sign in again to reconnect the delegated account.';
          window.dispatchEvent(new CustomEvent('gr:service-ready',{detail:{service}}));state.loaded=false;draft=null;await load();return;
        }
        if(service.mode==='SETUP'){window.dispatchEvent(new CustomEvent('gr:service-ready',{detail:{service}}));state.loaded=false;draft=null;await load();return;}
      }
    }catch{state.serviceOffline=true;}}
    throw Error('Restart did not complete within 75 seconds. Check service status, windows-startup-error.log and bootstrap.log in the Local Control Center.');
  }
  function init(){
    backdrop=document.createElement('div');backdrop.id='gr-auto-backdrop';backdrop.onclick=close;document.body.append(backdrop);
    panel=document.createElement('aside');panel.id='gr-auto-panel';panel.setAttribute('role','dialog');panel.setAttribute('aria-modal','true');panel.setAttribute('aria-label','GPO settings');document.body.append(panel);
    panel.addEventListener('input',capture);
    panel.addEventListener('change',e=>{if(e.target.name==='endpointTargeting'){capture();const manual=panel.querySelector('[name=allowedHosts]');if(manual)manual.disabled=e.target.value!=='ExplicitHosts';}});
    panel.addEventListener('submit',e=>{e.preventDefault();capture();const c={...draft};action(async()=>{
      const lines=value=>(Array.isArray(value)?value:String(value||'').split(/[\n;]/)).map(v=>String(v).trim()).filter(Boolean);
      const domainDn=String(c.domain||'').split('.').filter(Boolean).map(part=>`DC=${part}`).join(',');
      const endpointTargeting=c.endpointTargeting||'SelectedOu';
      const payload={...c,endpointTargeting,backupPath:c.backupPath||state.discovery?.backupPath||'C:\\ProgramData\\GpoRemediator\\Backups',urls:location.origin,approvedGpoIds:lines(c.approvedGpoIds).length?lines(c.approvedGpoIds):['*'],authorizedOus:lines(c.authorizedOus).length?lines(c.authorizedOus):[domainDn],allowedHosts:endpointTargeting==='ExplicitHosts'?lines(c.allowedHosts):[],autoRestart:!!state.service?.managed};
      const result=await api('/setup/config',payload);state.config={...state.config,...payload};state.notice='Saved. The launcher is switching to Windows / AD mode; writes remain disabled.';
      await restart(result);
    });});
    panel.addEventListener('click',e=>{
      if(e.target.closest('[data-close]'))return close();
      if(e.target.closest('[data-reconnect]')){close();location.hash='#/dashboard';window.dispatchEvent(new CustomEvent('gr:connection-expired'));return;}
      if(e.target.closest('[data-backup-grant]')){const identity=panel.querySelector('#backup-grant-identity')?.value?.trim();if(identity)action(async()=>{await api('/gpo/backup-access',{identity,confirmation:'GRANT BACKUP MODIFY'});state.notice='Persistent backup Modify access granted. Check readiness again.';});return;}
      if(e.target.closest('[data-detect]'))action(async()=>{state.discovery=await api('/setup/discover');const d=state.discovery;draft={...draft,domain:d.domain||draft?.domain,domainController:d.domainController||draft?.domainController,backupPath:d.backupPath||draft?.backupPath};state.notice='Discovered settings have been copied to the form.';});
      if(e.target.closest('[data-readiness]'))action(async()=>{state.connectionExpired=false;state.readiness=await api('/gpo/readiness');});
      if(e.target.closest('[data-plan-scope]')){close();location.hash='#/benchmark';return;}if(e.target.closest('[data-write]')){const enable=!state.service?.writesEnabled;const confirmation=enable?'ENABLE WRITES':'DISABLE WRITES';action(async()=>{const result=await api('/setup/write-mode',{enable,confirmation,autoRestart:true});if(state.config)state.config.enableWrites=!!result.enableWrites;await restart(result);});}
    });
    document.addEventListener('keydown',e=>{
      if(!panel.classList.contains('open'))return;
      if(e.key==='Escape')close();
      if(e.key==='Tab'){const items=[...panel.querySelectorAll('button:not(:disabled),input:not(:disabled),textarea:not(:disabled),summary')];const first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last?.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first?.focus();}}
    });
    window.addEventListener('gr:open',open);
    window.addEventListener('gr:service-restarting',()=>{state.serviceOffline=true;state.gpoSession=null;state.readiness=null;if(panel.classList.contains('open'))render();});
    window.addEventListener('gr:service-ready',()=>{state.serviceOffline=false;state.loaded=false;state.session=null;state.gpoSession=null;if(panel.classList.contains('open'))load();});
    window.addEventListener('hashchange',()=>{if(location.hash==='#/settings')open();else if(panel.classList.contains('open'))close();else setRootBlocked(false);});
    api('/session').then(()=>{if(location.hash==='#/settings'||state.session?.mode==='SETUP')open();else setRootBlocked(false);}).catch(()=>{setRootBlocked(false);});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
