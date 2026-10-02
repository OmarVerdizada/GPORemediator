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
  function normalizeRbac(operators,remediators,auditors,viewers){
    const uniq=a=>[...new Map((a||[]).map(x=>[String(x).toLowerCase(),String(x)])).values()];
    const admins=uniq(operators), used=new Set(admins.map(x=>x.toLowerCase()));
    const take=a=>uniq(a).filter(x=>{const k=x.toLowerCase();if(used.has(k))return false;used.add(k);return true;});
    return {operators:admins,remediators:take(remediators),auditors:take(auditors),viewers:take(viewers)};
  }
  function render(){
    const c=draft||state.config||{}, warnings=state.discovery?.warnings||[];
    const connectionState=state.serviceOffline?'Xidmət offline':state.session?.mode==='SETUP'?'Konfiqurasiya rejimi':state.gpoSession?.connected?'AD qoşulub':'Windows / AD aktiv';
    const field=(name,label,placeholder='')=>`<label class="gr-auto-field">${label}<input name="${name}" required value="${esc(c[name]||'')}" placeholder="${esc(placeholder)}"></label>`;
    const area=(name,label,placeholder='')=>`<label class="gr-auto-field gr-auto-span2">${label}<textarea name="${name}" placeholder="${esc(placeholder)}">${esc(Array.isArray(c[name])?c[name].join('\n'):(c[name]||''))}</textarea></label>`;
    const windowsReady=state.session?.mode==='WINDOWS'&&!state.serviceOffline, delegated=!!state.gpoSession?.connected&&!state.connectionExpired, writes=!!state.service?.writesEnabled&&windowsReady;const wildcardScope=(state.config?.approvedGpoIds||[]).includes('*')||(state.config?.authorizedOus||[]).includes('*');
    panel.innerHTML=`<div class="gr-auto-head"><div><span class="gr-auto-eyebrow">CONTROL PLANE</span><h2>Sazlamalar</h2><p>Domen bağlantısı, delegated session və production change gate</p></div><button data-close class="gr-auto-close" aria-label="Bağla">×</button></div><div class="gr-auto-body" aria-busy="${state.busy}">
      <div class="gr-auto-rail"><div class="${windowsReady?'done':'current'}"><span>1</span><b>Windows / AD</b><small>${windowsReady?'Aktiv':'Konfiqurasiya / offline'}</small></div><i></i><div class="${delegated?'done':windowsReady?'current':''}"><span>2</span><b>Delegated session</b><small>${delegated?'Qoşulub':'Login tələb olunur'}</small></div><i></i><div class="${writes?'done':delegated?'current':''}"><span>3</span><b>Change gate</b><small>${writes?'Aktiv':'Read-only'}</small></div></div>
      ${state.busy?'<p role="status" class="gr-auto-progress">Sorğu icra olunur…</p>':''}${state.notice?`<div class="gr-auto-note" role="status">${esc(state.notice)}</div>`:''}
      ${warnings.length?`<div class="gr-auto-note warn">${warnings.map(esc).join('<br>')}</div>`:''}${state.session?.mode==='SETUP'?'<div class="gr-auto-note warn"><strong>Qeyd:</strong> AD preflight yalnız DNS/Kerberos/WinRM yolunu yoxlayır. Domenə real qoşulma üçün bu formu saxlayıb Windows / AD rejiminə keçmək lazımdır.</div>':''}
      ${state.session?.mode==='WINDOWS'?'<details class="gr-auto-card gr-auto-connection"><summary>Domen bağlantısı</summary>':''}<form id="windows-setup" class="gr-auto-card"><div class="gr-auto-title-row"><div><h3>Domen bağlantısı</h3><p>Cari Windows hesabı Web UI operatorudur. GPO icrası üçün restart-dan sonra ayrıca delegated domen hesabı ilə qoşulmaq lazımdır.</p></div><span class="gr-auto-state ${state.serviceOffline?'offline':''}">${connectionState}</span></div><div class="gr-auto-grid">
      ${field('domain','AD DNS domeni','example.local')}${field('domainController','Yazıla bilən DC FQDN','dc01.example.local')}</div>
      <div class="gr-auto-note"><strong>Windows / AD rejimi üçün texniki tələblər:</strong> management host AD DNS istifadə etməlidir; DC adı FQDN ilə resolve olunmalıdır; DC-yə TCP/5985 açıq olmalıdır; Kerberos üçün vaxt/KDC işləməlidir; DC-də ActiveDirectory və GroupPolicy/GPMC modulları olmalıdır.</div>
      <details class="gr-auto-advanced"><summary>Scope, operatorlar və RBAC</summary><div class="gr-auto-grid gr-auto-advanced-grid">${area('approvedGpoIds','İcazəli GPO GUID-ləri','*')}${area('authorizedOus','İcazəli OU / domain DN','DC=example,DC=local')}${area('allowedHosts','Endpoint yoxlaması üçün hostlar','server01.example.local')}${area('allowedOperators','Web UI Administrator hesabları','DOMAIN\\Administrator')}${area('remediators','Web UI Remediator hesabları','DOMAIN\\gpo-remediator')}${area('auditors','Web UI Auditor hesabları','DOMAIN\\gpo-auditor')}${area('viewers','Web UI Viewer hesabları','DOMAIN\\gpo-viewer')}</div><p class="gr-auto-help"><b>Vacib:</b> bu RBAC sahələri yalnız brauzeri açan Windows hesabları üçündür. Dashboard-da daxil etdiyiniz delegated DC/GPO icra hesabını buraya yazmaq məcburi deyil və o avtomatik RBAC-a əlavə olunmur. Eyni Web UI hesabı bir neçə rolda yazılıbsa, sistem onu ən yüksək rolda saxlayıb təkrarı avtomatik təmizləyir. GPO/OU sahəsində <b>*</b> read-only discovery üçündür. Production write üçün GUID və OU-nu əl ilə yazmağa ehtiyac yoxdur: Remediation-da preview plan yaradıb <b>Bu GPO + scope-u təsdiqlə və davam et</b> seçdikdə tool həmin planı avtomatik konkret allowlist-ə kilidləyir.</p></details>
      <div class="gr-auto-actions"><button class="gr-auto-btn primary">${state.session?.mode==='WINDOWS'?'Saxla və xidmət rejimini yenilə':'Saxla və Windows / AD-ni başlat'}</button><button type="button" class="gr-auto-btn" data-detect>Avtomatik tap</button>${state.session?.mode==='WINDOWS'&&state.service?.writesEnabled?'<span class="gr-auto-inline-warning">Config dəyişiklikləri change gate-i read-only vəziyyətinə qaytaracaq və idarəli restart tələb edəcək.</span>':''}</div></form>${state.session?.mode==='WINDOWS'?'</details>':''}
      ${state.session?.mode==='WINDOWS'?`<div class="gr-auto-card gr-auto-permission"><div class="gr-auto-title-row"><div><h3>Production change gate</h3><p>Preview və Verify həmişə read-only qalır. Apply/Rollback yalnız bu gate aktiv olduqda mümkündür.</p></div><span class="gr-auto-state ${writes?'on':''}">${writes?'Aktiv':'Bağlı'}</span></div>${state.serviceOffline?'<div class="gr-auto-note warn">Backend xidməti hazırda cavab vermir. Local Control Center-dən service status-u yoxlayın.</div>':(!state.gpoSession?.connected||state.connectionExpired)?'<div class="gr-auto-note warn">Delegated domen sessiyası aktiv deyil. Bağlantı yoxlaması və write mode üçün əvvəlcə Dashboard-dan AD-yə qoşulun.</div><button class="gr-auto-btn primary" data-reconnect>AD-yə qoşul</button>':'<button class="gr-auto-btn" data-readiness>Bağlantını yoxla</button>'}
      ${(!state.gpoSession?.connected||state.connectionExpired||state.serviceOffline)?'':(state.readiness?.checks||[]).map(c=>`<div class="gr-auto-row"><div><strong>${esc(c.label)} · ${esc(c.state||c.status)}</strong><small>${esc(c.message)}</small></div></div>`).join('')}
      ${(!state.gpoSession?.connected||state.connectionExpired||state.serviceOffline)?'':`${wildcardScope&&!writes?'<div class="gr-auto-note info"><strong>Plan-bound authorization:</strong> hazırda discovery genişdir. Production write üçün Remediation-da GPO + scope seçib preview yaradın; tool həmin seçimi avtomatik write allowlist-ə çevirəcək. Əl ilə GUID/OU yazmaq lazım deyil.</div><button class="gr-auto-btn primary" data-plan-scope>Remediation planına keç</button>':`<button class="gr-auto-btn ${writes?'':'primary'}" data-write>${writes?'Dəyişiklikləri bağla':'Dəyişiklikləri aktiv et'}</button>`}`}</div>`:''}</div>`;
    window.GpoClient.localize(panel);
    if(state.busy)panel.querySelectorAll('button:not([data-close]),input,textarea').forEach(x=>x.disabled=true);
  }
  async function load(){
    if(state.loaded||state.busy)return;state.busy=true;render();
    try{
      [state.config,state.service]=await Promise.all([api('/setup/config'),api('/service')]);state.serviceOffline=false;
      if(state.config){const r=normalizeRbac(state.config.allowedOperators||[],state.config.remediators||[],state.config.auditors||[],state.config.viewers||[]);state.config={...state.config,allowedOperators:r.operators,remediators:r.remediators,auditors:r.auditors,viewers:r.viewers};}
      if(state.session?.mode==='WINDOWS'){try{state.gpoSession=await window.GpoClient.request('/api/gpo/session',{timeout:5000});state.connectionExpired=false;}catch(e){if(e.code==='GPO_LOGIN_REQUIRED'||e.status===401){state.gpoSession=null;state.connectionExpired=false;}else if(e.code==='SERVICE_UNREACHABLE'){state.serviceOffline=true;state.gpoSession=null;}else throw e;}}else state.gpoSession=null;
      try{state.discovery=await api('/setup/discover');}catch(e){state.notice=e.message;}
      if(!state.config.exists&&state.discovery){const d=state.discovery,domainDn=String(d.domain||'').split('.').filter(Boolean).map(part=>`DC=${part}`).join(',');state.config={...state.config,domain:d.domain,domainController:d.domainController,backupPath:d.backupPath,approvedGpoIds:['*'],authorizedOus:domainDn?[domainDn]:[],allowedHosts:[],allowedOperators:[d.operator].filter(Boolean)};}
      state.loaded=true;
    }catch(e){state.notice=e.message;}finally{state.busy=false;render();}
  }
  function setRootBlocked(blocked){const root=document.getElementById('root');if(!root)return;root.inert=!!blocked;if(blocked)root.setAttribute('aria-hidden','true');else{root.removeAttribute('inert');root.removeAttribute('aria-hidden');}}
  function open(){if(panel.classList.contains('open'))return;returnFocus=document.activeElement;state.loaded=false;state.config=null;state.service=null;state.gpoSession=null;state.readiness=null;state.notice='';draft=null;setRootBlocked(true);document.body.style.overflow='hidden';panel.classList.add('open');backdrop.classList.add('open');render();load();panel.querySelector('[data-close]')?.focus();}
  function close(){capture();setRootBlocked(false);document.body.style.overflow='';panel.classList.remove('open');backdrop.classList.remove('open');returnFocus?.focus();window.dispatchEvent(new CustomEvent('gr:refresh'));}
  async function action(fn){if(state.busy)return;capture();state.busy=true;state.notice='';render();try{await fn();}catch(e){state.notice=e.message;}finally{state.busy=false;render();}}
  async function restart(result){if(!result.restartScheduled){state.loaded=false;state.session=null;state.gpoSession=null;draft=null;state.notice='Saxlanıldı. Dəyişikliklərin qüvvəyə minməsi üçün tətbiqi yenidən başladın.';return;}state.notice='Saxlanıldı. Windows / AD xidməti idarəli şəkildə yenidən başladılır…';state.serviceOffline=false;window.dispatchEvent(new CustomEvent('gr:service-restarting'));render();const previous=state.service?.processId;const deadline=Date.now()+75000;while(Date.now()<deadline){await new Promise(resolve=>setTimeout(resolve,1200));try{const service=await window.GpoClient.request('/api/service',{timeout:3000});if(service.processId!==previous){window.dispatchEvent(new CustomEvent('gr:service-ready',{detail:{service}}));if(service.mode==='WINDOWS'){location.replace(location.origin+'/#/dashboard');location.reload();return;}if(service.mode==='SETUP'){location.replace(location.origin+'/#/settings');location.reload();return;}}}catch{state.serviceOffline=true;}}throw Error('Restart 75 saniyə ərzində tamamlanmadı. Local Control Center-də service status, windows-startup-error.log və bootstrap.log-u yoxlayın.');}
  function init(){
    backdrop=document.createElement('div');backdrop.id='gr-auto-backdrop';backdrop.onclick=close;document.body.append(backdrop);
    panel=document.createElement('aside');panel.id='gr-auto-panel';panel.setAttribute('role','dialog');panel.setAttribute('aria-modal','true');panel.setAttribute('aria-label','GPO sazlamaları');document.body.append(panel);
    panel.addEventListener('input',capture);
    panel.addEventListener('submit',e=>{e.preventDefault();capture();const c={...draft};action(async()=>{
      const lines=value=>(Array.isArray(value)?value:String(value||'').split(/[\n;]/)).map(v=>String(v).trim()).filter(Boolean);
      const accounts=name=>lines(c[name]).map(v=>v.replaceAll('/','\\'));
      const domainDn=String(c.domain||'').split('.').filter(Boolean).map(part=>`DC=${part}`).join(',');
      const currentOperator=state.session?.operator||state.discovery?.operator||'';
      const adminAccounts=accounts('allowedOperators').length?accounts('allowedOperators'):lines(currentOperator).map(v=>v.replaceAll('/','\\'));
      const rbac=normalizeRbac(adminAccounts,accounts('remediators'),accounts('auditors'),accounts('viewers'));
      const payload={...c,backupPath:c.backupPath||state.discovery?.backupPath||'C:\\ProgramData\\GpoRemediator\\Backups',urls:location.origin,approvedGpoIds:lines(c.approvedGpoIds).length?lines(c.approvedGpoIds):['*'],authorizedOus:lines(c.authorizedOus).length?lines(c.authorizedOus):[domainDn],allowedHosts:lines(c.allowedHosts),allowedOperators:rbac.operators,remediators:rbac.remediators,auditors:rbac.auditors,viewers:rbac.viewers,autoRestart:!!state.service?.managed};
      const result=await api('/setup/config',payload);state.notice='Saxlanıldı. Launcher Windows / AD rejiminə keçir; yazma bağlı qalır.';
      await restart(result);
    });});
    panel.addEventListener('click',e=>{
      if(e.target.closest('[data-close]'))return close();
      if(e.target.closest('[data-reconnect]')){close();location.hash='#/dashboard';window.dispatchEvent(new CustomEvent('gr:connection-expired'));return;}
      if(e.target.closest('[data-detect]'))action(async()=>{state.discovery=await api('/setup/discover');const d=state.discovery;draft={...draft,domain:d.domain||draft?.domain,domainController:d.domainController||draft?.domainController,backupPath:d.backupPath||draft?.backupPath,allowedOperators:d.operator||draft?.allowedOperators};state.notice='Aşkarlanan məlumatlar formaya köçürüldü.';});
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
    api('/session').then(()=>{if(location.hash==='#/settings')open();else setRootBlocked(false);}).catch(()=>{setRootBlocked(false);});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
