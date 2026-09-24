(() => {
  'use strict';
  const state={session:null,config:null,readiness:null,discovery:null,busy:false,notice:'',tab:'setup',loaded:false};
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let panel,backdrop,returnFocus,draft=null;
  async function api(path,body){
    if(!state.session){const r=await fetch('/api/session');state.session=await r.json();if(!r.ok)throw Error('Session unavailable');}
    const r=await fetch('/api'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:{'Content-Type':'application/json',...(body===undefined?{}:{'X-CSRF-Token':state.session.csrfToken})},body:body===undefined?undefined:JSON.stringify(body)});
    const data=await r.json();if(!r.ok)throw Error(data.message||'Request failed');return data;
  }
  function capture(){if(state.busy)return;const form=panel.querySelector('form');if(form)draft=Object.fromEntries(new FormData(form));}
  function render(){
    const c=draft||state.config||{}, warnings=state.discovery?.warnings||[];
    const field=(name,label,placeholder='')=>`<label class="gr-auto-field">${label}<input name="${name}" required value="${esc(c[name]||'')}" placeholder="${esc(placeholder)}"></label>`;
    panel.innerHTML=`<div class="gr-auto-head"><div><h2>Parol siyasəti · Sazlamalar</h2><p>Avtomatik aşkarlama · Əl ilə düzəliş mümkündür</p></div><button data-close class="gr-auto-close" aria-label="Bağla">×</button></div><div class="gr-auto-body" aria-busy="${state.busy}">
      ${state.notice?`<div class="gr-auto-note" role="status">${esc(state.notice)}</div>`:''}
      <div class="gr-auto-note">${state.session?.mode==='WINDOWS'?'Windows rejimi':'Demo rejimi — AD-yə dəyişiklik edilmir'}. Bu pilot yalnız seçilən test istifadəçisinin parol siyasətini dəyişir. GPO GUID, OU və hədəf kompüter siyahısı tələb olunmur.</div>
      ${warnings.length?`<div class="gr-auto-note warn">${warnings.map(esc).join('<br>')}</div>`:''}
      <form id="pilot-setup" class="gr-auto-card"><h3>Windows / AD bağlantısı</h3><p>Domen, DC və operator ilk açılışda aşkarlanır. Saxlanmış və əl ilə yazılmış məlumatlar avtomatik əvəz olunmur.</p><div class="gr-auto-grid">
      ${field('domain','AD domain','example.com')}${field('domainController','Writable domain controller','dc01.example.com')}
      ${field('urls','Management HTTPS URL','https://management.example.com:5443')}${field('backupPath','Backup path','C:\\ProgramData\\GpoRemediator\\Backups')}
      <label class="gr-auto-field gr-auto-span2">İcazəli operatorlar — hər sətirdə DOMAIN\\user<textarea name="allowedOperators" required>${esc(Array.isArray(c.allowedOperators)?c.allowedOperators.join('\n'):c.allowedOperators||'')}</textarea></label></div>
      <p>HTTPS ünvanı tətbiqin işlədiyi kompüterə aid olmalıdır; uyğun etibarlı sertifikat tələb olunur. Saxlama yazma icazəsini bağlayır.</p>
      <div class="gr-auto-actions"><button class="gr-auto-btn primary">Saxla və yenidən başlat</button><button type="button" class="gr-auto-btn" data-detect>Aşkarlamanı göstər</button></div></form>
      ${state.discovery?`<details class="gr-auto-card"><summary>Aşkarlanan məlumatlar</summary><p>${esc(state.discovery.domain||'Domen aşkarlanmadı')} · ${esc(state.discovery.domainController||'DC aşkarlanmadı')} · ${esc(state.discovery.operator)}</p><button class="gr-auto-btn" data-use-detection>Bu məlumatları formaya köçür</button></details>`:''}
      <div class="gr-auto-card"><h3>Hazırlıq və yazma icazəsi</h3><button class="gr-auto-btn" data-readiness>Hazırlığı yoxla</button>
      ${(state.readiness?.checks||[]).map(c=>`<div class="gr-auto-row"><div><strong>${esc(c.label)} · ${esc(c.status)}</strong><small>${esc(c.message)}</small></div></div>`).join('')}
      ${state.session?.mode==='WINDOWS'?`<p>Yazma ${state.config?.enableWrites?'aktivdir':'bağlıdır'}. Hər tətbiq ayrıca APPLY təsdiqi tələb edir.</p><label class="gr-auto-field">${state.config?.enableWrites?'DISABLE WRITES':'ENABLE WRITES'} yazın<input id="write-confirm" autocomplete="off"></label><button class="gr-auto-btn" data-write>${state.config?.enableWrites?'Yazmanı bağla':'Yazmanı aktivləşdir'}</button>`:'<p>Demo nəticəsi real AD hazırlığını göstərmir. Real tətbiq üçün sazlamaları saxlayın və Windows rejimində açın.</p>'}</div></div>`;
    if(state.busy)panel.querySelectorAll('button:not([data-close]),input,textarea').forEach(x=>x.disabled=true);
  }
  async function load(){
    if(state.loaded)return;state.busy=true;render();
    try{
      state.config=await api('/setup/config');
      try{state.discovery=await api('/setup/discover');}catch(e){state.notice=e.message;}
      if(!state.config.exists&&state.discovery){const d=state.discovery;state.config={...state.config,domain:d.domain,domainController:d.domainController,urls:d.urls,backupPath:d.backupPath,allowedOperators:[d.operator].filter(Boolean)};}
      state.loaded=true;
    }catch(e){state.notice=e.message;}finally{state.busy=false;render();}
  }
  function open(){returnFocus=document.activeElement;document.getElementById('root').inert=true;document.body.style.overflow='hidden';panel.classList.add('open');backdrop.classList.add('open');render();load();panel.querySelector('[data-close]').focus();}
  function close(){capture();document.getElementById('root').inert=false;document.body.style.overflow='';panel.classList.remove('open');backdrop.classList.remove('open');returnFocus?.focus();window.dispatchEvent(new CustomEvent('gr:refresh'));}
  async function action(fn){capture();state.busy=true;state.notice='';render();try{await fn();}catch(e){state.notice=e.message;}finally{state.busy=false;render();}}
  function init(){
    backdrop=document.createElement('div');backdrop.id='gr-auto-backdrop';backdrop.onclick=close;document.body.append(backdrop);
    panel=document.createElement('aside');panel.id='gr-auto-panel';panel.setAttribute('role','dialog');panel.setAttribute('aria-modal','true');panel.setAttribute('aria-label','Parol siyasəti sazlamaları');document.body.append(panel);
    panel.addEventListener('input',capture);
    panel.addEventListener('submit',e=>{e.preventDefault();capture();const c={...draft};action(async()=>{
      const payload={...c,approvedGpoIds:[],authorizedOus:[],allowedHosts:[],allowedOperators:String(c.allowedOperators||'').split(/[\n;]/).map(v=>v.trim()).filter(Boolean),autoRestart:true};
      const result=await api('/setup/config',payload);state.notice='Saxlanıldı. Windows rejimi yenidən başladılır; yazma bağlıdır.';
      if(result.restartScheduled)setTimeout(()=>{location.href=payload.urls.replace(/\/$/,'')+'/#/settings';},4000);
    });});
    panel.addEventListener('click',e=>{
      if(e.target.closest('[data-close]'))return close();
      if(e.target.closest('[data-detect]'))action(async()=>{state.discovery=await api('/setup/discover');state.notice='Aşkarlanan məlumatlar aşağıdadır. Formadakı düzəlişlər saxlanıldı.';});
      if(e.target.closest('[data-use-detection]')){capture();const d=state.discovery;draft={...draft,domain:d.domain,domainController:d.domainController,urls:d.urls,backupPath:d.backupPath,allowedOperators:d.operator};render();}
      if(e.target.closest('[data-readiness]'))action(async()=>{state.readiness=await api('/automation/readiness');});
      if(e.target.closest('[data-write]')){const confirmation=panel.querySelector('#write-confirm').value;action(async()=>{await api('/setup/write-mode',{enable:!state.config?.enableWrites,confirmation,autoRestart:true});state.notice='Yazma sazlaması saxlanıldı; xidmət yenidən başladılır.';setTimeout(()=>location.reload(),4000);});}
    });
    document.addEventListener('keydown',e=>{
      if(!panel.classList.contains('open'))return;
      if(e.key==='Escape')close();
      if(e.key==='Tab'){const items=[...panel.querySelectorAll('button:not(:disabled),input:not(:disabled),textarea:not(:disabled),summary')];const first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last?.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first?.focus();}}
    });
    window.addEventListener('gr:open',open);
    window.addEventListener('hashchange',()=>{if(location.hash==='#/settings')open();});
    api('/session').then(()=>{if(location.hash==='#/settings'||state.session.setupRequired)open();}).catch(()=>{});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
