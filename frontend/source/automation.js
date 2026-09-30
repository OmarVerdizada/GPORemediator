(() => {
  'use strict';
  const state={session:null,config:null,readiness:null,discovery:null,service:null,busy:false,notice:'',connectionExpired:false,tab:'setup',loaded:false};
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let panel,backdrop,returnFocus,draft=null;
  async function api(path,body){
    if(!state.session)state.session=await window.GpoClient.request('/api/session');
    try{return await window.GpoClient.request('/api'+path,{body,csrfToken:state.session.csrfToken});}
    catch(e){if(e.status===401||e.code==='CSRF_INVALID')state.session=null;if(e.code==='GPO_LOGIN_REQUIRED')state.connectionExpired=true;throw e;}
  }
  function capture(){if(state.busy)return;const form=panel.querySelector('form');if(form)draft=Object.fromEntries(new FormData(form));}
  function render(){
    const c=draft||state.config||{}, warnings=state.discovery?.warnings||[];
    const field=(name,label,placeholder='')=>`<label class="gr-auto-field">${label}<input name="${name}" required value="${esc(c[name]||'')}" placeholder="${esc(placeholder)}"></label>`;
    panel.innerHTML=`<div class="gr-auto-head"><div><h2>GPO · Sazlamalar</h2><p>Avtomatik aşkarlama · Əl ilə düzəliş mümkündür</p></div><button data-close class="gr-auto-close" aria-label="Bağla">×</button></div><div class="gr-auto-body" aria-busy="${state.busy}">
      ${state.busy?'<p role="status">Gözləyin, sorğu icra olunur…</p>':''}${state.notice?`<div class="gr-auto-note" role="status">${esc(state.notice)}</div>`:''}
      <div class="gr-auto-note">${state.session?.mode==='WINDOWS'?'Domen sazlamaları':'İlk quraşdırma'}. Domenə qoşulduqdan sonra GPO və hədəflər siyahıdan seçilir.</div>
      ${warnings.length?`<div class="gr-auto-note warn">${warnings.map(esc).join('<br>')}</div>`:''}
      ${state.session?.mode==='WINDOWS'?'<details class="gr-auto-card"><summary>Domen sazlamalarını dəyiş</summary>':''}<form id="windows-setup" class="gr-auto-card"><h3>Windows / AD bağlantısı</h3><p>Aşkarlanan məlumatları yoxlayın və saxlayın. Mövcud sazlamalarınız qorunur.</p><div class="gr-auto-grid">
      ${field('domain','Domen','example.local')}${field('domainController','Domen kontrolleri','dc01.example.local')}

      <label class="gr-auto-field gr-auto-span2">Administrator Windows hesabları<textarea name="allowedOperators" required spellcheck="false" placeholder="DOMAIN\\user">${esc(Array.isArray(c.allowedOperators)?c.allowedOperators.join('\n'):c.allowedOperators||'')}</textarea><small>Hər sətirdə bir hesab. Bu siyahı Administrator roludur.</small></label>
      <label class="gr-auto-field gr-auto-span2">İcazəli GPO GUID-ləri<textarea name="approvedGpoIds" required spellcheck="false" placeholder="{00000000-0000-0000-0000-000000000000}">${esc(Array.isArray(c.approvedGpoIds)?c.approvedGpoIds.join('\n'):c.approvedGpoIds||'')}</textarea><small>Hər sətirdə bir GUID. Şüurlu limitsiz seçim üçün yalnız * yazın.</small></label>
      <label class="gr-auto-field gr-auto-span2">İcazəli domen/OU DN-ləri<textarea name="authorizedOus" required spellcheck="false" placeholder="OU=Servers,DC=example,DC=local">${esc(Array.isArray(c.authorizedOus)?c.authorizedOus.join('\n'):c.authorizedOus||'')}</textarea><small>Hər sətirdə bir DN. Alt OU-lar server tərəfindən bu sərhəddə yoxlanır.</small></label>
      <label class="gr-auto-field gr-auto-span2">gpupdate üçün icazəli hostlar<textarea name="allowedHosts" spellcheck="false" placeholder="server01.example.local">${esc(Array.isArray(c.allowedHosts)?c.allowedHosts.join('\n'):c.allowedHosts||'')}</textarea><small>Boş siyahı endpoint refresh-i bloklayır; limitsiz seçim üçün * yazın.</small></label></div><details><summary>Əlavə sazlamalar</summary>${field('backupPath','DC-də ehtiyat nüsxə qovluğu','C:\\ProgramData\\GpoRemediator\\Backups')}</details>
      <p>Sazlamalar saxlandıqda tətbiq yenidən başladılır. Siyasətləri dəyişmək üçün ayrıca icazə açılmalıdır.</p>
      <div class="gr-auto-actions"><button class="gr-auto-btn primary">Saxla və yenidən başlat</button><button type="button" class="gr-auto-btn" data-detect>Məlumatları aşkarlayın</button></div></form>${state.session?.mode==='WINDOWS'?'</details>':''}
      ${state.discovery&&state.session?.mode!=='WINDOWS'?`<details class="gr-auto-card"><summary>Aşkarlanan məlumatlar</summary><p>${esc(state.discovery.domain||'Domen aşkarlanmadı')} · ${esc(state.discovery.domainController||'DC aşkarlanmadı')} · ${esc(state.discovery.operator)}</p><button class="gr-auto-btn" data-use-detection>Bu məlumatları formaya köçür</button></details>`:''}
      <div class="gr-auto-card"><h3>Siyasət dəyişikliklərinə icazə</h3>${state.connectionExpired?'<div class="gr-auto-note warn">Domen bağlantısı bitib. Əsas ekranda yenidən qoşulun.</div><button class="gr-auto-btn primary" data-reconnect>Domenə yenidən qoşul</button>':state.session?.mode==='WINDOWS'?'<button class="gr-auto-btn" data-readiness>Bağlantını yoxla</button>':'<p>Əvvəlcə domen sazlamalarını saxlayın və tətbiqi yenidən başladın.</p>'}
      ${state.connectionExpired?'':(state.readiness?.checks||[]).map(c=>`<div class="gr-auto-row"><div><strong>${esc(c.label)} · ${esc(c.state||c.status)}</strong><small>${esc(c.message)}</small></div></div>`).join('')}
      ${state.session?.mode==='WINDOWS'&&!state.connectionExpired?`<p>Yazma ${state.config?.enableWrites?'aktivdir':'bağlıdır'}. Hər tətbiq ayrıca APPLY təsdiqi tələb edir.</p><label class="gr-auto-field">${state.config?.enableWrites?'DISABLE WRITES':'ENABLE WRITES'} yazın<input id="write-confirm" autocomplete="off"></label><button class="gr-auto-btn" data-write>${state.config?.enableWrites?'Yazmanı bağla':'Yazmanı aktivləşdir'}</button>`:state.session?.mode==='WINDOWS'?'':'<p>Setup rejimində GPO əməliyyatı yoxdur. Sazlamaları saxlayın və Windows rejimində açın.</p>'}</div></div>`;
    window.GpoClient.localize(panel);
    if(state.busy)panel.querySelectorAll('button:not([data-close]),input,textarea').forEach(x=>x.disabled=true);
  }
  async function load(){
    if(state.loaded||state.busy)return;state.busy=true;render();
    try{
      [state.config,state.service]=await Promise.all([api('/setup/config'),api('/service')]);
      try{state.discovery=await api('/setup/discover');}catch(e){state.notice=e.message;}
      if(!state.config.exists&&state.discovery){const d=state.discovery;state.config={...state.config,domain:d.domain,domainController:d.domainController,backupPath:d.backupPath,allowedOperators:[d.operator].filter(Boolean)};}
      state.loaded=true;
    }catch(e){state.notice=e.message;}finally{state.busy=false;render();}
  }
  function open(){if(panel.classList.contains('open'))return;returnFocus=document.activeElement;document.getElementById('root').inert=true;document.body.style.overflow='hidden';panel.classList.add('open');backdrop.classList.add('open');render();load();panel.querySelector('[data-close]').focus();}
  function close(){capture();document.getElementById('root').inert=false;document.body.style.overflow='';panel.classList.remove('open');backdrop.classList.remove('open');returnFocus?.focus();window.dispatchEvent(new CustomEvent('gr:refresh'));}
  async function action(fn){if(state.busy)return;capture();state.busy=true;state.notice='';render();try{await fn();}catch(e){state.notice=e.message;}finally{state.busy=false;render();}}
  async function restart(result){if(!result.restartScheduled){state.loaded=false;state.session=null;draft=null;state.notice='Saxlanıldı. Dəyişikliklərin qüvvəyə minməsi üçün tətbiqi yenidən başladın.';return;}state.notice='Saxlanıldı. Tətbiq yenidən başladılır…';render();const previous=state.service?.processId;const deadline=Date.now()+60000;while(Date.now()<deadline){await new Promise(resolve=>setTimeout(resolve,1200));try{const service=await window.GpoClient.request('/api/service',{timeout:3000});if(service.mode==='WINDOWS'&&service.processId!==previous){location.replace(location.origin+'/#/dashboard');location.reload();return;}}catch{}}throw Error('Sazlamalar saxlanıldı, amma xidmət hələ açılmayıb. GpoRemediator.cmd faylını başladın və səhifəni yeniləyin.');}
  function init(){
    backdrop=document.createElement('div');backdrop.id='gr-auto-backdrop';backdrop.onclick=close;document.body.append(backdrop);
    panel=document.createElement('aside');panel.id='gr-auto-panel';panel.setAttribute('role','dialog');panel.setAttribute('aria-modal','true');panel.setAttribute('aria-label','GPO sazlamaları');document.body.append(panel);
    panel.addEventListener('input',capture);
    panel.addEventListener('submit',e=>{e.preventDefault();capture();const c={...draft};action(async()=>{
      const lines=value=>String(value||'').split(/[\n;]/).map(v=>v.trim()).filter(Boolean);
      const payload={...c,urls:location.origin,approvedGpoIds:lines(c.approvedGpoIds),authorizedOus:lines(c.authorizedOus),allowedHosts:lines(c.allowedHosts),allowedOperators:lines(c.allowedOperators).map(v=>v.replaceAll('/','\\')),autoRestart:!!state.service?.managed};
      const result=await api('/setup/config',payload);state.notice='Saxlanıldı. Windows rejimi yenidən başladılır; yazma bağlıdır.';
      await restart(result);
    });});
    panel.addEventListener('click',e=>{
      if(e.target.closest('[data-close]'))return close();
      if(e.target.closest('[data-reconnect]')){close();location.hash='#/dashboard';window.dispatchEvent(new CustomEvent('gr:connection-expired'));return;}
      if(e.target.closest('[data-detect]'))action(async()=>{state.discovery=await api('/setup/discover');state.notice='Aşkarlanan məlumatlar aşağıdadır. Formadakı düzəlişlər saxlanıldı.';});
      if(e.target.closest('[data-use-detection]')){capture();const d=state.discovery;draft={...draft,domain:d.domain,domainController:d.domainController,backupPath:d.backupPath,allowedOperators:d.operator};render();}
      if(e.target.closest('[data-readiness]'))action(async()=>{state.connectionExpired=false;state.readiness=await api('/gpo/readiness');});
      if(e.target.closest('[data-write]')){const confirmation=panel.querySelector('#write-confirm').value;action(async()=>{const result=await api('/setup/write-mode',{enable:!state.config?.enableWrites,confirmation,autoRestart:!!state.service?.managed});await restart(result);});}
    });
    document.addEventListener('keydown',e=>{
      if(!panel.classList.contains('open'))return;
      if(e.key==='Escape')close();
      if(e.key==='Tab'){const items=[...panel.querySelectorAll('button:not(:disabled),input:not(:disabled),textarea:not(:disabled),summary')];const first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last?.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first?.focus();}}
    });
    window.addEventListener('gr:open',open);
    window.addEventListener('hashchange',()=>{if(location.hash==='#/settings')open();});
    api('/session').then(()=>{if(location.hash==='#/settings'||state.session.mode==='SETUP')open();}).catch(()=>{});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
