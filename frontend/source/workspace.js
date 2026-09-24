/* Editable operator workspace. No package manager or remote dependencies. */
(() => {
  'use strict';
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const icons = {
    home:'<path d="m3 10 9-7 9 7v10H3Z"/><path d="M9 20v-7h6v7"/>',
    scan:'<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M7 12h10"/>',
    modules:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    settings:'<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
    arrow:'<path d="M5 12h14m-6-6 6 6-6 6"/>',
    shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6Z"/><path d="m8 12 3 3 5-6"/>'
  };
  const icon = name => `<svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">${icons[name] || icons.shield}</svg>`;
  let session, service, dashboard, controls, busy = false, notice = '', offline = false, lastUpdated, pendingAction = '', requestSequence = 0;
  const labels = {USER_RIGHTS_ASSIGNMENT:'İstifadəçi hüquqları',SECURITY_OPTION:'Təhlükəsizlik seçimləri',REGISTRY_POLICY:'Registry siyasətləri',ADMINISTRATIVE_TEMPLATE:'Administrative Templates',ACCOUNT_POLICY:'Hesab siyasətləri',ADVANCED_AUDIT_POLICY:'Audit siyasətləri',WINDOWS_FIREWALL:'Windows Firewall',SERVICE_CONFIGURATION:'Sistem xidmətləri',REGISTRY_PREFERENCE:'Registry Preferences',MANUAL:'Əl ilə yoxlama',UNSUPPORTED:'Xəritələnməmiş parametrlər'};
  async function api(path, body) {
    const response = await fetch('/api'+path, {method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json',...(body===undefined?{}:{'X-CSRF-Token':session.csrfToken})},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
    const data = await response.json();
    if(!response.ok) throw new Error(data.message || `HTTP ${response.status}`);
    return data;
  }
  function open(tab) { window.dispatchEvent(new CustomEvent('gr:open',{detail:{tab}})); }
  function mount() {
    const workspace = document.querySelector('.workspace'), nav = document.querySelector('.sidebar nav');
    if(!workspace || !nav) return;
    if(!document.getElementById('operator-home')) {
      const page = document.createElement('section'); page.id='operator-home'; page.tabIndex=-1; page.setAttribute('aria-label','Başlanğıc');
      workspace.insertBefore(page,workspace.querySelector('main,.main'));
      const status=document.createElement('div'); status.id='service-bar'; status.setAttribute('aria-live','polite'); workspace.insertBefore(status,page);
      page.addEventListener('click',e=>{const b=e.target.closest('[data-open],[data-refresh]');if(b?.dataset.open)open(b.dataset.open);if(b?.hasAttribute('data-refresh'))refresh();});
      const modules=document.createElement('section'); modules.id='operator-modules'; modules.tabIndex=-1; modules.hidden=true; workspace.insertBefore(modules,page);
      modules.addEventListener('input',()=>filterModules());
      modules.addEventListener('submit',startSelection);
      status.addEventListener('click',e=>{const b=e.target.closest('[data-service],[data-refresh]');if(b?.hasAttribute('data-refresh'))refresh();if(b?.dataset.service)showServiceDialog(b.dataset.service);});
    }
    if(!nav.querySelector('[data-home-nav]')) {
      const home=document.createElement('a');home.href='#/home';home.className='nav-link';home.dataset.homeNav='';home.innerHTML=icon('home')+'Başlanğıc';nav.prepend(home);
      const modules=document.createElement('a');modules.href='#/modules';modules.className='nav-link';modules.dataset.modulesNav='';modules.innerHTML=icon('modules')+'Modullar';nav.insertBefore(modules,home.nextSibling);
    }
    route();
  }
  function route() {
    const home=location.hash==='#/home'||!location.hash;
    const modules=location.hash==='#/modules';
    document.body.classList.toggle('operator-custom-page',home||modules);
    const page=document.getElementById('operator-home'); if(page)page.hidden=!home;
    const catalog=document.getElementById('operator-modules'); if(catalog)catalog.hidden=!modules;
    for(const [selector,active] of [['[data-home-nav]',home],['[data-modules-nav]',modules]]) {
      const link=document.querySelector(selector); if(link){link.classList.toggle('selected',active);if(active)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');}
    }
    if(home||modules) document.querySelectorAll('.sidebar nav a:not([data-home-nav]):not([data-modules-nav])').forEach(a=>{a.classList.remove('selected');a.removeAttribute('aria-current');});
  }
  function renderStatus() {
    const bar=document.getElementById('service-bar');if(!bar)return;
    const managed=service?.managed, active=service?.activeJobs || 0;
    const focused=bar.contains(document.activeElement)?{action:document.activeElement.dataset.service,refresh:document.activeElement.hasAttribute('data-refresh')}:null;
    const html=`<div class="service-state"><span class="live-dot ${offline?'off':''}"></span><strong>${offline?'Bağlantı yoxdur':service?.stopping?'Xidmət dayandırılır…':service?'Xidmət işləyir':'Qoşulur…'}</strong><span>${offline?'GpoRemediator.cmd → Başlat':`${session?.mode==='MOCK'?'Demo rejimi':session?'Windows rejimi':''}${service?.writesEnabled?' · Yazma aktivdir':' · AD-yə yazma bağlıdır'}`}</span></div><div class="service-actions"><button data-refresh ${busy?'disabled':''}>${icon('scan')} Yenilə</button><button data-service="restart" ${!managed||active||busy||offline||service?.stopping?'disabled':''}>Yenidən başlat</button><button class="service-stop" data-service="stop" ${!managed||active||busy||offline||service?.stopping?'disabled':''}>Dayandır</button></div>${active?`<p class="service-hint">${active} aktiv əməliyyat var. Tamamlanana qədər dayandırma bağlıdır.</p>`:''}${notice?`<p class="service-hint" role="status">${esc(notice)}</p>`:''}`;
    if(bar.dataset.rendered!==html){bar.innerHTML=html;bar.dataset.rendered=html;if(focused){const target=focused.refresh?bar.querySelector('[data-refresh]'):[...bar.querySelectorAll('[data-service]')].find(b=>b.dataset.service===focused.action);if(target&&!target.disabled)target.focus();}}
  }
  function renderHome() {
    const page=document.getElementById('operator-home');if(!page)return;
    page.innerHTML=`<div class="op-heading"><div><div class="op-eyebrow">GPO REMEDIATOR</div><h1>Benchmark üzrə remediation</h1><p>Modulu seçin, hədəfi göstərin və dəyişikliyi tətbiq edin.</p></div></div>
      <div class="op-hero"><div><h2>Benchmark siyahısından başlayın</h2><p>İlkin vəziyyət skanı tələb olunmur. Yalnız seçdiyiniz parametr üçün GPO planı hazırlanır. Backup və tətbiqdən sonrakı yoxlama saxlanılır.</p><div class="op-hero-actions"><a class="primary" href="#/modules">Modulu seç →</a><button data-open="setup">Mühiti sazla</button></div></div><ol class="op-steps"><li><span>01</span><div><strong>Modulu seç</strong><small>Benchmark parametrini tapın</small></div></li><li><span>02</span><div><strong>Planı hazırla</strong><small>Hədəfi və GPO dəyişikliyini yoxlayın</small></div></li><li><span>03</span><div><strong>Tətbiq et</strong><small>Təsdiq, backup və nəticə</small></div></li></ol></div>
      <div class="op-columns"><a class="op-card" href="#/modules"><h2>Benchmark siyahısı</h2><p>${(controls||[]).filter(c=>c.benchmarkId==='CIS').length} parametr · Axtarış və modul filtri</p></a><a class="op-card" href="#/history"><h2>Əməliyyat tarixçəsi</h2><p>${dashboard?.jobs?.length||0} əməliyyat · Nəticələr və geri qaytarma</p></a></div>`;
  }
  function renderModules() {
    const el=document.getElementById('operator-modules');if(!el)return;
    const items=(controls||[]).filter(c=>c.benchmarkId==='CIS').sort((a,b)=>a.controlId.localeCompare(b.controlId,undefined,{numeric:true}));
    el.innerHTML=`<div class="op-heading"><div><div class="op-eyebrow">CIS BENCHMARK v4.0.0 · GÖNDƏRİLƏN SİYAHI</div><h1>Modulu seçin</h1><p>İlkin scan yoxdur. Plan yalnız seçilmiş parametr üçün hazırlanır.</p></div></div>
      <div class="op-module-note">Siyahı təqdim etdiyiniz hissəni əhatə edir. “Adapter yoxdur” parametrləri üçün avtomatik dəyişiklik hələ dəstəklənmir.</div>
      <form id="module-selection"><div class="op-filter"><label for="module-host">Hədəfin DNS adı</label><input id="module-host" name="hostname" required maxlength="253" placeholder="srv-app-01.example.com"><label for="module-role">Rol</label><select id="module-role" name="profile"><option value="MemberServer">Member Server</option></select></div>
      <div class="op-filter"><label for="module-search">Parametr axtar</label><input id="module-search" type="search" placeholder="Kod və ya ad…"><label for="module-group">Modul</label><select id="module-group"><option value="">Bütün modullar</option>${[...new Set(items.map(c=>c.policyPath))].map(g=>`<option value="${esc(g)}">${esc(g)}</option>`).join('')}</select><label for="module-filter">Dəstək</label><select id="module-filter"><option value="all">Hamısı</option><option value="auto">Remediation hazırdır</option><option value="manual">Adapter yoxdur</option></select></div><p id="module-count" aria-live="polite"></p><p id="module-message" role="status"></p>
      <div class="op-module-grid">${items.map(c=>`<article class="op-card op-module" data-group="${esc(c.policyPath)}" data-auto="${c.automated}" data-search="${esc((c.title+' '+c.controlId+' '+c.policyPath).toLowerCase())}"><small>${esc(c.policyPath)}</small><h2>${esc(c.controlId)} · ${esc(c.title)}</h2><p>Hədəf dəyər: ${esc(c.expectedDisplayValue)}</p><span class="op-tag">${c.automated?'Remediation hazırdır':'Adapter yoxdur'}</span><details><summary>Ətraflı</summary><p>${esc(c.notes)}</p></details><button type="submit" name="controlId" value="${esc(c.id)}" ${c.automated?'':'disabled'}>Seç və planı aç</button></article>`).join('')}</div><div id="module-empty" class="op-empty" hidden>Uyğun parametr tapılmadı.</div></form>`;
    filterModules();
  }
  async function startSelection(e) {
    e.preventDefault();const button=e.submitter;if(!button||busy)return;
    const form=e.target, message=document.getElementById('module-message');
    busy=true;button.disabled=true;message.textContent='Seçim hazırlanır…';
    try {
      const finding=await api('/findings',{controlId:button.value,hostname:form.elements.hostname.value.trim(),profile:form.elements.profile.value,benchmarkSelection:true});
      location.hash='#/findings/'+encodeURIComponent(finding.id);
      setTimeout(()=>open('plan'),100);
    } catch(error) {message.textContent=error.message;}
    finally {busy=false;button.disabled=false;}
  }
  function filterModules() {
    const query=(document.getElementById('module-search')?.value||'').trim().toLowerCase(), filter=document.getElementById('module-filter')?.value;
    let count=0;document.querySelectorAll('.op-module').forEach(card=>{const show=card.dataset.search.includes(query)&&(!document.getElementById('module-group')?.value||card.dataset.group===document.getElementById('module-group').value)&&(filter==='all'||(filter==='auto'?card.dataset.auto==='true':card.dataset.auto==='false'));card.hidden=!show;if(show)count++;});
    const label=document.getElementById('module-count');if(label)label.textContent=count+' parametr göstərilir';
    const empty=document.getElementById('module-empty');if(empty)empty.hidden=count>0;
  }
  async function refresh() {
    if(busy)return;busy=true;renderStatus();const request=++requestSequence;
    try {
      session=await api('/session');
      const data=await Promise.all([api('/service'),api('/dashboard'),api('/controls')]);
      if(request!==requestSequence)return;
      [service,dashboard,controls]=data;offline=false;notice='';lastUpdated=new Date();
      renderHome();renderModules();
    }catch(e){offline=true;notice=`Bağlantını yoxlayın və “Yenilə” düyməsini basın. ${e.message}`;}
    finally{busy=false;renderStatus();}
  }
  function showServiceDialog(action) {
    const dialog=document.getElementById('service-dialog');pendingAction=action;
    document.getElementById('service-dialog-title').textContent=action==='stop'?'Xidmət dayandırılsın?':'Xidmət yenidən başladılsın?';
    document.getElementById('service-dialog-text').textContent=action==='stop'?'Tətbiqə bağlantı kəsiləcək. Yenidən başlamaq üçün GpoRemediator.cmd idarəetmə panelində Başlat düyməsini istifadə edin.':'Səhifə müvəqqəti ayrılacaq və xidmət hazır olduqda yenidən qoşulacaq.';
    dialog.showModal();document.getElementById('service-cancel').focus();
  }
  async function serviceAction() {
    const action=pendingAction;document.getElementById('service-dialog').close();busy=true;renderStatus();
    try {
      await api('/service/'+action,{});notice=action==='stop'?'Dayandırma qəbul edildi. Yenidən açmaq üçün masaüstü idarəetmə panelindən istifadə edin.':'Yenidən başladılır…';
      service.stopping=true;renderStatus();
      if(action==='restart') { await new Promise(r=>setTimeout(r,3000)); for(let i=0;i<25;i++){try{session=await api('/session');const status=await api('/service');if(!status.stopping){service=status;notice='Xidmət yenidən başladıldı.';offline=false;break;}}catch{}await new Promise(r=>setTimeout(r,1200));if(i===24){offline=true;notice='Xidmətə qoşulmaq alınmadı. İdarəetmə panelini və logları yoxlayın.';}} }
      else {await new Promise(r=>setTimeout(r,2000));offline=true;}
    }catch(e){notice=e.message;}finally{busy=false;renderStatus();}
  }
  function init() {
    document.addEventListener('click',e=>{if(!e.target.closest('.skip-link'))return;e.preventDefault();const target=document.querySelector('#operator-home:not([hidden]),#operator-modules:not([hidden])')||document.querySelector('.main');if(target){target.tabIndex=-1;target.focus();target.scrollIntoView({block:'start'});}});
    const dialog=document.createElement('dialog');dialog.id='service-dialog';dialog.setAttribute('aria-labelledby','service-dialog-title');dialog.innerHTML='<h2 id="service-dialog-title"></h2><p id="service-dialog-text"></p><div><button id="service-cancel">Ləğv et</button><button id="service-confirm" class="danger">Davam et</button></div>';document.body.appendChild(dialog);
    document.getElementById('service-cancel').onclick=()=>dialog.close();document.getElementById('service-confirm').onclick=serviceAction;
    const observer=new MutationObserver(()=>{if(!document.getElementById('operator-home')||!document.querySelector('[data-home-nav]')){mount();renderHome();renderModules();renderStatus();}});observer.observe(document.getElementById('root'),{childList:true,subtree:true});
    mount();refresh();window.addEventListener('gr:refresh',refresh);window.addEventListener('hashchange',()=>{route();if(location.hash==='#/home'&&!busy)refresh();});
    setInterval(async()=>{if(busy||document.hidden)return;try{service=await api('/service');offline=false;}catch{offline=true;}renderStatus();},10000);
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
