/* Password-only pilot. No background inventory or compliance scan. */
(() => {
  'use strict';
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const state={session:null,service:null,settings:[],history:[],plan:null,busy:false,notice:'',setting:'MinPasswordLength',user:'',value:14};
  let page,bar;
  async function api(path,body){
    const r=await fetch('/api'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json',...(body===undefined?{}:{'X-CSRF-Token':state.session.csrfToken})},body:body===undefined?undefined:JSON.stringify(body)});
    const data=await r.json();if(!r.ok)throw Error(data.message||'Request failed');return data;
  }
  function settingName(id){return state.settings.find(s=>s.id===id)?.title||({LockoutThreshold:'Account lockout threshold (attempts)',LockoutDuration:'Account lockout duration (seconds)',LockoutObservationWindow:'Reset lockout counter after (seconds)'}[id])||id;}
  function valueLabel(id,value){if(id==='ComplexityEnabled'||id==='ReversibleEncryptionEnabled')return value?'Enabled':'Disabled';if(id==='MaxPasswordAge'&&value===0)return '0 (never expires)';return String(value);}
  function capture(){const form=page?.querySelector('#password-select');if(form){state.user=form.elements.user.value;state.value=Number(form.elements.value.value);}}
  function renderStatus(){if(!bar)return;bar.innerHTML=`<div class="service-state"><span class="live-dot"></span><strong>${state.session?.mode==='WINDOWS'?'Windows / AD':'Demo — lokal simulyasiya'}</strong><span>${state.service?.writesEnabled?'Yazma aktivdir':'AD-yə yazma bağlıdır'}</span></div><div class="service-actions"><button data-settings>Sazlamalar</button><button data-refresh>Yenilə</button><button data-service="restart" ${!state.service?.managed||state.busy?'disabled':''}>Yenidən başlat</button><button data-service="stop" ${!state.service?.managed||state.busy?'disabled':''}>Dayandır</button></div>`;}
  function render(){
    if(!page)return;
    const history=location.hash==='#/history';
    const rule=state.settings.find(s=>s.id===state.setting),p=state.plan;
    page.innerHTML=`<div class="op-heading"><div><div class="op-eyebrow">SECHARD → REMEDIATION · PASSWORD PILOT</div><h1>${history?'Parol siyasəti tarixçəsi':'Parol siyasətini seçin'}</h1><p>SecHard-da uğursuz olan elementi seçin, test istifadəçisini göstərin və planı təsdiqləyin.</p></div></div>
      <div class="op-module-note">Yalnız seçdiyiniz istifadəçi üçün fine-grained password policy (PSO). Avtomatik scan yoxdur. Domen siyasəti dəyişmir. ${state.session?.mode==='MOCK'?'Hazırda bütün əməliyyatlar demodur.':''}</div>
      ${state.notice?`<div class="gr-auto-note" role="status">${esc(state.notice)}</div>`:''}
      ${history?'':`<div class="op-module-grid">${state.settings.map(s=>`<button class="op-card pilot-choice ${state.setting===s.id?'chosen':''}" data-setting="${esc(s.id)}" aria-pressed="${state.setting===s.id}"><span class="op-tag">Password policy</span><h2>${esc(s.title)}</h2><p>${esc(s.unit)}</p></button>`).join('')}</div>
      <form id="password-select" class="op-card pilot-form"><h2>Test istifadəçisi və gözlənilən dəyər</h2><p>SecHard nəticəsini və tələb etdiyi dəyəri əl ilə seçin. İstifadəçi parolu tələb olunmur.</p><div class="gr-auto-grid"><label class="gr-auto-field">Test istifadəçisi<input name="user" required maxlength="256" autocomplete="off" placeholder="test.user və ya test.user@example.com" value="${esc(state.user)}"></label><label class="gr-auto-field">${esc(rule?.title||'Dəyər')} ${rule?`(${esc(rule.unit)})`:''}<input name="value" type="number" required step="1" min="${rule?.minimum??0}" max="${rule?.maximum??255}" value="${state.value}"></label></div><p>Təklif olunan dəyəri SecHard tələbi ilə tutuşdurun. Digər parol və lockout dəyərləri istifadəçinin hazırkı effektiv siyasətindən köçürülür.</p><button class="gr-auto-btn primary">${state.busy?'Hazırlanır…':'Seçilmiş parametr üçün plan hazırla'}</button></form>
      ${p?`<section class="op-card pilot-form"><h2>Planı yoxlayın</h2><dl class="gr-auto-kv"><dt>Rejim</dt><dd>${esc(p.mode)}</dd><dt>İstifadəçi</dt><dd>${esc(p.before.user)}<br><small>${esc(p.before.distinguishedName)}</small></dd><dt>Əvvəlki mənbə</dt><dd>${esc(p.before.sourceId||'Domain default')}</dd><dt>Təsir</dt><dd>Yalnız bu istifadəçi · 1 parametr</dd></dl><table class="pilot-table"><thead><tr><th>Parametr</th><th>Əvvəl</th><th>Sonra</th></tr></thead><tbody>${Object.entries(p.after).map(([k,v])=>`<tr class="${k===p.setting?'changed':''}"><td>${esc(settingName(k))}${k===p.setting?' · seçilmiş':''}</td><td>${esc(valueLabel(k,p.before.values[k]))}</td><td>${esc(valueLabel(k,v))}</td></tr>`).join('')}</tbody></table><div class="gr-auto-note">${p.before.warnings.map(esc).join('<br>')}</div><form id="password-apply"><label class="gr-auto-field">Seçilmiş test istifadəçisini və dəyişikliyi təsdiqləmək üçün APPLY yazın<input name="confirmation" autocomplete="off" required placeholder="APPLY"></label><button class="gr-auto-btn primary">Backup et və tətbiq et</button></form></section>`:''}`}
      <section class="op-card pilot-form"><h2>Əməliyyatlar və geri qaytarma</h2>${state.history.length?state.history.map(j=>`<article class="pilot-job"><strong>${esc(j.plan.before.user)} · ${esc(settingName(j.plan.setting))}</strong><p>${esc(j.state)} · ${esc(j.plan.mode)} · ${esc(new Date(j.updatedAt).toLocaleString())}</p><p>${esc(j.message)}</p><details><summary>Əməliyyat və backup identifikatoru</summary><code>${esc(j.id)}</code><p>${esc(j.policyId||'PSO yaradılması təsdiqlənməyib')}</p></details>${j.state==='ROLLED_BACK'?'':`<form data-rollback="${esc(j.id)}"><label class="gr-auto-field">Bu pilot dəyişiklik üçün ROLLBACK yazın<input name="confirmation" required placeholder="ROLLBACK" autocomplete="off"></label><button class="gr-auto-btn">Əvvəlki siyasətə qayıt</button></form>`}</article>`).join(''):'<p>Hələ tətbiq edilmiş dəyişiklik yoxdur.</p>'}</section>`;
    if(state.busy)page.querySelectorAll('button,input').forEach(e=>e.disabled=true);
    renderStatus();
  }
  async function run(fn){if(state.busy)return;capture();state.busy=true;state.notice='';render();try{await fn();}catch(e){state.notice=e.message;}finally{state.busy=false;render();}}
  async function refresh(){
    if(state.busy)return;
    await run(async()=>{state.session=await api('/session');[state.service,state.settings,state.history]=await Promise.all([api('/service'),api('/password/settings'),api('/password/history')]);});
  }
  function mount(){
    const workspace=document.querySelector('.workspace'),nav=document.querySelector('.sidebar nav');if(!workspace||!nav)return;
    document.body.classList.add('operator-custom-page');
    if(!document.getElementById('operator-modules')){
      bar=document.createElement('div');bar.id='service-bar';bar.setAttribute('aria-live','polite');workspace.prepend(bar);
      page=document.createElement('section');page.id='operator-modules';workspace.insertBefore(page,bar.nextSibling);
      page.addEventListener('input',e=>{if(e.target.closest('#password-select')){capture();if(state.plan){state.plan=null;const apply=page.querySelector('#password-apply');if(apply)apply.closest('section').remove();}}});
      page.addEventListener('click',e=>{const b=e.target.closest('[data-setting]');if(!b||state.busy)return;capture();state.setting=b.dataset.setting;state.value=state.settings.find(s=>s.id===state.setting).suggested;state.plan=null;render();});
      page.addEventListener('submit',e=>{
        e.preventDefault();const form=e.target,confirmation=form.elements.confirmation?.value;
        if(form.id==='password-select')run(async()=>{state.plan=null;state.plan=await api('/password/plan',{user:state.user.trim(),setting:state.setting,value:state.value});state.notice='Plan hazırdır. AD-yə dəyişiklik edilməyib.';});
        if(form.id==='password-apply'&&state.plan){const id=state.plan.id;run(async()=>{const result=await api('/password/'+id+'/apply',{confirmation});state.plan=null;state.history=await api('/password/history');state.notice=result.state+': '+result.message;});}
        if(form.dataset.rollback)run(async()=>{const result=await api('/password/'+form.dataset.rollback+'/rollback',{confirmation});state.plan=null;state.history=await api('/password/history');state.notice=result.state+': '+result.message;});
      });
      bar.addEventListener('click',e=>{
        if(e.target.closest('[data-settings]'))window.dispatchEvent(new CustomEvent('gr:open'));
        if(e.target.closest('[data-refresh]'))refresh();
        const button=e.target.closest('[data-service]');if(button){const action=button.dataset.service;if(!confirm(action==='stop'?'Xidmət dayandırılsın?':'Xidmət yenidən başladılsın?'))return;run(async()=>{await api('/service/'+action,{});state.notice='Sorğu qəbul edildi. Yenidən qoşulmaq üçün Yenilə düyməsini istifadə edin.';});}
      });
      render();
    }
    if(!nav.querySelector('[data-pilot-nav]')){
      nav.querySelectorAll('a,button').forEach(a=>a.hidden=true);
      for(const [href,label] of [['#/modules','Parol siyasətləri'],['#/history','Tarixçə'],['#/settings','Sazlamalar']]){const a=document.createElement('a');a.href=href;a.className='nav-link';a.dataset.pilotNav='';a.textContent=label;nav.append(a);}
    }
    nav.querySelectorAll('[data-pilot-nav]').forEach(a=>a.classList.toggle('selected',a.hash===location.hash||(!location.hash&&a.hash==='#/modules')));
  }
  function init(){
    const observer=new MutationObserver(()=>mount());observer.observe(document.getElementById('root'),{childList:true,subtree:true});
    mount();refresh();window.addEventListener('gr:refresh',refresh);
    window.addEventListener('hashchange',()=>{capture();mount();render();if(location.hash==='#/history')refresh();});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
