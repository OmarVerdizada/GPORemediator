/* Fresh proof per server process; Windows Negotiate and server-side roles stay mandatory. */
(() => {'use strict';
let pending=null,reloading=false;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const say=(az,en)=>window.GpoClient.storage.get('gr-lang','az')==='az'?az:en;
async function session(){const response=await fetch('/api/session',{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(15000),headers:{Accept:'application/json'}});if(!response.ok)throw new Error(say('Windows girişini və operator icazənizi yoxlayın.','Check Windows sign-in and operator permissions.'));return response.json();}
function prompt(initial){return new Promise(resolve=>{
 const root=document.getElementById('root');root.inert=true;root.hidden=true;
 const overlay=document.createElement('div');overlay.className='operator-sign-in';overlay.setAttribute('role','dialog');overlay.setAttribute('aria-modal','true');overlay.setAttribute('aria-labelledby','operator-sign-in-title');
 let current=initial;
 overlay.innerHTML=`<form class="operator-sign-in-card"><span class="operator-sign-in-emblem" aria-hidden="true">◇</span><span class="card-kicker">GPO REMEDIATOR · WINDOWS</span><h1 id="operator-sign-in-title">${say('Girişinizi təsdiqləyin','Confirm your sign-in')}</h1><p>${say('Proqramın bu başlanğıcı üçün Windows hesabınızın parolunu daxil edin. Eyni server sessiyasında refresh zamanı yenidən tələb olunmur.','Enter your Windows account password for this application start. Refreshing within the same server session does not ask again.')}</p><label>${say('Windows hesabı','Windows account')}<input name="actor" readonly tabindex="-1" autocomplete="username" value="${esc(current?.operator||'')}"></label><label>${say('Parol','Password')}<input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label><p class="operator-sign-in-error" role="alert"></p><button class="primary" type="submit">${say('Təsdiqlə və daxil ol','Confirm and enter')}</button><small>${say('Windows autentifikasiyası və rol yoxlaması qüvvədədir. Bu təsdiq AD/GPO icra hesabına qoşulmur. Parol saxlanılmır. Xidmət restart olsa yenidən təsdiq tələb olunur.','Windows authentication and role checks remain active. This does not connect a delegated AD/GPO account. The password is not stored. A service restart requires confirmation again.')}</small></form>`;
 document.body.append(overlay);const form=overlay.querySelector('form'),password=form.elements.password,button=form.querySelector('button'),error=form.querySelector('[role=alert]');
 if(!current){error.textContent=say('Sessiya alınmadı. Xidmət və Windows girişini yoxlayıb yenidən sınayın.','Session unavailable. Check the service and Windows sign-in, then retry.');password.required=false;password.disabled=true;button.textContent=say('Yenidən yoxla','Retry');}
 overlay.addEventListener('keydown',e=>{if(e.key==='Tab'){const items=[...form.querySelectorAll('input:not([readonly]),button')].filter(x=>!x.disabled),first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}});
 form.addEventListener('submit',async e=>{e.preventDefault();if(button.disabled)return;button.disabled=true;error.textContent='';
  try{
   if(!current){current=await session();form.elements.actor.value=current.operator||'';if(current.operatorConfirmationRequired!==true){finish();return;}password.disabled=false;password.required=true;button.textContent=say('Təsdiqlə və daxil ol','Confirm and enter');password.focus();return;}
   const body=JSON.stringify({password:password.value});password.value='';
   const response=await fetch('/api/operator/sign-in',{method:'POST',credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(15000),headers:{Accept:'application/json','Content-Type':'application/json','X-CSRF-Token':current.csrfToken||''},body});
   if(!response.ok){if(response.status===429)throw new Error(say('Çox cəhd edildi. Bir dəqiqə gözləyin; yanlış parol hesabı kilidləyə bilər.','Too many attempts. Wait a minute; incorrect passwords can lock your account.'));throw new Error(say('Təsdiq alınmadı. Windows parolunu və bağlantını yoxlayın. Təkrar səhv cəhdlər hesabı kilidləyə bilər.','Confirmation failed. Check your Windows password and connection. Repeated failures can lock your account.'));}
   // Verify the server accepted the cookie before unlocking the workspace.
   current=await session();if(current.operatorConfirmationRequired===true)throw new Error(say('Giriş cookie-si qəbul edilmədi. Brauzer sazlamalarını yoxlayın.','Sign-in cookie was not accepted. Check browser settings.'));finish();
  }catch(ex){error.textContent=ex.message;password.value='';try{current=await session();form.elements.actor.value=current.operator||'';}catch{current=null;}password.focus();}finally{button.disabled=false;}
 });
 function finish(){password.value='';overlay.remove();root.hidden=false;root.inert=false;resolve();}
 (current?password:button).focus();
});}
function ensure(){if(!pending)pending=(async()=>{let current;try{current=await session();}catch{return prompt(null);}if(current.operatorConfirmationRequired===true)await prompt(current);})().finally(()=>{pending=null;});return pending;}
function reconfirm(){if(reloading)return;reloading=true;ensure().then(()=>location.reload());}
window.GpoOperatorSignIn=Object.freeze({ensure,reconfirm});
})();
