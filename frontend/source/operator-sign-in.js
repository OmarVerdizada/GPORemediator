/* One explicit sign-in opens the workspace and its delegated AD connection. */
(() => {'use strict';
let pending=null,reloading=false;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const say=(az,en)=>window.GpoClient.storage.get('gr-lang','az')==='az'?az:en;
async function session(){const response=await fetch('/api/session',{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(15000),headers:{Accept:'application/json'}});if(!response.ok)throw new Error(say('Windows girişini və operator icazənizi yoxlayın.','Check Windows sign-in and operator permissions.'));return response.json();}
function prompt(initial){return new Promise(resolve=>{
 const root=document.getElementById('root');root.inert=true;root.hidden=true;
 const overlay=document.createElement('div');overlay.className='operator-sign-in';overlay.setAttribute('role','dialog');overlay.setAttribute('aria-modal','true');overlay.setAttribute('aria-labelledby','operator-sign-in-title');
 let current=initial;
 overlay.innerHTML=`<form class="operator-sign-in-card"><span class="operator-sign-in-emblem" aria-hidden="true">◇</span><span class="card-kicker">GPO REMEDIATOR</span><h1 id="operator-sign-in-title"></h1><p data-sign-in-copy></p><label><span data-account-label></span><input name="actor" autocomplete="username" maxlength="256" required></label><label>${say('Parol','Password')}<input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label><p class="operator-sign-in-error" role="alert"></p><button class="primary" type="submit"></button><small data-sign-in-note></small></form>`;
 document.body.append(overlay);const form=overlay.querySelector('form'),account=form.elements.actor,password=form.elements.password,button=form.querySelector('button'),error=form.querySelector('[role=alert]');
 function configure(){
  const domain=current?.domainSignIn===true;
  overlay.querySelector('h1').textContent=domain?say('Domen hesabı ilə daxil olun','Sign in with your domain account'):say('Girişinizi təsdiqləyin','Confirm your sign-in');
  overlay.querySelector('[data-sign-in-copy]').textContent=domain?say('Bir giriş kifayətdir: bu hesabla AD bağlantısı yaradılır və GPO əməliyyatları icra olunur.','One sign-in opens your AD connection and supplies the account for GPO operations.'):say('İlkin sazlamaları açmaq üçün Windows hesabınızın parolunu təsdiqləyin.','Confirm your Windows password to open initial configuration.');
  overlay.querySelector('[data-account-label]').textContent=domain?say('Domen hesabı (DOMAIN\\user və ya user@domain)','Domain account (DOMAIN\\user or user@domain)'):say('Windows hesabı','Windows account');
  account.readOnly=!domain;account.tabIndex=domain?0:-1;account.value=current?.operator||'';
  password.disabled=!current;password.required=!!current;
  button.textContent=!current?say('Yenidən yoxla','Retry'):domain?say('Daxil ol və AD-yə qoşul','Sign in and connect to AD'):say('Təsdiqlə və daxil ol','Confirm and enter');
  overlay.querySelector('[data-sign-in-note]').textContent=domain?say('Parol diskə yazılmır. Bağlantı aktiv olduğu müddətdə təkrar tələb olunmur. Xidmət restartı və ya sessiyanın bitməsi yenidən giriş tələb edir.','The password is not saved to disk. It is reused while the connection is active. A service restart or session expiry requires sign-in again.'):say('Sazlamaları yalnız icazəli Windows operatoru dəyişə bilər.','Only an authorized Windows operator can change configuration.');
 }
 configure();
 if(!current)error.textContent=say('Sessiya alınmadı. Xidmət və Windows girişini yoxlayıb yenidən sınayın.','Session unavailable. Check the service and Windows sign-in, then retry.');
 overlay.addEventListener('keydown',e=>{if(e.key==='Tab'){const items=[...form.querySelectorAll('input:not([readonly]),button')].filter(x=>!x.disabled),first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}});
 form.addEventListener('submit',async e=>{e.preventDefault();if(button.disabled)return;button.disabled=true;error.textContent='';
  try{
   if(!current){current=await session();configure();if(current.operatorConfirmationRequired!==true){finish();return;}password.focus();return;}
   const body=JSON.stringify({password:password.value,...(current.domainSignIn?{userName:account.value.trim().replaceAll('/','\\')}:{})});password.value='';
   const response=await fetch('/api/operator/sign-in',{method:'POST',credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(110000),headers:{Accept:'application/json','Content-Type':'application/json','X-CSRF-Token':current.csrfToken||''},body});
   if(!response.ok){if(response.status===429)throw new Error(say('Çox cəhd edildi. Bir dəqiqə gözləyin; yanlış parol hesabı kilidləyə bilər.','Too many attempts. Wait a minute; incorrect passwords can lock your account.'));let detail;try{detail=await response.json();}catch{}throw new Error(detail?.message||say('Giriş alınmadı. Hesabı, parolu və DC bağlantısını yoxlayın.','Sign-in failed. Check the account, password and DC connection.'));}
   current=await session();if(current.operatorConfirmationRequired===true)throw new Error(say('Giriş cookie-si qəbul edilmədi. Brauzer sazlamalarını yoxlayın.','Sign-in cookie was not accepted. Check browser settings.'));
   // No password is retained in browser memory or replayed after restart.
   window.GpoClient.ephemeralCredential.clear();finish();
  }catch(ex){error.textContent=ex.message;password.value='';try{const next=await session();if(next.domainSignIn!==current?.domainSignIn){current=next;configure();}else current=next;}catch{current=null;}password.focus();}finally{button.disabled=false;}
 });
 function finish(){password.value='';overlay.remove();root.hidden=false;root.inert=false;resolve();}
 (current?password:button).focus();
});}
function ensure(force=false){if(!pending)pending=(async()=>{let current;try{current=await session();}catch{return prompt(null);}if(force||current.operatorConfirmationRequired===true)await prompt(current);})().finally(()=>{pending=null;});return pending;}
function reconfirm(){if(reloading)return;reloading=true;ensure().then(()=>location.reload());}
window.GpoOperatorSignIn=Object.freeze({ensure,reconfirm,open:()=>ensure(true)});
})();
