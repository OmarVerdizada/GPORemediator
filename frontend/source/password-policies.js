/* Reviewed password-policy workspace. AD mutations remain server controlled. */
(() => {
  'use strict';
  function create({state,esc,api,run,render}){
    let plan=null,result=null,history=[],historyError='',error='',loadedKey=null,currentContext=null,pending=null,loadSequence=0,evidenceLimit=100;
    const draft={scopeDn:'',name:'GPOR-Users',precedence:100,passwordHistoryCount:24,minPasswordLength:14,minPasswordAgeDays:1,maxPasswordAgeDays:90,complexityEnabled:true,reversibleEncryptionEnabled:false,lockoutThreshold:5,lockoutDurationMinutes:15,lockoutObservationWindowMinutes:15};
    const fields=[
      ['precedence','Precedence',1,2147483647,'Lower numbers take precedence.'],
      ['passwordHistoryCount','Password history',0,1024,'Previous passwords remembered.'],
      ['minPasswordLength','Minimum length',0,255,'Characters per password.'],
      ['minPasswordAgeDays','Minimum age',0,998,'Days before a password can change.'],
      ['maxPasswordAgeDays','Maximum age',1,999,'Days before a password expires.'],
      ['lockoutThreshold','Lockout threshold',1,999,'Failed attempts before lockout.'],
      ['lockoutDurationMinutes','Lockout duration',1,99999,'Minutes an account remains locked.'],
      ['lockoutObservationWindowMinutes','Observation window',1,99999,'Minutes before failed attempts reset.']
    ];
    const context=()=>[state.inventory?.domain,state.inventory?.domainController,state.inventory?.executionUser].join('|').toLowerCase();
    function syncContext(){
      if(!state.inventory)return;
      const key=context();
      if(currentContext!==null&&currentContext!==key){plan=null;result=null;history=[];loadedKey=null;draft.scopeDn='';error='Connection changed. Create a fresh preview for this domain and execution account.';}
      currentContext=key;
    }
    function planContextMatches(){
      const i=state.inventory;
      return !!i&&['domain','domainController','executionUser'].every(key=>!plan?.[key]||!i[key]||String(plan[key]).toLowerCase()===String(i[key]).toLowerCase());
    }
    const canExecutePlan=()=>planContextMatches()&&!state.busy;
    const busy=()=>state.busy?' disabled':'';
    const scopes=()=>Array.isArray(state.inventory?.scopes)?state.inventory.scopes.filter(x=>String(x.kind).toUpperCase()==='OU'):[];
    const date=value=>{const d=new Date(value);return Number.isFinite(d.getTime())?d.toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'}):'Date unavailable';};
    const tone=value=>/FAIL|DRIFT|MISMATCH/.test(value||'')?'danger':/REVIEW|PENDING|UNAVAILABLE|OVERRIDDEN/.test(value||'')?'warning':/^(VERIFIED|ROLLED_BACK)$/.test(value||'')?'success':'neutral';
    const badge=value=>'<span data-policy-state="'+esc(value||'PREVIEW')+'" class="ps-badge ps-'+tone(value)+'">'+esc(String(value||'PREVIEW').replaceAll('_',' '))+'</span>';
    function field(name){
      const [,label,min,max,hint]=fields.find(x=>x[0]===name);
      return '<label for="ps-'+name+'">'+label+'<input id="ps-'+name+'" type="number" step="1" name="'+name+'" min="'+min+'" max="'+max+'" value="'+draft[name]+'" required aria-describedby="ps-'+name+'-hint"><small id="ps-'+name+'-hint">'+hint+'</small></label>';
    }
    function membership(){
      const m=plan?.preview?.membership;if(!m)return '';
      const lists=[['Add',m.add],['Remove',m.remove],['Moved within OU',m.moved],['Departed since last applied snapshot',m.departed]];
      return '<section class="ps-membership"><h3>OU membership comparison</h3><p>'+Number(m.currentSubjects||0)+' existing subjects → '+Number(m.desiredUsers||0)+' enabled users. '+Number(m.unchanged||0)+' unchanged.</p><p>Only an explicitly approved Apply changes assignments. Moving a user in AD does not update this PSO automatically.</p>'+(!m.baselineAvailable?'<p>No previously applied user snapshot is available; current PSO subjects are still compared.</p>':'')+lists.map(([label,items])=>'<details class="ps-details"><summary>'+label+' ('+(items||[]).length+')</summary><ul class="ps-user-list">'+(items||[]).slice(0,100).map(u=>'<li><strong>'+esc(u.name||u.dn||u.guid)+'</strong><small>'+esc(u.reason||u.afterDn||u.dn||'')+'</small>'+(u.beforeDn?'<small>Previous: '+esc(u.beforeDn)+'</small>':'')+'</li>').join('')+'</ul>'+((items||[]).length>100?'<p>First 100 shown; download evidence for the full comparison.</p>':'')+'</details>').join('')+'</section>';
    }
    function snapshot(){
      if(!plan)return '';
      const users=Array.isArray(plan.preview?.users)?plan.preview.users:[];
      const preview={requested:plan.request,previousPolicy:plan.preview?.before,warnings:plan.preview?.warnings||[]};
      return '<section id="fgpp-review" class="content-card ps-review"><div class="ps-section-heading"><div><span class="eyebrow">REVIEWED SNAPSHOT</span><h2>'+esc(plan.request.name)+'</h2></div>'+badge('PREVIEW')+'</div>'+
        '<dl class="ps-facts"><div><dt>Users in snapshot</dt><dd>'+users.length.toLocaleString('en-GB')+'</dd></div><div><dt>Execution account</dt><dd>'+esc(plan.executionUser)+'</dd></div><div class="ps-full"><dt>OU</dt><dd>'+esc(plan.request.scopeDn)+'</dd></div></dl>'+
        '<p>Review the complete policy and user snapshot before applying. Preview expires after 10 minutes; Apply rechecks OU membership and the previous policy.</p>'+
        '<details class="ps-details"><summary>Requested values, warnings and previous policy</summary><pre>'+esc(JSON.stringify(preview,null,2))+'</pre></details>'+
        '<details class="ps-details"><summary>Users in this snapshot ('+users.length+')</summary><ul class="ps-user-list">'+users.slice(0,100).map(u=>'<li><strong>'+esc(u.name)+'</strong><small>'+esc(u.dn||'')+'</small></li>').join('')+'</ul>'+(users.length>100?'<p>Showing the first 100 users. Download the full evidence for every user.</p>':'')+'</details>'+
        membership()+'<button type="button" data-fgpp-reconcile'+(canExecutePlan()?'':' disabled')+'>Compare current OU membership</button><p class="ps-footnote">Creates a fresh read-only preview; review and confirm APPLY FGPP to reconcile.</p>'+
        '<form id="fgpp-action"><p class="ps-footnote">'+(planContextMatches()?'':'Reconnect to the recorded domain, DC and execution account to run actions on this snapshot.')+'</p><label for="ps-confirmation">Explicit confirmation<input id="ps-confirmation" name="confirmation" autocomplete="off" spellcheck="false" placeholder="APPLY FGPP or ROLLBACK FGPP" aria-describedby="ps-confirmation-help"></label><small id="ps-confirmation-help">Type APPLY FGPP to apply, or ROLLBACK FGPP to restore this operation. Verify is read-only.</small>'+
        '<div class="ps-actions"><button class="primary" name="action" value="apply" disabled>Apply approved snapshot</button><button name="action" value="verify"'+(canExecutePlan()?'':' disabled')+'>Verify resultant policies</button><button class="ps-rollback" name="action" value="rollback" disabled>Roll back</button><button type="button" data-fgpp-export'+busy()+'>Download evidence</button></div></form>'+
        '<p class="ps-footnote">Writes require the enabled change gate and this OU in Settings → Authorized OU / domain DNs. External changes block automatic rollback.</p></section>';
    }
    function evidence(){
      if(!result)return '';
      const users=Array.isArray(result.users)?result.users:[];
      return '<section id="fgpp-result" class="content-card ps-result" role="status"><div class="ps-section-heading"><h2>Result and evidence</h2>'+badge(result.state)+'</div><p>'+esc(result.message)+'</p>'+
        (users.length?'<div class="ent-table-wrap ps-evidence-table" tabindex="0" role="region" aria-label="Resultant user policies"><table class="ent-table"><thead><tr><th scope="col">Account</th><th scope="col">Resultant policy</th><th scope="col">Status</th></tr></thead><tbody>'+users.slice(0,evidenceLimit).map(u=>'<tr><td>'+esc(u.user||u.name||'Unknown')+'</td><td>'+esc(u.policy||'Unavailable')+'</td><td>'+badge(u.state)+'</td></tr>').join('')+'</tbody></table></div><div class="ps-evidence-footer"><small>Showing '+Math.min(evidenceLimit,users.length)+' of '+users.length+' users</small>'+(users.length>evidenceLimit?'<button type="button" data-fgpp-more'+busy()+'>Show 100 more</button>':'')+'</div>':'')+
        '<details class="ps-details"><summary>Policy details and backup location</summary><pre>'+esc(JSON.stringify({policy:result.policy,backupDirectory:result.backupDirectory},null,2))+'</pre></details></section>';
    }
    function view(){
      syncContext();
      const available=scopes(),connected=!!state.inventory;
      return '<header class="page-header ps-page-header"><div><span class="page-kicker">DOMAIN USER SECURITY</span><h1>OU password policies</h1><p>Prepare a fine-grained password policy for domain users in an OU, then review and verify the result.</p></div><a class="ps-settings-link" href="#/settings">Connection & permissions →</a></header>'+
        (error?'<div class="ps-alert ps-danger" role="alert">'+esc(error)+'</div>':'')+
        '<div class="ps-workspace"><section class="content-card ps-editor"><div class="ps-section-heading"><div><span class="eyebrow">01 · READ-ONLY PREVIEW</span><h2>Configure the policy</h2></div>'+badge(connected?'CONNECTED':'NOT CONNECTED')+'</div>'+
        (!connected?'<p class="ps-alert">Connect a domain account on Dashboard to discover OUs.</p>':'')+
        '<form id="fgpp-preview"><fieldset'+(state.busy||!connected?' disabled':'')+'><legend>Policy identity</legend><div class="ps-field-grid"><label for="ps-scope">OU<select id="ps-scope" name="scopeDn" required><option value="">Choose a discovered OU</option>'+available.map(x=>'<option value="'+esc(x.dn)+'"'+(x.dn===draft.scopeDn?' selected':'')+'>'+esc((x.name||'OU')+' — '+x.dn)+'</option>').join('')+'</select><small>Enabled users in this OU and its child OUs.</small></label><label for="ps-name">Managed policy name<input id="ps-name" name="name" value="'+esc(draft.name)+'" pattern="[A-Za-z]([A-Za-z0-9_.]|-){2,63}" required minlength="3" maxlength="64" spellcheck="false" autocomplete="off"><small>3–64 characters: letters, numbers, dots, underscores or hyphens.</small></label>'+field('precedence')+'</div></fieldset>'+
        '<fieldset'+(state.busy||!connected?' disabled':'')+'><legend>Password requirements</legend><div class="ps-field-grid">'+['passwordHistoryCount','minPasswordLength','minPasswordAgeDays','maxPasswordAgeDays'].map(field).join('')+'</div><label class="ps-checkbox"><input type="checkbox" name="complexityEnabled"'+(draft.complexityEnabled?' checked':'')+'> Require password complexity</label><label class="ps-checkbox"><input type="checkbox" name="reversibleEncryptionEnabled"'+(draft.reversibleEncryptionEnabled?' checked':'')+'> Store passwords with reversible encryption</label></fieldset>'+
        '<fieldset'+(state.busy||!connected?' disabled':'')+'><legend>Account lockout</legend><div class="ps-field-grid">'+['lockoutThreshold','lockoutDurationMinutes','lockoutObservationWindowMinutes'].map(field).join('')+'</div></fieldset>'+
        '<div class="ps-actions"><button class="primary"'+(state.busy||!connected?' disabled':'')+'>Generate read-only preview</button><small>No policy is changed at this stage.</small></div></form></section>'+
        '<aside class="ps-guidance" aria-label="Policy scope guidance"><section class="content-card"><span class="eyebrow">SCOPE & PERMISSIONS</span><h2>Before you apply</h2><ul><li><strong>Domain users.</strong> This policy changes domain account passwords and lockout. A GPO on a OU controls local accounts.</li><li><strong>A reviewed snapshot.</strong> New or moved users need a fresh preview and Apply to reconcile membership.</li><li><strong>Separate delegation.</strong> PSO permissions on the Password Settings Container are separate from GPO Edit settings and Link GPOs.</li><li><strong>Precedence matters.</strong> A competing password policy can override this one. Verify checks the resultant policy.</li></ul></section></aside></div>'+
        snapshot()+evidence()+
        '<section class="content-card ps-history"><div class="ps-section-heading"><div><span class="eyebrow">RECORDED OPERATIONS</span><h2>Password policy history</h2></div><button data-fgpp-history'+busy()+'>Reload history</button></div>'+
        (historyError?'<p class="ps-alert ps-warning" role="alert">'+esc(historyError)+'</p>':'')+
        (history.length?'<ul class="ps-history-list">'+history.map(x=>'<li><button data-fgpp-open="'+esc(x.plan.id)+'"'+busy()+'><strong>'+esc(x.plan.request.name)+'</strong><small>'+esc(x.plan.request.scopeDn)+' · '+esc(date(x.plan.createdAt))+'</small></button>'+badge(x.result?.state||'PREVIEW')+'</li>').join('')+'</ul>':'<div class="ps-empty"><strong>No password policy operations recorded</strong><p>Create a read-only preview to start a reviewed operation.</p></div>')+'</section>';
    }
    async function load(){
      syncContext();
      const key=context();
      if(pending?.key===key)return pending.promise;
      const sequence=++loadSequence;historyError='';
      const promise=(async()=>{
        try{
          const entries=await api('/password-policies');
          if(!Array.isArray(entries))throw Error('Password policy history could not be loaded. Check the connection and retry.');
          if(sequence===loadSequence&&key===context()){history=entries.filter(x=>x?.plan?.id&&x.plan.request);loadedKey=key;}
        }catch(e){if(sequence===loadSequence){historyError=e.message||'History is unavailable. Retry when the service is ready.';loadedKey=null;}}
        finally{if(sequence===loadSequence)pending=null;}
      })();
      pending={key,promise};return promise;
    }
    function dispatch(action){
      if(state.busy)return;
      error='';
      return run(async()=>{try{await action();}catch(e){error=e.message||'The operation could not finish. Verify its recorded state before retrying.';throw e;}});
    }
    function handleClick(e){
      const button=e.target.closest('[data-fgpp-history],[data-fgpp-open],[data-fgpp-more],[data-fgpp-export],[data-fgpp-reconcile]');
      if(!button)return false;
      if(state.busy)return true;
      if(button.hasAttribute('data-fgpp-history'))dispatch(load);
      if(button.hasAttribute('data-fgpp-reconcile')&&plan&&canExecutePlan())dispatch(async()=>{plan=await api('/password-policies/'+plan.id+'/reconcile-preview',{});result=null;evidenceLimit=100;await load();});
      if(button.hasAttribute('data-fgpp-more')){evidenceLimit+=100;render();}
      if(button.hasAttribute('data-fgpp-open')){
        const entry=history.find(x=>x.plan.id===button.dataset.fgppOpen);
        if(entry){plan=entry.plan;result=entry.result;evidenceLimit=100;error='';Object.assign(draft,plan.request);render();document.getElementById('fgpp-review')?.scrollIntoView({block:'start',behavior:'instant'});}
      }
      if(button.hasAttribute('data-fgpp-export')&&plan){
        const url=URL.createObjectURL(new Blob([JSON.stringify({plan,result},null,2)],{type:'application/json'})),link=document.createElement('a');
        link.href=url;link.download='password-policy-'+plan.id+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
      }
      return true;
    }
    function capture(form){
      draft.scopeDn=form.elements.scopeDn.value;draft.name=form.elements.name.value;
      for(const [name] of fields)draft[name]=Number(form.elements[name].value);
      draft.complexityEnabled=form.elements.complexityEnabled.checked;draft.reversibleEncryptionEnabled=form.elements.reversibleEncryptionEnabled.checked;
      form.elements.minPasswordAgeDays.setCustomValidity(draft.minPasswordAgeDays>=draft.maxPasswordAgeDays?'Minimum password age must be lower than maximum age.':'');
      form.elements.lockoutObservationWindowMinutes.setCustomValidity(draft.lockoutObservationWindowMinutes>draft.lockoutDurationMinutes?'Observation window must not exceed lockout duration.':'');
      for(const input of [form.elements.minPasswordAgeDays,form.elements.lockoutObservationWindowMinutes])
        if(input.hasAttribute('aria-invalid'))window.GpoPreferences?.validate(input,state);
    }
    function handleInput(e){
      if(e.target.closest('#fgpp-action')&&e.target.name==='confirmation'){
        const text=e.target.value,form=e.target.form;
        form.querySelector('[value=apply]').disabled=!canExecutePlan()||text!=='APPLY FGPP';
        form.querySelector('[value=rollback]').disabled=!canExecutePlan()||text!=='ROLLBACK FGPP';return true;
      }
      if(!e.target.closest('#fgpp-preview'))return false;
      capture(e.target.form);plan=null;result=null;error='';
      document.getElementById('fgpp-review')?.remove();document.getElementById('fgpp-result')?.remove();return true;
    }
    function handleSubmit(e){
      if(e.target.id==='fgpp-preview'){
        e.preventDefault();if(state.busy)return true;capture(e.target);
        if(!e.target.reportValidity())return true;
        const request={...draft};
        dispatch(async()=>{plan=await api('/password-policies/preview',request);result=null;evidenceLimit=100;await load();});
        return true;
      }
      if(e.target.id==='fgpp-action'){
        e.preventDefault();const action=e.submitter?.value;
        if(!canExecutePlan()||!plan||!['apply','verify','rollback'].includes(action))return true;
        const id=plan.id,confirmation=e.target.elements.confirmation.value;
        if(action!=='verify'&&confirmation!==(action==='apply'?'APPLY FGPP':'ROLLBACK FGPP'))return true;
        dispatch(async()=>{result=await api('/password-policies/'+id+'/'+action,{confirmation});evidenceLimit=100;await load();});return true;
      }
      return false;
    }
    return {view,handleClick,handleInput,handleSubmit,load:()=>loadedKey===context()?Promise.resolve():load()};
  }
  window.GpoPasswordPolicies={create};
})();
