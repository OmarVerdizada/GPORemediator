/* Fine-grained password policies: an explicit, reviewed OU user snapshot. */
(() => {
  'use strict';
  function create({state,esc,api,run,render}){
    let plan=null,result=null,history=[],loaded=false;
    const draft={scopeDn:'',name:'GPOR-Users',precedence:100,passwordHistoryCount:24,minPasswordLength:14,minPasswordAgeDays:1,maxPasswordAgeDays:90,complexityEnabled:true,reversibleEncryptionEnabled:false,lockoutThreshold:5,lockoutDurationMinutes:15,lockoutObservationWindowMinutes:15};
    const fields=[['precedence','Precedence (lower number wins)',1,2147483647],['passwordHistoryCount','Password history',0,1024],['minPasswordLength','Minimum password length',0,255],['minPasswordAgeDays','Minimum age (days)',0,998],['maxPasswordAgeDays','Maximum age (days)',1,999],['lockoutThreshold','Lockout threshold',1,999],['lockoutDurationMinutes','Lockout duration (minutes)',1,99999],['lockoutObservationWindowMinutes','Lockout observation (minutes)',1,99999]];
    function view(){
      const scopes=(state.inventory?.scopes||[]).filter(x=>String(x.kind).toUpperCase()==='OU');
      return `<section class="content-card"><span class="eyebrow">DOMAIN USER PASSWORD POLICY</span><h1>OU password policies</h1><p>Use a fine-grained password policy (PSO) for domain users in one OU. A GPO linked to an OU controls computer local accounts; it does not change those users' domain passwords.</p><p>This workflow assigns a policy directly to a reviewed snapshot of enabled users in the OU and child OUs. Re-preview and apply to reconcile users added or moved later. PSO permissions on the Password Settings Container are separate from GPO delegation.</p><form id="fgpp-preview"><div class="gr-auto-grid"><label class="gr-auto-field">User OU<select name="scopeDn" required><option value="">Choose a discovered OU</option>${scopes.map(x=>`<option value="${esc(x.dn)}" ${x.dn===draft.scopeDn?'selected':''}>${esc(x.name||x.dn)}</option>`).join('')}</select></label><label class="gr-auto-field">Managed policy name<input name="name" value="${esc(draft.name)}" pattern="[A-Za-z][A-Za-z0-9_.-]{2,63}" required maxlength="64"></label>${fields.map(([name,label,min,max])=>`<label class="gr-auto-field">${label}<input type="number" step="1" name="${name}" min="${min}" max="${max}" value="${draft[name]}" required></label>`).join('')}<label><input type="checkbox" name="complexityEnabled" ${draft.complexityEnabled?'checked':''}> Require password complexity</label><label><input type="checkbox" name="reversibleEncryptionEnabled" ${draft.reversibleEncryptionEnabled?'checked':''}> Store passwords with reversible encryption</label></div><button class="primary" ${state.busy?'disabled':''}>Generate read-only preview</button></form></section>
      ${plan?`<section id="fgpp-review" class="content-card"><h2>Reviewed user snapshot</h2><p><b>${esc(plan.request.name)}</b> · ${esc(plan.request.scopeDn)} · ${plan.preview.users.length} users · ${esc(plan.executionUser)}</p><p>Preview expires after 10 minutes. Apply checks membership and previous policy again before writing. Other password policies may take precedence.</p><details><summary>Users, values, warnings and previous policy</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(JSON.stringify(plan.preview,null,2))}</pre></details><form id="fgpp-action"><label class="gr-auto-field">Explicit confirmation<input name="confirmation" autocomplete="off" placeholder="APPLY FGPP or ROLLBACK FGPP"></label><button name="action" value="apply" ${state.busy?'disabled':''}>Apply approved snapshot</button><button name="action" value="verify" ${state.busy?'disabled':''}>Verify resultant policies</button><button name="action" value="rollback" ${state.busy?'disabled':''}>Roll back this operation</button></form><p>Writes require the enabled change gate and this OU in Settings → Authorized OU / domain DNs. Rollback restores the managed policy's previous values and subjects; external changes block automatic recovery.</p></section>`:''}
      ${result?`<section id="fgpp-result" class="content-card" role="status"><h2>${esc(result.state)}</h2><p>${esc(result.message)}</p><details><summary>Per-user evidence</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(JSON.stringify(result,null,2))}</pre></details></section>`:''}
      <section class="content-card"><h2>Password policy operations</h2><button data-fgpp-history ${state.busy?'disabled':''}>Reload history</button>${history.map(x=>`<p><button data-fgpp-open="${esc(x.plan.id)}">${esc(x.plan.request.name)} · ${esc(x.plan.createdAt)}</button> · ${esc(x.result?.state||'PREVIEW')}</p>`).join('')}</section>`;
    }
    async function load(){history=await api('/password-policies');loaded=true;}
    function handleClick(e){
      if(e.target.closest('[data-fgpp-history]')){run(load);return true;}
      const open=e.target.closest('[data-fgpp-open]');
      if(open){const entry=history.find(x=>x.plan.id===open.dataset.fgppOpen);if(entry){plan=entry.plan;result=entry.result;Object.assign(draft,plan.request);render();}return true;}
      return false;
    }
    function handleInput(e){
      if(!e.target.closest('#fgpp-preview'))return false;
      const f=e.target.form;draft.scopeDn=f.elements.scopeDn.value;draft.name=f.elements.name.value;
      for(const [name] of fields)draft[name]=Number(f.elements[name].value);
      draft.complexityEnabled=f.elements.complexityEnabled.checked;draft.reversibleEncryptionEnabled=f.elements.reversibleEncryptionEnabled.checked;
      plan=null;result=null;document.getElementById('fgpp-review')?.remove();document.getElementById('fgpp-result')?.remove();return true;
    }
    function handleSubmit(e){
      if(e.target.id==='fgpp-preview'){e.preventDefault();handleInput({target:e.target.elements.name});run(async()=>{plan=await api('/password-policies/preview',{...draft});result=null;await load();});return true;}
      if(e.target.id==='fgpp-action'){e.preventDefault();const action=e.submitter?.value;if(!plan||!['apply','verify','rollback'].includes(action))return true;const id=plan.id,confirmation=e.target.elements.confirmation.value;run(async()=>{result=await api('/password-policies/'+id+'/'+action,{confirmation});await load();});return true;}
      return false;
    }
    return {view,handleClick,handleInput,handleSubmit,load:()=>loaded?Promise.resolve():load()};
  }
  window.GpoPasswordPolicies={create};
})();
