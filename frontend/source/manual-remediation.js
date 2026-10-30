/* Standalone manual procedures; rendering/copying never submits a domain job. */
(()=>{'use strict';
const quote=value=>`'${String(value??'').replaceAll("'","''")}'`;
const placeholder=name=>'REPLACE_WITH_'+name;
const writable=m=>m?.automation==='Automated'&&m.handler!=='Manual';
function mappingFor(s,r){return s.settings?.find(m=>m.id===(r.backendSetting||r.id))||window.GpoManualEngine?.mappings.find(m=>m.id===(r.backendSetting||r.id));}
function context(s,r,m){
 const selected=s.selection?.setting===(r.backendSetting||r.id)?s.selection:{};
 const connectedMapping=s.settings?.some(x=>x.id===m.id);
 return {domain:s.inventory?.domain||placeholder('DOMAIN'),dc:s.inventory?.domainController||placeholder('WRITABLE_DC'),gpo:selected.gpoId||placeholder('GPO_GUID'),target:selected.scopeDn||placeholder(m.domainPolicySensitive?'DOMAIN_DN':m.scope==='User'?'USER_OU_DN':'COMPUTER_OU_DN'),value:m.allowValueOverride?((connectedMapping?selected.value:null)??m.suggested??0):0,custom:m.requiresInput?(selected.customValue??m.inputDefault??''):'',first:!!selected.firstLink};
}
function generate(s,r,action='Preview'){
 const original=mappingFor(s,r);if(!original)return null;
 const selection=s.selection?.setting===(r.backendSetting||r.id)?s.selection:{};
 const pendingReview=!writable(original)&&(!selection.reviewContext||selection.reviewContext.trim().length<10);
 const effective=window.GpoValueEditor?.effective(original,pendingReview?{...selection,itemValues:null}:selection)||original;
 const m={...effective,items:effective.items.map(x=>({section:null,key:null,name:null,type:'String',value:null,guid:null,state:null,mask:null,...x}))};
 const c=context(s,r,m),engine=window.GpoManualEngine;
 const guide=window.GpoRemediationGuides?.get(r.id);
 if(guide&&!writable(m))return {mapping:m,context:c,writable:false,guide:true,script:guide.read};
 if(!writable(m))return {mapping:m,context:c,writable:false,script:`# Review-only control ${r.id}. No automatic write recipe is published.\n& {\n  $ErrorActionPreference = 'Stop'\n  $DomainName = ${quote(c.domain)}\n  $DomainController = ${quote(c.dc)}\n  $GpoId = ${quote(c.gpo)}\n  if ($DomainName -like 'REPLACE_*' -or $DomainController -like 'REPLACE_*' -or $GpoId -like 'REPLACE_*') { throw 'Choose the domain, writable DC and GPO first' }\n  Import-Module GroupPolicy -ErrorAction Stop\n  Get-GPOReport -Guid ([guid]$GpoId) -Domain $DomainName -Server $DomainController -ReportType Xml\n}\n# Review the role-specific guidance and edit the approved policy in GPMC.\n# gpmc.msc`};
 if(!engine)return null;
 const fields={DOMAIN:quote(c.domain),DC:quote(c.dc),GPO:quote(c.gpo),TARGET:quote(c.target),VALUE:String(Number.isFinite(Number(c.value))?Number(c.value):0),CUSTOM:quote(c.custom),FIRST:c.first?'$true':'$false',MAPPING:quote(JSON.stringify(m)),FUNCTIONS:engine.functions};
 let script=engine.template.replace(/__GR_([A-Z]+)__/g,(_,key)=>fields[key]);
 if(action==='Apply')script=script.replace("$Action = 'Preview'","$Action = 'Apply'");
 return {mapping:m,context:c,writable:true,script};
}
function check(s,r,generated){
 const {mapping:m,context:c}=generated;
 if(m.domainPolicySensitive){
  const properties={'1.1.1':'PasswordHistoryCount','1.1.3':'MinPasswordAge','1.1.4':'MinPasswordLength','1.1.5':'ComplexityEnabled','1.1.6':'ReversibleEncryptionEnabled','1.2.1':'LockoutDuration','1.2.2':'LockoutThreshold','1.2.4':'LockoutObservationWindow'};
  return `Import-Module ActiveDirectory -ErrorAction Stop\nGet-ADDefaultDomainPasswordPolicy -Identity ${quote(c.domain)} -Server ${quote(c.dc)} | Format-List ${properties[m.id]||'*'}`;
 }
 const settings=[m],selection={...s.selection,setting:m.id};
 return window.GpoComponents.manualCheck({...s,settings},{plan:{selection}},null);
}
function render(s,r){
 const action=s.manualScriptAction==='Apply'?'Apply':'Preview';let g;
 try{g=generate(s,r,action)}catch(error){return `<section class="manual-procedure" data-manual-procedure="${window.GpoComponents.esc(r.id)}"><p>${window.GpoComponents.esc(error.message)}</p></section>`}
 if(!g)return '';
 const {esc,text}=window.GpoComponents,t=(_fallback,en)=>text(s,_fallback,en),c=g.context,m=g.mapping;
 if(g.guide)return `<div data-manual-procedure="${esc(r.id)}">${window.GpoRemediationGuides.render(r.id,{state:s,esc,say:t})}</div>`;
 const ready=![c.domain,c.dc,c.gpo,c.target].some(v=>v.startsWith('REPLACE_'))&&(!m.requiresInput||!!c.custom.trim());
 const endpoint=check(s,r,g),mode=g.writable?action:'Review';
 const values=m.items.map(item=>{const desired=!g.writable?(m.recommended||'Review role guidance'):m.requiresInput?(c.custom||'Enter an organization value'):m.allowValueOverride?String(c.value):m.handler==='AdvancedAudit'?`${item.state} · mask ${item.mask}`:(item.value||[]).join(', ')||'Explicit empty value';return `<tr><td><strong>${esc(item.name||item.key||item.guid)}</strong><small>${esc(item.section||item.key||item.guid||'')}</small></td><td data-label="${'Type'}">${esc(m.handler==='AdvancedAudit'?'Audit mask · CSV':item.type)}</td><td data-label="${'Requested value'}"><strong>${esc(desired)}</strong><small>${esc(item.comparator||m.comparator||'=')}</small></td></tr>`;}).join('');
 const facts=[['Domain / DC',`${c.domain} · ${c.dc}`],['Selected GPO',s.inventory?.gpos?.find(x=>x.id.toLowerCase()===c.gpo.toLowerCase())?.name||c.gpo],['Policy target',c.target],['Policy setting',`${m.scope} · ${m.handler} · ${r.id}`]];
 return `<section class="manual-procedure" data-manual-procedure="${esc(r.id)}"><header class="manual-procedure-head"><span class="manual-procedure-icon" aria-hidden="true">&gt;_</span><div><span class="eyebrow">POWERSHELL · ${esc(r.id)}</span><h2>${'Inspect the script and run it yourself'}</h2><p>${'The full script is visible here. Copy it into Windows PowerShell 5.1 on the selected writable DC.'}</p></div><span class="manual-mode ${g.writable&&action==='Apply'?'write':''}">${mode==='Preview'?'Read-only':mode==='Apply'?'Write script':'Manual review'}</span></header><dl class="manual-context">${facts.map(([k,v])=>`<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>
 ${g.writable?`<ol class="manual-phases">${['Review target and value','Full GPO backup','Confirm and apply','Read back the GPO'].map((x,i)=>`<li><b>${i+1}</b>${x}</li>`).join('')}</ol><p class="manual-boundary">${'Includes the application’s actual writer functions; no application/API or internet is required. Viewing, copying and downloading change nothing. Manual execution uses your Windows identity and is not recorded in application history.'}</p>`:`<p class="manual-boundary">${'This control requires manual/role-specific review. No automatic write script is published; use the read-only report and dedicated guidance.'}</p>`}
 ${!ready?`<p class="manual-target-needed">${'Template shown. Choose GPO/OU and required values in Target & apply, or fill in the REPLACE_WITH fields at the top of the script.'} <button type="button" data-control-start>${'Choose target'} →</button></p>`:''}
 ${m.items.length?`<details class="manual-mapping" open><summary>${'Policy fields and selected values'} · ${m.items.length}</summary><div class="manual-mapping-scroll"><table><thead><tr><th>${'Setting / path'}</th><th>${'Type'}</th><th>${'Requested value'}</th></tr></thead><tbody>${values}</tbody></table></div></details>`:''}
 <div class="manual-code-toolbar">${g.writable?`<div class="manual-mode-switch" role="group" aria-label="${'Script mode'}">${['Preview','Apply'].map(x=>`<button type="button" data-manual-action="${x}" aria-pressed="${action===x}">${x==='Preview'?'1 · Preview script':'2 · Apply script'}</button>`).join('')}</div>`:`<strong>${'GPO report · read-only'}</strong>`}<div class="manual-code-actions"><button type="button" data-copy-value="${esc(g.script)}">${'Copy full script'}</button><button type="button" data-manual-download="${esc(r.id)}-${mode}.ps1" aria-label="${'Download PowerShell file'}">↓ .ps1</button></div></div>
 ${g.writable&&action==='Apply'?`<p class="manual-write-note">${'This mode changes the GPO and selected link and affects every existing link. Before backup, the script requires confirmation using the control ID + GPO GUID. gpupdate is a separate step.'}</p>`:''}
 <pre class="manual-script-source" tabindex="0" aria-label="${'Full PowerShell script'}"><code>${esc(g.script)}</code></pre><footer class="manual-code-footer"><span>Windows PowerShell 5.1 · ${g.script.split('\n').length} ${'lines'}</span><span>${'Current Windows identity · no password in script'}</span></footer>
 <details class="manual-follow-up"><summary>${'Manual verification and refresh after execution'}</summary><p>${m.domainPolicySensitive?'Read domain account policy from the selected DC.':'Run this check on the target endpoint as Administrator; user policy requires the intended user session.'}</p><div class="manual-check-head"><strong>${'Read current value'}</strong><button type="button" data-copy-value="${esc(endpoint)}">${'Copy'}</button></div><pre tabindex="0"><code>${esc(endpoint)}</code></pre>${g.writable?`<p>${'Optionally refresh policy on the target endpoint. Refresh and value equality do not prove that the selected GPO won.'}</p><div class="manual-check-head"><strong>gpupdate /force</strong><button type="button" data-copy-value="gpupdate.exe /target:${m.scope==='User'?'user':'computer'} /force">${'Copy'}</button></div><pre><code>gpupdate.exe /target:${m.scope==='User'?'user':'computer'} /force</code></pre>`:''}</details></section>`;
}
window.GpoManualRemediation=Object.freeze({mappingFor,generate,render,check});
})();
