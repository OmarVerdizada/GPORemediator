/* Operator-selected policy data. No registry paths, types or scope are editable. */
(()=>{'use strict';
function defaults(m){return m.items.map(x=>m.handler==='AdvancedAudit'?[String(x.mask)]:m.allowValueOverride?[String(m.suggested??0)]:(x.value||[]).map(String));}
function effective(m,s){
 if(!s?.itemValues)return m;
 if(m.automation!=='Automated'||m.handler==='Manual'||m.requiresInput||s.itemValues.length!==m.items.length)throw Error('Invalid custom policy values');
 const items=m.items.map((item,i)=>{
  let values=s.itemValues[i].map(String);const type=String(item.type||'String').toUpperCase();
  if(m.handler==='AdvancedAudit'){const mask=Number(values[0]);if(values.length!==1||!Number.isInteger(mask)||mask<0||mask>3)throw Error('Audit mask must be 0–3');return {...item,mask,state:['No Auditing','Success','Failure','Success and Failure'][mask],comparator:'=='};}
  if(type==='DWORD'||type==='INTEGER'){if(values.length!==1||!/^\d+$/.test(values[0]))throw Error('Enter an integer');const number=BigInt(values[0]);if(number>(type==='DWORD'?4294967295n:65535n))throw Error('Integer is out of range');values=[String(number)];}
  if(type==='PRINCIPALS')values=values.map(x=>x.trim());
  return {...item,value:values,comparator:['DWORD','INTEGER'].includes(type)?'==':'exact'};
 });
 return {...m,items,allowValueOverride:false,requiresInput:false,comparator:null,source:m.source+' | operator-selected values',warnings:[...(m.warnings||[]),'CUSTOM_VALUES: These are operator-selected values, not a CIS benchmark compliance assertion.']};
}
function capture(form,m,s){
 if(!m||m.requiresInput){s.itemValues=null;return;}
 const inputs=[...form.querySelectorAll('[data-policy-value]')];if(inputs.length!==m.items.length)return;
 const values=inputs.map((input,i)=>['MultiString','Principals'].includes(m.items[i].type)?input.value.split(/\r?\n/).filter(x=>x.length):[input.value]);
 s.itemValues=JSON.stringify(values)===JSON.stringify(defaults(m))?null:values;
}
function render(s,m){
 const {esc,text}=window.GpoComponents,t=(_fallback,en)=>text(s,_fallback,en);
 if(!m)return '';
 if(m.requiresInput)return `<label>${esc(m.inputLabel||'Desired value')}<input name="customValue" value="${esc(s.selection.customValue??m.inputDefault??'')}" maxlength="4096" required></label>`;
 if(m.automation!=='Automated'||m.handler==='Manual')return `<p>${'This control requires role-specific manual review.'}</p>`;
 const recommended=defaults(m),values=s.selection.itemValues||recommended;
 return `<section class="policy-value-editor"><header><strong>${'Desired value'}</strong><button type="button" data-recommended-values>${'Restore recommendation'}</button></header><p>${'The recommendation is the initial value; you can change it. Custom choices are used in preview and the manual script.'}</p>${m.items.map((item,i)=>{
 const name=m.allowValueOverride&&i===0?'value':'policyValue'+i,value=values[i]||[],type=item.type||'String';
 const attrs=`name="${name}" data-policy-value="${i}" maxlength="4096"`;
 const input=m.handler==='AdvancedAudit'?`<select ${attrs}>${['No Auditing','Success','Failure','Success and Failure'].map((label,mask)=>`<option value="${mask}" ${String(value[0])===String(mask)?'selected':''}>${label} · ${mask}</option>`).join('')}</select>`:['MultiString','Principals'].includes(type)?`<textarea ${attrs} rows="3">${esc(value.join('\n'))}</textarea>`:`<input ${attrs} value="${esc(value[0]??'')}" ${['DWORD','Integer'].includes(type)?'inputmode="numeric" pattern="[0-9]+" required':''}>`;
 return `<label>${m.items.length===1?'':esc(item.name||item.key||item.guid)}${input}<small>${esc(item.name||item.key||item.guid)} · ${esc(type)} · ${'Recommended'}: ${esc(recommended[i].join(' / ')||'Empty list')}${['MultiString','Principals'].includes(type)?` · ${'One value per line; an empty list clears the assignment.'}`:''}</small></label>`;
 }).join('')}${s.selection.itemValues?`<p class="custom-value-note">${'Custom values selected. Successful application does not establish CIS recommendation compliance.'}</p>`:''}</section>`;
}
window.GpoValueEditor=Object.freeze({defaults,effective,capture,render});
})();
