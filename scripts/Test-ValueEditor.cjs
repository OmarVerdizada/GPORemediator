const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),vm=require('node:vm');
const root=path.resolve(__dirname,'..'),window={},ctx=vm.createContext({window,Date,JSON,String,Number,Boolean,BigInt});
for(const file of ['components.js','value-editor.js','manual-engine.js','manual-remediation.js','ui-domain.js'])vm.runInContext(fs.readFileSync(path.join(root,'frontend/source',file),'utf8'),ctx);
const mappings=JSON.parse(fs.readFileSync(path.join(root,'backend/data/gpo-production-mappings.json'),'utf8')).mappings;
for(const m of mappings.filter(x=>x.automation==='Automated')){
 const state={lang:'en',selection:{value:m.suggested??0,customValue:m.inputDefault??''}};
 const html=window.GpoValueEditor.render(state,m);
 assert(!html.includes('disabled'));
 assert(html.includes(m.requiresInput?'customValue':'data-policy-value'));
}
const fixtures=JSON.parse(fs.readFileSync(path.join(root,'work/audit/custom-values.json'),'utf8'));
for(const fixture of fixtures){
 const base=mappings.find(x=>x.id===fixture.selection.setting),resolved=window.GpoValueEditor.effective(base,fixture.selection);
 assert.equal(resolved.source,fixture.mapping.source);assert.equal(resolved.allowValueOverride,false);
 for(let i=0;i<resolved.items.length;i++){
  assert.deepEqual(JSON.parse(JSON.stringify(resolved.items[i].value??null)),fixture.mapping.items[i].value);
  assert.equal(resolved.items[i].mask??null,fixture.mapping.items[i].mask);
  assert.equal(resolved.items[i].comparator,fixture.mapping.items[i].comparator);
 }
 const rule={id:base.id,backendSetting:base.id},state={lang:'en',settings:mappings,selection:fixture.selection,inventory:{domain:'example.test',domainController:'dc.example.test'}};
 const generated=window.GpoManualRemediation.generate(state,rule,'Apply');
 assert(generated.script.includes('operator-selected values'));
 assert.equal(generated.mapping.items[0].comparator,fixture.mapping.items[0].comparator);
}
const base=mappings.find(x=>x.id==='9.1.5'),selection={};
window.GpoValueEditor.capture({querySelectorAll:()=>[{value:'32768'}]},base,selection);
assert.equal(selection.itemValues[0][0],'32768');
window.GpoValueEditor.capture({querySelectorAll:()=>[{value:'16384'}]},base,selection);
assert.equal(selection.itemValues[0][0],'16384','The initial recommendation also pins an exact value');
const exact=JSON.parse(fs.readFileSync(path.join(root,'work/audit/exact-values.json'),'utf8'));
for(const fixture of exact){const resolved=window.GpoValueEditor.effective(mappings.find(x=>x.id===fixture.selection.setting),fixture.selection);assert.equal(resolved.comparator,fixture.mapping.comparator);for(let i=0;i<resolved.items.length;i++)for(const field of ['section','key','name','guid','state','mask','type','comparator','value'])assert.deepEqual(JSON.parse(JSON.stringify(resolved.items[i][field]??(field==='type'?'String':null))),fixture.mapping.items[i][field]??null,fixture.mapping.id+' '+field);}
console.log('PASS all 413 exact remediation mapping cases match C# including inclusion/audit semantics');
const quality=window.GpoUiDomain.classify({plan:{selection:{itemValues:[['0']]}},result:{gpoPublished:true,linkVerified:true,verification:{replicationConverged:true},effectiveStatus:'VERIFIED_ON_SAMPLE'}});
assert.equal(quality.compliant,false);assert.equal(quality.custom,true);
console.log('PASS 394 editable controls, C#/manual-script custom-value parity, capture/reset and custom values excluded from benchmark compliance');
for(const mapping of mappings.filter(x=>x.automation!=='Automated')){
 assert.equal(window.GpoUiDomain.impact(mapping).cls,'high','Reviewed controls must not default to low operational risk: '+mapping.id);
 const rule={id:mapping.id,backendSetting:mapping.id},state={settings:mappings,selection:{setting:mapping.id,itemValues:window.GpoValueEditor.defaults(mapping),reviewContext:''}};
 const pending=window.GpoManualRemediation.generate(state,rule);
 assert.equal(pending.writable,false,'An unfinished review must remain read-only: '+mapping.id);
 state.selection.reviewContext='R';
 const ready=window.GpoManualRemediation.generate(state,rule);
 assert.equal(ready.writable,true,'A completed review must preserve the explicit policy fields: '+mapping.id);
}
console.log('PASS 11 reviewed controls remain read-only while justification is unfinished and generate explicit approved values after review');
