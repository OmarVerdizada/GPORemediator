const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const root=path.resolve(__dirname,'../frontend/source'),window={};
for(const file of ['gpo-scope-picker.js','control-view.js','value-editor.js'])vm.runInNewContext(fs.readFileSync(path.join(root,file),'utf8'),{window});
const settings=JSON.parse(fs.readFileSync(path.resolve(root,'../../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const domain='DC=example,DC=local',ou='OU=Pilot,'+domain,id='11111111-1111-1111-1111-111111111111';
const state={settings,plan:{id:'stale'},approval:{reviewed:true},selectedRule:{id:'1.1.1',backendSetting:'1.1.1',implementation:'live'},selection:{gpoId:id,scopeDn:ou,accountScope:'Domain',refresh:'Scope',firstLink:false},inventory:{gpos:[{id,name:'Pilot',selectable:true}],scopes:[{dn:domain,name:'example.local',kind:'Domain'},{dn:ou,name:'Pilot',kind:'OU'}]},lang:'en',gpoSearch:'',scopeExpanded:new Set()};
window.GpoValueEditor={...window.GpoValueEditor,render(){return '';}};
window.GpoPremium={copyValue(){return '';},emptyIcon(){return '';}};
const view=window.GpoControlView.create({state,esc:v=>String(v??'').replaceAll('<','&lt;'),say:(az,en)=>en,tr:v=>v,uiIcon:()=>'',renderConnection:()=>''});
view.ensureSelection();
assert.equal(state.selection.scopeDn,ou);assert.equal(state.selection.accountScope,'LocalComputers');assert.equal(state.selection.refresh,'Scope');assert.equal(state.plan,null);
let html=view.targetForm(state.selectedRule);assert(html.includes('LOCAL accounts'));assert(!html.includes('class="primary-action" disabled'));assert(html.includes('name="refresh" value="Scope"'));assert(!html.includes('name="refresh" value="Pdc"'));
let effective=window.GpoValueEditor.effective(settings.find(x=>x.id==='1.1.1'),state.selection);assert.equal(effective.scope,'Computer');assert.equal(effective.domainPolicySensitive,false);
state.selection.scopeDn=domain;view.ensureSelection();assert.equal(state.selection.accountScope,'Domain');assert.equal(state.selection.firstLink,true);assert.equal(state.selection.refresh,'None');
html=view.targetForm(state.selectedRule);assert(html.includes('priority 1'));assert(html.includes('name="refresh" value="Pdc"'));assert(!html.includes('class="primary-action" disabled'));
for(const control of ['2.3.1.1','17.1.1','19.5.1.1']){
 state.selectedRule={id:control,backendSetting:control,implementation:'live'};state.selection.scopeDn=ou;view.ensureSelection();
 assert.equal(state.selection.scopeDn,ou);assert.equal(view.targetIssue(),'');html=view.targetForm(state.selectedRule);assert(!html.includes('class="primary-action" disabled'));
 state.selection.scopeDn=domain;view.ensureSelection();assert.equal(state.selection.scopeDn,domain);assert.equal(view.targetIssue(),'');
}
const modal=window.GpoScopePicker.modal(state.inventory.scopes,'scopeDn','',new Set([domain.toLowerCase()]),{scopeDn:ou},'en',false,true,'All');
assert(modal.includes('data-scope-choose="'+ou+'"'));assert(modal.includes('data-scope-choose="'+domain+'"'));
state.selection.scopeDn=ou;state.targetAccessError={key:view.targetKey(),message:'GPMC <unsafe>'};html=view.targetForm(state.selectedRule);assert(html.includes('&lt;unsafe>'));assert(!html.includes('class="primary-action" disabled'));
console.log('PASS local/domain account intent, OU/domain targets across handlers, stable selection, access escaping and selectable plan actions');
