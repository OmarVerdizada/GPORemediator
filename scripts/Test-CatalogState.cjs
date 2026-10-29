/* One catalog hierarchy, all controls and truthful recorded status. No AD. */
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=path.resolve(__dirname,'../frontend/source'),window={GpoClient:{storage:{get:()=> '[]',set(){}}}},ctx=vm.createContext({window,Date,JSON,String,Number,Boolean});
for(const file of ['ui-domain.js','components.js','domain-guidance.js','product.js','catalog-view.js'])vm.runInContext(fs.readFileSync(path.join(source,file),'utf8'),ctx);
ctx.GpoUiDomain=window.GpoUiDomain;
const catalog=JSON.parse(fs.readFileSync(path.join(source,'benchmark-v4.json'),'utf8'));
const state={catalog,history:[],settings:[],lang:'en',query:'',level:'ALL',automation:'ALL',savedView:'ALL',expandedTop:new Set(),expandedSub:new Set(),catalogSearchCollapsed:new Set(),catalogSearchSubCollapsed:new Set()};
const view=window.GpoCatalogView.create({state,esc:window.GpoComponents.esc,say:(a,b)=>b,tr:x=>x});
assert.equal((view.benchmarkView().match(/data-domain=/g)||[]).length,19);
assert.equal((view.benchmarkView().match(/data-rule=/g)||[]).length,0,'Hierarchy starts collapsed');
let total=0;
for(const section of catalog.sections.filter(x=>!x.parentId)){
 state.expandedTop=new Set([section.id]);state.expandedSub=new Set(catalog.sections.filter(x=>x.parentId).map(x=>x.id));
 const html=view.benchmarkView(),expected=catalog.rules.filter(r=>r.id.startsWith(section.id+'.')).length;
 assert.equal((html.match(/data-rule=/g)||[]).length,expected,section.id);total+=expected;
 if(!expected)assert.match(html,/SUPPLEMENTAL GUIDANCE/);
}
assert.equal(total,405);
state.query='1.2.2';state.expandedTop.clear();state.expandedSub.clear();
assert.equal((view.benchmarkView().match(/data-rule=/g)||[]).length,1,'Searching opens matching nested sections');
state.catalogSearchCollapsed.add('1');assert.equal((view.benchmarkView().match(/data-rule=/g)||[]).length,0,'Search results remain collapsible');state.catalogSearchCollapsed.clear();
const rule=catalog.rules.find(r=>r.id==='1.2.2'),run=result=>({updatedAt:'2026-10-29T06:00:00Z',plan:{selection:{setting:'1.2.2'}},result});
for(const [result,label] of [[{state:'PUBLISHED',gpoPublished:true},'Verification pending'],[{state:'ROLLED_BACK'},'Rolled back'],[{state:'VERIFYING'},'In progress'],[{state:'PUBLISHED',effectiveStatus:'ENDPOINT_MISMATCH'},'Needs review'],[{state:'PUBLISHED',gpoPublished:true,linkVerified:true,effectiveStatus:'VERIFIED_ON_SAMPLE',verification:{replicationConverged:true}},'Sample configuration verified']]){
 state.history=[run(result)];assert.equal(window.GpoProduct.controlStatus(state,rule).label,label);
}
const html=view.renderRuleRow({...rule,title:'<script>unsafe</script>'});assert(html.includes('&lt;script&gt;')&&!html.includes('<script>'));
assert(!/data-favorite|data-catalog-layout|recipe-card/.test(view.benchmarkView()));
console.log('PASS single catalog hierarchy: 19 sections, all 405 controls, nested/search/collapse behavior, recorded state, HTML escaping and no retired catalog modes.');
