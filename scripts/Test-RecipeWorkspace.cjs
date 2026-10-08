// Verify recorded implementation status without turning catalog coverage into compliance.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const window={GpoClient:{storage:{get:()=> '[]',set:()=>{}}}};
const context=vm.createContext({window,Date,JSON,String,Number,Boolean});
const source=path.join(__dirname,'../frontend/source');
for(const name of ['ui-domain.js','product.js'])vm.runInContext(fs.readFileSync(path.join(source,name),'utf8'),context);
const product=window.GpoProduct,rule={id:'1.2.1',implementation:'live'};
const s={lang:'en',history:[],favorites:new Set(),query:"",level:"ALL",automation:"ALL",savedView:"ALL",expandedTop:new Set(["1"]),catalog:{rules:[rule],sections:[{id:"1",title:"Accounts"}]}};
assert.equal(product.controlStatus(s,rule).label,'Not assessed');
const run=result=>({updatedAt:'2026-10-08T10:00:00Z',plan:{selection:{setting:rule.id},preview:{gpo:{name:'Test GPO'}}},result});
const verified={state:'PUBLISHED',gpoPublished:true,linkVerified:true,verification:{replicationConverged:true},effectiveStatus:'VERIFIED_ON_SAMPLE'};
for(const [result,label] of [[verified,'Implementation verified'],[{...verified,state:'ROLLED_BACK'},'Rolled back'],[{state:'APPLYING'},'In progress'],[{state:'FAILED_SAFE'},'Needs review'],[{state:'PUBLISHED',gpoPublished:true},'Verification pending']]){
  s.history=[run(result)];assert.equal(product.controlStatus(s,rule).label,label);
}
s.history=[run(verified),{...run({state:'ROLLED_BACK'}),updatedAt:'2026-10-08T11:00:00Z'}];
assert.equal(product.controlStatus(s,rule).label,'Rolled back');
s.history=[{...run(verified),plan:{selection:{setting:'another-control'}}}];assert.equal(product.controlStatus(s,rule).label,'Not assessed');
s.history=[];
const rules=[{...rule,id:'1.2.10',title:'<script>bad</script>',description:'<img onerror=bad>',recommended:'<unsafe>'},{...rule,id:'1.2.2',title:'Two',description:'Text'}];
const html=product.recipes(s,rules);
assert.ok(html.indexOf('1.2.2')<html.indexOf('1.2.10'));
assert.ok(html.includes('&lt;script&gt;')&&!html.includes('<script>'));
assert.ok(html.includes('&lt;img onerror=bad&gt;'));
assert.ok(product.coverage(s).includes('Not assessed'));
assert.ok(product.disconnectedControl(s,rule).includes('Connect to domain'));
console.log('Recipe workspace: PASS (status evidence, latest record, numeric order, escaping, disconnected preparation).');

const catalog=JSON.parse(fs.readFileSync(path.join(source,'benchmark-v4.json'),'utf8'));
s.catalog=catalog;s.expandedTop.clear();
let grouped=product.recipes(s,catalog.rules);
assert.equal((grouped.match(/data-domain=/g)||[]).length,19);
assert.equal((grouped.match(/class="recipe-card"/g)||[]).length,0);
let total=0;
for(const domain of catalog.sections.filter(d=>!d.parentId)){
  s.expandedTop=new Set([domain.id]);grouped=product.recipes(s,catalog.rules);
  const expected=catalog.rules.filter(r=>r.id.startsWith(domain.id+'.')).length;
  assert.equal((grouped.match(/class="recipe-card"/g)||[]).length,expected);
  assert.ok(grouped.includes(`aria-controls="catalog-domain-${domain.id}"`));
  if(!expected)assert.ok(grouped.includes('no controls for this domain'));
  total+=expected;
}
assert.equal(total,405);
s.query='1.2.1';s.expandedTop.clear();grouped=product.recipes(s,catalog.rules.filter(r=>r.id==='1.2.1'));
assert.equal((grouped.match(/data-domain=/g)||[]).length,1);
assert.ok(!grouped.includes('class="recipe-card"'));
s.expandedTop.add('1');assert.equal((product.recipes(s,catalog.rules.filter(r=>r.id==='1.2.1')).match(/class="recipe-card"/g)||[]).length,1);
console.log('Domain accordion: PASS (19 domains, 405 controls, collapsed default, filtered groups, empty domains, accessible headers).');
