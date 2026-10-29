const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=path.join(__dirname,'../frontend/source'),window={GpoClient:{storage:{get:()=> '[]',set(){}}}};
const workspaceSource=fs.readFileSync(path.join(source,'workspace.js'),'utf8');
assert(!/allowedOperators|remediators|auditors|viewers/.test(workspaceSource),'Legacy application role fields remain in frontend setup payloads');
const context=vm.createContext({window,Date,JSON,String,Number,Boolean});
for(const name of ['ui-domain.js','components.js','product.js','premium.js','catalog-view.js','operation-view.js'])vm.runInContext(fs.readFileSync(path.join(source,name),'utf8'),context);
const ui=window.GpoComponents,s={lang:'en',history:[],favorites:new Set(),query:'',level:'ALL',automation:'ALL',savedView:'ALL',catalog:JSON.parse(fs.readFileSync(path.join(source,'benchmark-v4.json'),'utf8'))};
assert.equal(ui.status(s,'ROLLED_BACK').tone,'neutral');
assert.equal(ui.status(s,'PUBLISHED_REFRESH_FAILED').tone,'danger');
assert.equal(ui.status(s,'ENDPOINT_VERIFICATION_PENDING').tone,'pending');
assert.equal(ui.status(s,'NOT_VERIFIED').tone,'pending');
assert.equal(ui.status(s,'PUBLISHED').label,'Published');
assert.ok(ui.status(s,'<script>').html.includes('&lt;SCRIPT&gt;'));
const incomplete={id:'<unsafe>',plan:{selection:{setting:'1.2.1'},preview:{gpo:{name:'<bad>'}}},result:{state:'PUBLISHED',gpoPublished:true}};
s.history=[incomplete];
assert.equal(window.GpoProduct.controlStatus(s,s.catalog.rules.find(r=>r.id==='1.2.1')).tone,'unknown');
assert.ok(ui.timeline(s,incomplete).includes('Not confirmed'));
assert.ok(ui.timeline(s,{result:{state:'NO_CHANGE'}}).includes('Not required'));
assert.equal((ui.timeline(s,{result:{state:'NO_CHANGE'}}).match(/class="done"/g)||[]).length,0);
assert.equal((ui.timeline(s,incomplete).match(/class="done"/g)||[]).length,2);
assert.ok(ui.operations(s,s.history).includes('&lt;bad&gt;'));
assert.ok(!ui.operations(s,s.history).includes('<bad>'));
const recoverable={...incomplete,result:{state:'PUBLISHED',backupId:'backup-<id>'}};
assert.ok(ui.operations(s,[recoverable]).includes('Rollback'));
s.gpoSession={connected:true};
assert.ok(!ui.recovery(s,recoverable).includes('<form'),'Backup ID alone must not expose a restore form');
s.rollbackChecks={[recoverable.id]:{result:{canRestore:true,manifestPhase:'PUBLISHED',reason:'READY'},updatedAt:recoverable.updatedAt,state:recoverable.result.state,session:s.gpoSession,at:Date.now()}};
assert.ok(ui.recovery(s,recoverable).includes('data-rollback="&lt;unsafe&gt;"'));
assert.ok(ui.recovery(s,recoverable).includes('backup-&lt;id&gt;'));
assert.ok(ui.recovery(s,recoverable).includes('name="refresh"'));
assert.ok(ui.recovery(s,{...recoverable,result:{...recoverable.result,state:'ROLLED_BACK'}}).includes('data-gpupdate="&lt;unsafe&gt;"'));
assert.match(ui.recovery(s,{...recoverable,result:{...recoverable.result,state:'ROLLBACK_DRIFT_DETECTED'}}),/data-gpupdate[^>]*disabled/);
assert.ok(!ui.recovery(s,{...recoverable,result:{...recoverable.result,state:'ROLLED_BACK'}}).includes('<form'),'A changed result requires a fresh rollback assessment');
for(const state of ['NO_CHANGE','BATCH_ROLLED_BACK','ROLLBACK_DRIFT_DETECTED','APPLYING','ROLLBACKING','VERIFYING','REFRESHING']){
 assert.ok(!ui.recovery(s,{...recoverable,result:{...recoverable.result,state}}).includes('<form'),state);
}
assert.ok(!ui.recovery(s,incomplete).includes('<form'));
assert.ok(!ui.recovery(s,{...recoverable,result:{...recoverable.result,state:'REVIEW_REQUIRED'}}).includes('<form'),'Unreviewed partial restore must not expose retry form');
const assessed=s.rollbackChecks[recoverable.id];
for(const change of [{at:Date.now()-60001},{updatedAt:'new-record'},{state:'FAILED_SAFE'},{session:{}},{processId:99}]){
 s.rollbackChecks[recoverable.id]={...assessed,...change};
 assert.equal(ui.rollbackCheck(s,recoverable),null,'Changed or expired context must invalidate restore assessment');
}
s.rollbackChecks[recoverable.id]={...assessed,result:{canRestore:false,manifestPhase:'ROLLBACK_REVIEW_REQUIRED',reason:'MANUAL_REVIEW_REQUIRED',failure:{code:'<unsafe>',stage:'RESTORING_GPO',message:'<detail>'}}};
assert.ok(!ui.recovery(s,recoverable).includes('<form'));
assert.ok(ui.recovery(s,recoverable).includes('&lt;detail&gt;'));
assert.ok(ui.recovery(s,recoverable).includes('ROLLBACK_REVIEW_REQUIRED'));
s.serviceOffline=true;s.rollbackChecks[recoverable.id]=assessed;
assert.ok(!ui.recovery(s,recoverable).includes('<form'));
assert.match(ui.refreshAction(s,recoverable),/data-gpupdate[^>]*disabled/);
s.serviceOffline=false;
const connected=s.gpoSession;s.gpoSession=null;assert.match(ui.refreshAction(s,{...recoverable,result:{state:'PUBLISHED',gpoPublished:true,linkVerified:true}}),/disabled/);s.gpoSession=connected;
assert.doesNotMatch(ui.refreshAction(s,{...recoverable,result:{state:'PUBLISHED',gpoPublished:true,linkVerified:true}}),/disabled/,'Published operation must allow explicit refresh even without an original refresh request');
assert.ok(ui.domainEvidence(s).includes('Not assessed'));
s.audit={integrityValid:false,firstInvalidEventId:2,events:[{id:2,hash:'<bad>'}]};
assert.ok(ui.auditChain(s).includes('First invalid event: #2'));
assert.ok(ui.auditChain(s).includes('class="invalid"'));
assert.ok(!ui.auditChain(s).includes('Hash chain verified'));
const c=window.GpoCatalogView.create({state:s,esc:ui.esc,say:(a,e)=>e,tr:x=>x});
s.expandedTop=new Set();s.settings=[];
assert.equal((c.benchmarkView().match(/data-domain=/g)||[]).length,19);
assert.ok(ui.breadcrumb(s,s.catalog.rules.find(r=>r.id==='1.2.1')).includes('Account Lockout Policy'));
const index=fs.readFileSync(path.join(source,'index.html'),'utf8');
assert.deepEqual([...index.matchAll(/rel="stylesheet" href="\/([^?]+)/g)].map(m=>m[1]),['app.css','gpo-scope-picker.css','ux-pro.css','wave1-reliability.css','enterprise-center.css','studio-design.css','theme-polish.css','workspace-refinement.css']);
for(const name of [...index.matchAll(/(?:src|href)="\/([^"?]+)(?:\?[^" ]+)?"/g)].map(m=>m[1]))if(!name.startsWith('#'))assert.ok(fs.existsSync(path.join(source,name)),`Missing asset ${name}`);
const css=fs.readFileSync(path.join(source,'app.css'),'utf8');
assert.ok(!css.includes('!important'));
assert.ok(!/--(?:accent|cc-|ink|muted|green)\b/.test(css));
for(const s of ['prefers-reduced-motion','data-large-text','data-contrast','data-gr-theme=dark','.ds-field-error','.ds-toast'])assert.ok(css.includes(s));
const controlView=fs.readFileSync(path.join(source,'control-view.js'),'utf8');
for(const marker of ['endpointScopeDn','verificationUser','User Configuration','/target:user'])assert.ok(controlView.includes(marker),`Missing user-policy UI marker ${marker}`);
// Domain-vs-local PDC/Scope behavior is exercised by Test-ControlTargeting.cjs.
require('./Test-GpoScopePicker.cjs');
console.log('Frontend system: PASS (honest evidence, status tones, escaping, grouping, audit mismatch, breadcrumb, packaged assets and canonical tokens).');
const premium=window.GpoPremium;assert.equal(premium.heatmap,undefined);assert.equal(window.GpoProduct.recipes,undefined);
const copied=premium.copyValue(s,'<unsafe>" & value','Hash');
assert.ok(copied.includes('data-copy-value="&lt;unsafe&gt;&quot; &amp; value"'));
assert.ok(!copied.includes('<unsafe>'));
for(const name of ['Geist-Variable.woff2','GeistMono-Variable.woff2'])assert.equal(fs.readFileSync(path.join(source,'fonts',name)).subarray(0,4).toString(),'wOF2');
assert.ok(fs.readFileSync(path.join(source,'fonts/LICENSE.txt'),'utf8').includes('SIL OPEN FONT LICENSE'));
console.log('PASS shared copy controls, removed heatmap/recipes and offline fonts.');

// Configured-value provenance is independent of the resultant endpoint policy.
const policySource={gpoId:'11111111-1111-1111-1111-111111111111',gpoName:'Baseline <unsafe>'};
assert.match(ui.valueSource(policySource,0),/Baseline &lt;unsafe&gt;/);
assert.match(ui.valueSource(policySource,''),/11111111-1111-1111-1111-111111111111/);
assert(!ui.valueSource(policySource,null,{name:'must not appear'}).includes('Baseline'));
assert.match(ui.valueSource(policySource,null),/Source GPO: —/);
assert.match(ui.valueSource(null,'1',{id:policySource.gpoId,name:'Legacy recorded GPO'}),/Legacy recorded GPO/);
console.log('PASS configured-value GPO source, zero/empty values, unknown source and HTML escaping');

assert.equal(ui.status(s,'PUBLISHED').tone,'pending');assert.equal(ui.status(s,'REFRESH_COMPLETED').tone,'pending');

assert.equal(window.GpoUiDomain.resultState({result:{state:"PUBLISHED",effectiveStatus:"ENDPOINT_MISMATCH"}}),"ENDPOINT_MISMATCH");
assert.equal(ui.status(s,"ENDPOINT_MISMATCH").label,"Not effective");
