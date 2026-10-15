const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../frontend/source/enterprise-center.js'),'utf8');
const ctx={window:{},Date,Blob};
vm.runInNewContext(source,ctx,{filename:'enterprise-center.js'});
const {record,collect,csv,html,diagnosis}=ctx.window.GpoEnterpriseCenter;
const base={id:'abc',updatedAt:'2026-10-14T09:00:00Z',correlationId:'cor1',
 plan:{actor:'LAB\\operator',executionUser:'LAB\\svc',domain:'lab.local',selection:{setting:'2.2.12',gpoId:'123',scopeDn:'OU=Servers,DC=lab,DC=local'},preview:{gpo:{name:'CIS Baseline'},previousValue:'A',desiredValue:'B'}},
 result:{state:'PUBLISHED',effectiveStatus:'VERIFIED_ON_SAMPLE',gpoPublished:true,linkVerified:true,verification:{replicationConverged:true},endpointChecks:[{hostname:'srv1',state:'VERIFIED',message:'observed'}],backupId:'backup-001',currentValue:'B',message:'ok'}};
const run=structuredClone(base);
const out=record(run);assert.equal(out.status,'EVIDENCE_VERIFIED');
for(const mod of [
 r=>r.result.gpoPublished=false,
 r=>r.result.linkVerified=false,
 r=>r.result.verification.replicationConverged=false,
 r=>r.result.effectiveStatus='ENDPOINT_VERIFICATION_PENDING',
 r=>r.result.state='DRIFT_DETECTED',
 r=>r.result.state='ROLLED_BACK',
 r=>r.result.effectiveStatus='ENDPOINT_MISMATCH'
]) { const candidate=structuredClone(base);mod(candidate);assert.notEqual(record(candidate).status,'EVIDENCE_VERIFIED'); }
assert.equal(record({...base,result:{...base.result,effectiveStatus:'ENDPOINT_MISMATCH'}}).status,'NEEDS_REVIEW');
const data=collect({history:[base],catalog:{meta:{benchmark:'CIS v4.0'},rules:Array.from({length:405},(_,i)=>({id:String(i)}))}},{});
assert.equal(data.knownControls,405);assert.equal(data.controlsWithoutRecordedOperations,404);assert.equal(data.count,1);
const filter=collect({history:[base],catalog:{rules:[{id:'2.2.12'}]}},{scope:'OU=Unknown'});assert.equal(filter.count,0);
const injection={...data,entries:[{...out,gpo:'<img src=x onerror=alert(1)>',scopeDn:'=cmd|/c evil',note:'\r\n=1+1'}]};
const markup=html(injection);assert(!markup.includes('<img src=x'));assert(markup.includes('&lt;img'));
const csvOutput=csv(injection);assert(csvOutput.includes('"\'=cmd|/c evil"'));
assert(!csvOutput.includes('\r\n=1+1'));
const diag=diagnosis({mode:'WINDOWS'},{ready:false,checkedAt:'2026-10-14T09:00:00Z',checks:[{id:'dns',label:'DNS',state:'WARN',required:true}]},null);
assert.equal(diag.warn,1);assert.equal(diag.ready,false);assert(diag.checks.some(x=>x.id==='scope-permissions'&&x.state==='NOT_CHECKED'));
const diag2=diagnosis({mode:'WINDOWS'},{ready:true,checks:[{id:'dns',label:'DNS',state:'PASS',required:true}]},{preview:{preflight:{checks:[{id:'gpo-edit',label:'GPO edit',state:'FAIL'}]}}});
assert.equal(diag2.ready,false);assert.equal(diag2.failed,1);
// Enforce no mutation via the module: source must not call GPO apply/rollback/refresh endpoints.
assert(!/api\(['"]\/gpo\/[^'"]+\/(apply|rollback|refresh)/.test(source));
console.log('ENTERPRISE CENTER TESTS PASSED: evidence, filters, CSV safety, HTML escaping, diagnosis');
