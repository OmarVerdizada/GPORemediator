'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(require('path').join(__dirname,'../frontend/source/studio-ui.js'),'utf8');
const context={window:{GpoUiDomain:{classify:run=>({compliant:run.result?.effectiveStatus==='VERIFIED_ON_SAMPLE'&&run.result?.linkVerified===true&&run.result?.gpoPublished===true&&run.result?.verification?.replicationConverged===true})}},Date};
vm.createContext(context);vm.runInContext(source,context,{filename:'studio-ui.js'});
const ui=context.window.GpoStudioUI;
assert(ui);
const run=(s,e,ok=false)=>({updatedAt:'2026-10-14T10:00:00Z',result:{state:s,effectiveStatus:e,gpoPublished:ok,linkVerified:ok,verification:{replicationConverged:ok}}});
const state={lang:'en',history:[run('COMPLETED','VERIFIED_ON_SAMPLE',true),run('VERIFY_MISMATCH','NO_SAMPLE'),run('PUBLISHED','PENDING')],
  catalog:{rules:[{id:'1.1.1',implementation:'live'},{id:'2.2.1',implementation:'manual'}]},
  inventory:{domain:'example.local',gpos:[{id:'a',name:'<script>alert(1)</script>'}],scopes:[{dn:'OU=Sales,DC=example,DC=local',name:'Sales'}]},
  session:{operator:'LAB\\admin'},gpoSession:{connected:true},selection:{gpoId:'a',scopeDn:'OU=Sales,DC=example,DC=local'},
  selectedRule:{id:'2.2.1',title:'Test policy'},approval:{reviewed:false}};
const dashboard=ui.dashboard(state),catalog=ui.catalog(state),ops=ui.operations(state),workflow=ui.workflow(state);
assert(dashboard.includes('Evidence verified')&&dashboard.includes('Automated CIS mappings'));
assert(dashboard.includes('Not compliance rate'));
assert(catalog.includes('controls currently have real GPO mappings'));
assert.equal(ui.remediation,undefined,'The unused duplicate remediation context must remain removed');
const unsafeDashboard=ui.dashboard({...state,inventory:{...state.inventory,domain:'<script>alert(1)</script>'}});
assert(unsafeDashboard.includes('&lt;script&gt;alert(1)&lt;/script&gt;')&&!unsafeDashboard.includes('<script>alert(1)</script>'));
assert(ops.includes('OPERATION ASSURANCE'));
assert(workflow.includes('Preview → Approval → Apply → Verify'));
assert.equal(ui.status(state.history[0]),'verified');
assert.equal(ui.status(state.history[1]),'review');
assert.equal(ui.status(state.history[2]),'pending');
assert.equal(ui.status(run('ROLLED_BACK','VERIFIED_ON_SAMPLE',true)),'restored');
assert(!/eval\(|new Function|innerHTML\s*=/.test(source));
console.log('PASS Studio UI: active components, duplicate context removed, trusted counts, output encoding, no fabricated compliance.');
