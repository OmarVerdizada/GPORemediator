/* Deterministic responsiveness regressions: no domain access or real timers. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=name=>fs.readFileSync(path.join(__dirname,'../frontend/source',name),'utf8');

async function main(){
 const window={GpoClient:{storage:{get:()=> '[]',set(){}}}};
 const ctx=vm.createContext({window,Date,JSON,String,Number,Boolean});
 for(const name of ['ui-domain.js','components.js','product.js','premium.js'])vm.runInContext(source(name),ctx);
 const product=window.GpoProduct;
 const history=Array.from({length:10000},(_,i)=>({updatedAt:new Date(1700000000000+i*1000).toISOString(),plan:{selection:{setting:String(i%405)}},result:{state:'PUBLISHED'}}));
 history.push({...history[9999],id:'tied'});
 const latest=product.latestByControl(history);
 assert.equal(latest.size,405);
 for(let i=0;i<405;i++){
  const expected=product.sortedRuns(history.filter(r=>r.plan.selection.setting===String(i)))[0];
  assert.equal(latest.get(String(i)),expected,'Latest status must preserve date order and ties');
 }
 const sample={lang:'en',catalog:{rules:[{id:'0',implementation:'live'}],sections:[{id:'0',title:'Test'}]},history};
 let iterations=0;
 const iterator=history[Symbol.iterator].bind(history);
 history[Symbol.iterator]=function*(){iterations++;yield* iterator();};
 const lookup=product.latestByControl(history);
 sample.catalog.rules=Array.from({length:405},(_,i)=>({id:'0.'+i,backendSetting:String(i),title:'Control'}));
 sample.catalog.rules.forEach(r=>product.controlStatus(sample,r,lookup));assert.equal(iterations,1,'Catalog status must reuse one history index');
 assert.equal(product.latestByControl([{updatedAt:'bad',plan:{selection:{setting:'x'}}},{updatedAt:'bad',plan:{selection:{setting:'x'}}}]).size,1);

 let renders=0,calls=0,editing=false,fail=false,pending=null;
 const document={hidden:false,addEventListener(){},activeElement:{closest:()=>editing?{}:null}};
 const location={hash:'#/dashboard'},state={session:{mode:'WINDOWS'},history:[]};
 const data={jobs:[],batches:[],history:[]};
 vm.runInNewContext(source('operation-monitor.js'),{window,document,location,Date,JSON,Set});
 const center=window.GpoOperationMonitor.create({state,esc:String,say:(a,b)=>b,render:()=>renders++,run:fn=>fn(),api:async url=>{
  calls++;if(pending)await pending;if(fail)throw Error('Offline');
  return JSON.parse(JSON.stringify(url==='/workflows'?data.jobs:url==='/batches'?data.batches:data.history));
 }});
 await center.poll();assert.equal(renders,1);
 await center.poll();assert.equal(renders,1,'Identical poll results must not replace the DOM');
 document.hidden=true;let before=calls;await center.poll();assert.equal(calls,before,'Hidden tabs must not poll');document.hidden=false;
 state.busy=true;await center.poll();assert.equal(calls,before,'User requests must not compete with polling');state.busy=false;
 editing=true;data.jobs=[{id:'job',state:'RUNNING'}];await center.poll();assert.equal(renders,1,'Polling must preserve edits');
 editing=false;await center.poll();assert.equal(renders,2,'Deferred changes must render after editing even if unchanged');
 editing=true;data.jobs[0].state='COMPLETED';await center.poll();location.hash='#/benchmark';editing=false;
 await center.poll();assert.equal(renders,3,'A deferred terminal result must still render after navigation');
 location.hash='#/dashboard';let release;pending=new Promise(resolve=>release=resolve);
 const first=center.poll();before=calls;await center.poll();assert.equal(calls,before,'Slow requests must not overlap');release();await first;pending=null;
 fail=true;await center.poll();assert.equal(renders,4,'A new polling error must be visible');await center.poll();assert.equal(renders,4,'Repeated errors must not churn the DOM');
 fail=false;await center.poll();assert.equal(renders,5,'Recovery must clear the error');

 const workspace=source('workspace.js'),healthCode=workspace.slice(workspace.indexOf('async function healthTick(){'),workspace.indexOf('function captureForm(){'));
 let healthRenders=0,clears=0;
 const healthState={session:{mode:'SETUP'},service:{processId:1},history:[]};
 const healthContext={state:healthState,document,location:{hash:'#/dashboard'},Date,JSON,window:{GpoProduct:{active:()=>false}},
  client:{request:async url=>url==='/api/service'?{processId:1,activeJobs:0}:{mode:'SETUP'},ephemeralCredential:{available:()=>false}},
  clearDelegatedState:()=>clears++,render:()=>healthRenders++,say:(a,b)=>b};
 vm.runInNewContext(healthCode+'\nthis.healthTick=healthTick;',healthContext);
 await healthContext.healthTick();await healthContext.healthTick();
 assert.equal(healthRenders,0,'Healthy Setup probes must preserve the page');
 assert.equal(clears,0,'Unchanged Setup probes must not reset draft state');
 healthState.session.mode='WINDOWS';await healthContext.healthTick();
 assert.equal(clears,1);assert.equal(healthRenders,1,'A real mode transition must update the page');
 healthState.session.mode='WINDOWS';healthState.gpoSession={connected:true};
 healthContext.client.request=async url=>{
  if(url==='/api/gpo/session')throw Object.assign(Error('Expired'),{code:'GPO_LOGIN_REQUIRED'});
  return url==='/api/service'?{processId:1,activeJobs:0}:{mode:'WINDOWS'};
 };
 healthContext.restoreDelegatedAfterRestart=async()=>false;
 healthContext.clearDelegatedState=()=>{healthState.gpoSession=null;};
 await healthContext.healthTick();assert.equal(healthRenders,2,'Session-expiry notices must render even when history is unchanged');

 const timers=[];let response;
 const clientWindow={};
 vm.runInNewContext(source('client.js'),{window:clientWindow,document:{},sessionStorage:{getItem:()=> 'en'},TextEncoder,TextDecoder,AbortController,Set,Date,JSON,String,Number,Boolean,TypeError,Error,
  setTimeout:(_,ms)=>{timers.push(ms);return timers.length;},clearTimeout(){},fetch:()=>new Promise(resolve=>response=resolve)});
 const request=clientWindow.GpoClient.request('/api/gpo/plan/rollback-preview');
 assert.equal(timers.at(-1),620000,'Rollback inspection must allow the ten-minute server deadline');
 assert.equal(clientWindow.GpoClient.progress().cancelable,true);
 response({ok:true,text:async()=> '{}'});await request;
 assert.equal(clientWindow.GpoClient.progress(),undefined,'Transport must release completed requests');
 console.log('PASS responsiveness: one-pass history, unchanged/hidden/busy polling, editing, terminal updates, concurrency, Setup probes, recovery and rollback timeout');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
