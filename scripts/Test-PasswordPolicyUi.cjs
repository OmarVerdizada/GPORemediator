/* Real FGPP presentation/controller, local responses only. No AD access. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),http=require('node:http'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source');
const server=http.createServer((req,res)=>{
 if(req.url==='/password-policies.js'){res.setHeader('Content-Type','application/javascript');res.end(fs.readFileSync(path.join(root,'password-policies.js')));return;}
 if(req.url==='/app.css'){res.setHeader('Content-Type','text/css');res.end(fs.readFileSync(path.join(root,'app.css')));return;}
 res.setHeader('Content-Type','text/html');res.end('<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="stylesheet" href="/app.css"></head><body><main id="root"></main><script src="/password-policies.js"></script></body></html>');
});
(async()=>{let browser;try{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});const page=await browser.newPage({viewport:{width:1280,height:900}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto('http://127.0.0.1:'+server.address().port);
 await page.evaluate(()=>{
 const root=document.querySelector('#root'),state={busy:false,inventory:{scopes:[{kind:'Domain',dn:'DC=test,DC=local',name:'test.local'},{kind:'OU',dn:'OU=Users,DC=test,DC=local',name:'Users'}]}};
 window.calls=[];let controller;
 const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function render(){root.innerHTML=controller.view();}
 async function run(fn){state.busy=true;render();try{await fn();}finally{state.busy=false;render();}}
 async function api(path,body){window.calls.push({path,body});if(path==='/password-policies')return [];if(path.endsWith('/preview'))return {id:'fixture',request:body,executionUser:'TEST\\operator',preview:{users:[{name:'alice'},{name:'bob'}],warnings:[],before:{exists:false}}};return {state:path.endsWith('/rollback')?'ROLLED_BACK':'VERIFIED',message:'Fixture only',users:[]};}
 controller=window.GpoPasswordPolicies.create({state,esc,api,run,render});root.addEventListener('input',controller.handleInput);root.addEventListener('click',controller.handleClick);root.addEventListener('submit',controller.handleSubmit);render();
 });
 assert.equal(await page.locator('[name=scopeDn] option').count(),2,'domain must not be an FGPP OU option');
 await page.selectOption('[name=scopeDn]','OU=Users,DC=test,DC=local');await page.fill('[name=name]','GPOR-Reviewed');await page.fill('[name=minPasswordLength]','16');
 await page.locator('#fgpp-preview button').click();await page.locator('#fgpp-action').waitFor();
 assert.equal(await page.locator('#fgpp-action [value=apply]').count(),1);
 await page.fill('#fgpp-action [name=confirmation]','APPLY FGPP');await page.locator('#fgpp-action [value=apply]').click();
 await page.waitForFunction(()=>window.calls.some(x=>x.path.endsWith('/apply')));
 let calls=await page.evaluate(()=>window.calls);assert.equal(calls.find(x=>x.path.endsWith('/preview')).body.minPasswordLength,16);assert.equal(calls.find(x=>x.path.endsWith('/apply')).body.confirmation,'APPLY FGPP');
 await page.locator('#fgpp-action [value=verify]').click();await page.waitForFunction(()=>window.calls.some(x=>x.path.endsWith('/verify')));
 await page.fill('#fgpp-action [name=confirmation]','ROLLBACK FGPP');await page.locator('#fgpp-action [value=rollback]').click();await page.waitForFunction(()=>document.body.textContent.includes('ROLLED_BACK'));
 for(const width of [1280,390]){await page.setViewportSize({width,height:900});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'FGPP page overflows');}
 await page.fill('[name=name]','GPOR-NewReview');const before=(await page.evaluate(()=>window.calls)).length;
 assert.equal(await page.locator('#fgpp-action').count(),0,'editing removes stale confirmation controls');assert.equal((await page.evaluate(()=>window.calls)).length,before,'editing invalidates previous approved snapshot');
 assert.deepEqual(errors,[]);console.log('PASS FGPP UI: OU-only picker, values, preview/apply/verify/rollback, stale review invalidation and narrow viewport.');
 }finally{if(browser)await browser.close();server.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
