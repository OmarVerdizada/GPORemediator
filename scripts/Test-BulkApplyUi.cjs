/* Real optional batch UI, mocked durable HTTP jobs. Never contacts AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),shots=path.resolve(__dirname,'../work/screens/3.18.9');fs.mkdirSync(shots,{recursive:true});
const mappings=JSON.parse(fs.readFileSync(path.resolve(root,'../../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const gpo={id:'11111111-1111-1111-1111-111111111111',name:'Bulk test policy',protected:false,selectable:true},scope='OU=Mixed,DC=test,DC=local',endpoint='OU=Sessions,DC=test,DC=local';
const scopes=[{dn:'DC=test,DC=local',name:'test.local',kind:'Domain'},{dn:scope,name:'Mixed users and computers',kind:'OU'},{dn:endpoint,name:'Session computers',kind:'OU'},...Array.from({length:5000},(_,i)=>({dn:`OU=Unit${i},DC=test,DC=local`,name:`Unit${i}`,kind:'OU'}))];
const requests=[],jobs=[],batches=new Map();let runs=[],previewDone=false,applyDone=false,applyFailed=false,pollUnavailable=false,number=0;
function makePlan(s){const m=mappings.find(m=>m.id===s.setting),value=s.itemValues?.[0]?.join(',')??(m.allowValueOverride?String(s.value):m.requiresInput?s.customValue:m.handler==='AdvancedAudit'?String(m.items[0].mask):(m.items[0].value||[]).join(','));return {id:'plan-'+(++number),selection:s,writeAuthorized:true,executionUser:'TEST\\operator',preview:{gpo,scope:{dn:s.scopeDn,name:'Mixed',kind:'OU'},previousValue:null,desiredValue:value,existingLink:null,warnings:['Changing this GPO affects all of its links.'],relatedConflicts:[{severity:'HIGH',code:'SETTING_DEFINED_ELSEWHERE',message:'Competing value differs',gpoName:'Branch baseline',domain:'test.local',scope:s.scopeDn}],verificationComputers:['ws.test.local']}};}
function update(job){
 if(job.action==='preview'&&previewDone){job.state='COMPLETED';job.message='Batch preview ready.';job.completedIds=batches.get(job.batchId).plans.map(p=>p.id);}
 if(job.action==='apply'&&!['COMPLETED','NEEDS_REVIEW','CHECKS_INCOMPLETE'].includes(job.state)){
  const plans=batches.get(job.batchId).plans,ready=applyDone?plans:plans.slice(0,1);job.state=applyDone?(applyFailed?'NEEDS_REVIEW':'CHECKS_INCOMPLETE'):'RUNNING';job.completedIds=ready.map(p=>p.id);job.message=applyDone?(applyFailed?'Second write stopped; no remaining writes.':'GPO settings saved. Endpoint checks incomplete.'):'Applying 1 of '+plans.length;
  runs=ready.map(p=>({id:p.id,plan:p,updatedAt:'2026-11-05T06:00:00Z',result:{state:'PUBLISHED',backupId:'backup-'+p.id,gpoPublished:true,linkVerified:true,currentValue:p.preview.desiredValue,effectiveStatus:'ENDPOINT_VERIFICATION_PENDING',endpointChecks:[{hostname:'ws.test.local',state:'UNAVAILABLE',actualValue:null,message:'Native probe unavailable'}],refreshResults:[]}}));
 }
 return job;
}
const server=http.createServer(async(req,res)=>{try{let body='';for await(const chunk of req)body+=chunk;const payload=body?JSON.parse(body):{},url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/')){
 requests.push({path:url.pathname,method:req.method,payload});let data={};
 if(url.pathname==='/api/session')data={mode:'WINDOWS',csrfToken:'fixture',operator:'TEST\\operator'};
 else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
 else if(url.pathname==='/api/gpo/session')data={connected:true,sessionId:'bulk-session'};
 else if(url.pathname==='/api/gpo/settings')data=mappings;
 else if(url.pathname==='/api/gpo/inventory')data={gpos:[gpo],scopes,domain:'test.local',domainController:'dc.test.local',executionUser:'TEST\\operator'};
 else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
 else if(url.pathname==='/api/gpo/history')data=runs;
 else if(url.pathname.endsWith('/rollback-preview'))data={canRestore:true,reason:'READY',message:'Live snapshot matches',manifestPhase:'PUBLISHED',checkedAt:'2026-11-05T06:00:00Z'};
 else if(url.pathname==='/api/gpo/target-access')data={authorized:true};
 else if(url.pathname==='/api/setup/config')data={exists:true,domain:'test.local',domainController:'dc.test.local',approvedGpoIds:['*'],authorizedOus:['*'],endpointTargeting:'SelectedOu'};
 else if(url.pathname==='/api/workflows'&&req.method==='GET')data=jobs.map(update);
 else if(url.pathname==='/api/batches')data=[...batches.values()].map(x=>x.batch);
 else if(url.pathname.startsWith('/api/batches/'))data=batches.get(url.pathname.split('/').pop());
 else if(url.pathname.startsWith('/api/workflows/')&&req.method==='POST'){
  const action=url.pathname.split('/').pop();data={id:'job-'+(++number),action,state:'QUEUED',planIds:payload.planIds||[],completedIds:[],message:'Accepted',updatedAt:'2026-11-05T06:00:00Z'};
  if(action==='preview'){assert(payload.batch.selections.length<=20);const plans=payload.batch.selections.map(makePlan);data.batchId='batch-'+number;batches.set(data.batchId,{batch:{id:data.batchId,planIds:plans.map(p=>p.id)},plans});}
  if(action==='apply'){const b=batches.get(payload.batchId);assert.deepEqual(payload.planIds,b.batch.planIds);assert.equal(payload.consent.confirmation,'APPLY');assert.equal(payload.consent.acknowledgeImpact,true);data.batchId=payload.batchId;}
  if(action==='rollback'){const source=jobs.find(j=>j.id===payload.sourceWorkflowId);assert(source);assert.equal(payload.consent.confirmation,'ROLLBACK');data.sourceWorkflowId=source.id;data.state='COMPLETED';data.completedIds=[source.completedIds[0]];data.message='Batch snapshot restored.';runs=runs.map((r,i)=>({...r,result:{...r.result,state:i===0?'ROLLED_BACK':'BATCH_ROLLED_BACK',gpoPublished:false,linkVerified:false,effectiveStatus:'ROLLBACK_ENDPOINT_PENDING'}}));}
  if(action==='verify'){data.state='COMPLETED';data.completedIds=payload.planIds;data.message='Read-only checks complete.';}
  jobs.push(data);
 }else if(url.pathname.startsWith('/api/workflows/')){
  if(pollUnavailable){res.writeHead(503,{'Content-Type':'application/json'});res.end(JSON.stringify({message:'Temporary fixture outage'}));return;}
  data=update(jobs.find(j=>j.id===url.pathname.split('/').pop()));
 }
 else if(['/api/audit','/api/password-policies'].includes(url.pathname))data=[];
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
}catch(error){res.statusCode=500;res.end(JSON.stringify({message:error.message}));}});
(async()=>{let browser;try{await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(20000);const base='http://127.0.0.1:'+server.address().port;
 await page.goto(base+'/#/benchmark');await page.locator('[data-bulk-mode]').click();await page.fill('#catalog-search','17.1.1');await page.locator('[data-bulk-select="17.1.1"]').check();await page.fill('#catalog-search','19.7.5.2');await page.locator('[data-bulk-select="19.7.5.2"]').check();await page.locator('[data-bulk-open]').click();
 assert.equal(await page.getByRole('dialog',{name:'Prepare selected controls'}).count(),1);assert.equal(requests.filter(r=>r.method==='POST').length,0);
 assert.equal(await page.locator('.bulk-steps [aria-current=step]').textContent(),'Prepare');
 assert.equal(await page.locator('.bulk-control-card').count(),2);
 assert.match(await page.locator('.bulk-control-card').first().textContent(),/Success and Failure/);
 await page.selectOption('#bulk-gpoId',gpo.id);await page.fill('#bulk-scope-query','Unit4999');await page.waitForFunction(()=>!!document.querySelector('#bulk-scopeDn option[value="OU=Unit4999,DC=test,DC=local"]'));assert(await page.locator('#bulk-scopeDn option').count()<=201);await page.selectOption('#bulk-scopeDn','OU=Unit4999,DC=test,DC=local');await page.fill('#bulk-scope-query','');await page.waitForTimeout(300);assert.equal(await page.locator('#bulk-scopeDn').inputValue(),'OU=Unit4999,DC=test,DC=local','Filtering must preserve a selected OU outside the first 200');
 await page.fill('#bulk-scope-query','Mixed');await page.selectOption('#bulk-scopeDn',scope);await page.selectOption('#bulk-endpointScopeDn',endpoint);await page.fill('#bulk-verificationUser','TEST\\alice');await page.locator('#bulk-refresh').check();
 for(const theme of ['light','dark']){await page.evaluate(t=>document.documentElement.dataset.grTheme=t,theme);for(const width of [1440,390,320]){await page.setViewportSize({width,height:844});assert(await page.evaluate(()=>{const d=document.querySelector('.bulk-dialog').getBoundingClientRect();return d.left>=0&&d.right<=innerWidth&&d.top>=0&&d.bottom<=innerHeight;}));await page.locator('.bulk-dialog-body').evaluate(el=>{el.scrollTop=0});if(width!==320)await page.locator('.bulk-dialog').screenshot({path:path.join(shots,`bulk-prepare-${theme}-${width}.png`)});}}
 await page.setViewportSize({width:1440,height:1000});await page.locator('[data-bulk-form] button[type=submit]').click();await page.getByRole('heading',{name:'Checking selected controls',exact:true}).waitFor();assert.equal(requests.filter(r=>/\/apply$/.test(r.path)).length,0);assert.equal(await page.locator('[data-bulk-approval]').count(),0);
 const preview=requests.find(r=>r.path==='/api/workflows/preview').payload.batch.selections;assert.deepEqual(preview.map(s=>s.accountScope),['LocalComputers','Users']);assert.equal(preview[1].endpointScopeDn,endpoint);assert.equal(preview[1].verificationUser,'TEST\\alice');
 previewDone=true;await page.locator('[data-bulk-approval]').waitFor();assert.match(await page.locator('.bulk-table').textContent(),/Will be linked/);assert.match(await page.locator('.policy-conflicts').textContent(),/Branch baseline.*test.local/);await page.fill('#bulk-reference','CHG-BULK');await page.locator('#bulk-impact').check();await page.fill('#bulk-confirmation','APPLY');assert.equal(requests.filter(r=>/\/apply$/.test(r.path)).length,0);
 for(const theme of ['light','dark']){await page.evaluate(t=>document.documentElement.dataset.grTheme=t,theme);for(const width of [1440,390]){await page.setViewportSize({width,height:1000});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.locator('.bulk-dialog').screenshot({path:path.join(shots,`bulk-review-${theme}-${width}.png`)});}}
 await page.setViewportSize({width:1440,height:1000});await page.locator('[data-bulk-approval] button[type=submit]').click();await page.getByRole('heading',{name:'Applying selected controls',exact:true}).waitFor();assert.equal(requests.filter(r=>r.path==='/api/workflows/apply').length,1);assert.equal(requests.find(r=>r.path==='/api/workflows/apply').payload.refresh,'Auto');
 pollUnavailable=true;
 const pollWarning=page.locator('.bulk-dialog [role=alert]').filter({hasText:'Live updates unavailable'});
 await pollWarning.waitFor();
 pollUnavailable=false;
 await pollWarning.waitFor({state:'hidden'});
 assert.equal(requests.filter(r=>r.path==='/api/workflows/apply').length,1,'Recovering polling must only read the recorded workflow');
 await page.locator('.bulk-dialog>header [data-bulk-close]').click();await page.goto(base+'/#/operations');await page.reload();await page.locator('[data-bulk-job]').first().click();assert.equal(requests.filter(r=>r.path==='/api/workflows/apply').length,1,'Reloading must not resubmit approved writes');applyDone=true;await page.getByRole('heading',{name:'GPO settings saved',exact:true}).waitFor();assert.match(await page.locator('.bulk-table').textContent(),/1 unavailable/);await page.locator('.bulk-dialog').screenshot({path:path.join(shots,'bulk-result.png')});
 await page.getByRole('button',{name:'Review rollback',exact:true}).click();await page.locator('.ds-recovery [data-rollback-inspect]').click();await page.getByRole('button',{name:'Rollback this control',exact:true}).waitFor();assert.equal(requests.filter(r=>r.path==='/api/workflows/rollback').length,0);await page.locator('.ds-recovery [data-bulk-from-operation]').click();
 await page.locator('[data-bulk-recover]').click();await page.fill('#bulk-confirmation','ROLLBACK');await page.locator('[data-bulk-recovery] button[type=submit]').click();await page.getByRole('heading',{name:'Batch snapshot restored',exact:true}).waitFor();assert.equal(requests.filter(r=>r.path==='/api/workflows/rollback').length,1);assert.match(await page.locator('.bulk-table').textContent(),/Snapshot restored/);await page.locator('[data-bulk-inspect]').nth(1).click();await page.locator('.ds-recovery [data-bulk-from-operation]').waitFor();assert.equal(await page.locator('.ds-recovery [data-verify]').count(),0,'Restored child must use the full batch recovery receipt');await page.locator('.ds-recovery [data-bulk-from-operation]').click();await page.getByRole('heading',{name:'Batch snapshot restored',exact:true}).waitFor();await page.getByRole('button',{name:'Re-verify restored snapshot'}).click();await page.getByText('Read-only checks complete.',{exact:true}).waitFor();
 const verify=requests.filter(r=>r.path==='/api/workflows/verify');assert.equal(verify.length,1);assert.deepEqual(verify[0].payload.planIds,jobs.find(j=>j.action==='rollback').completedIds,'Re-verify must read the authoritative restore receipt only');
 await page.keyboard.press('Escape');assert.equal(await page.locator('.bulk-dialog').count(),0);assert.deepEqual(errors,[]);
 console.log('PASS real bulk UI: mixed user/computer selection, 5000-OU search and selected-value retention, read-only preview before approval, concrete links/values, Auto refresh, per-control results, light/dark/mobile, durable resume without replay and full-batch rollback');
}finally{await browser?.close();server.close();}})().catch(error=>{console.error(error);process.exitCode=1;});
