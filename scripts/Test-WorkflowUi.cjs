/* Presentation tests use recorded server states; coordinator/worker behavior is tested separately. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),screens=path.resolve(__dirname,'../work/screens');fs.mkdirSync(screens,{recursive:true});
const settings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings.map(m=>({...m,writable:m.automation==='Automated'&&['SecurityTemplate','Registry','RegistrySet','AdvancedAudit'].includes(m.handler)}));
const inventory={domain:'test.local',domainController:'dc.test.local',executionUser:'TEST\\executor',gpos:[{id:'11111111-1111-1111-1111-111111111111',name:'Pilot policy',protected:false,selectable:true}],scopes:[{dn:'OU=Pilot,DC=test,DC=local',name:'Pilot',kind:'OU'},{dn:'OU=Production,DC=test,DC=local',name:'Production',kind:'OU'}]};
const jobs=[],batches=[],history=[],requests=[];let serial=0,role='Administrator',boot=1,confirmations=0,connected=false;
function plan(selection){return {id:'plan-'+(++serial),actor:'TEST\\operator',executionUser:inventory.executionUser,domain:inventory.domain,domainController:inventory.domainController,selection,preview:{gpo:inventory.gpos[0],scope:inventory.scopes[0],previousValue:'Disabled',desiredValue:'Enabled',existingLink:{enabled:false,order:3,enforced:false},warnings:['Recorded warning'],impact:{affectedObjects:{computers:2}}}};}
function job(action,payload){const j={id:'job-'+(++serial),action,state:'COMPLETED',planIds:payload.planIds||[],completedIds:payload.planIds||[],createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),message:'Recorded server result',refresh:payload.refresh||'None',verificationDelays:payload.verificationDelays||[]};jobs.unshift(j);return j;}
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://localhost');let body='';for await(const part of req)body+=part;const payload=body?JSON.parse(body):{};
 if(url.pathname.startsWith('/api/')){
  let data={};res.setHeader('Content-Type','application/json');
  if(req.method==='POST'&&url.pathname!=='/api/operator/sign-in')requests.push({path:url.pathname,body:payload});
  if(url.pathname==='/api/session')data={mode:'WINDOWS',role,operator:'TEST\\operator',csrfToken:'test',domainSignIn:true,operatorConfirmationRequired:!String(req.headers.cookie).split('; ').includes('startup='+boot)};
  else if(url.pathname==='/api/operator/sign-in'){if(payload.password!=='fixture-password'||payload.userName!=='TEST\\executor'){res.statusCode=403;data={error:{code:'OPERATOR_PASSWORD_INVALID'}};}else{confirmations++;connected=true;res.setHeader('Set-Cookie',`startup=${boot}; Path=/; HttpOnly; SameSite=Strict`);data={confirmed:true};}}
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
  else if(url.pathname==='/api/gpo/settings')data=settings;
  else if(url.pathname==='/api/gpo/history')data=history;
  else if(url.pathname==='/api/gpo/inventory')data=inventory;
  else if(url.pathname==='/api/gpo/disconnect'){connected=false;data={disconnected:true};}
  else if(url.pathname==='/api/gpo/session')data={connected};
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
  else if(url.pathname==='/api/batches')data=batches.map(x=>x.batch);
  else if(url.pathname.startsWith('/api/batches/'))data=batches.find(x=>x.batch.id===url.pathname.split('/').pop());
  else if(url.pathname==='/api/workflows')data=jobs;
  else if(url.pathname==='/api/workflows/preview'){
   const plans=payload.batch.selections.map(plan),batch={id:'batch-'+(++serial),planIds:plans.map(p=>p.id),pilot:payload.batch.pilot,pilotLimit:payload.batch.pilotLimit};batches.push({batch,plans});
   data=job('preview',payload);Object.assign(data,{batchId:batch.id,selections:payload.batch.selections,completedIds:batch.planIds});res.statusCode=202;
  }else if(url.pathname==='/api/workflows/apply'){
   data=job('apply',payload);Object.assign(data,{state:'RUNNING',batchId:payload.batchId,completedIds:[],currentOperationId:payload.planIds[0]});
   for(const id of payload.planIds){const p=batches.flatMap(x=>x.plans).find(p=>p.id===id);history.push({id,plan:p,result:{state:'APPLYING',message:'Backup in progress',refreshResults:[]},stages:[{phase:'BACKUP',startedAt:new Date().toISOString()}]});}res.statusCode=202;
  }else if(url.pathname==='/api/workflows/scan'){
   data=job('scan',payload);Object.assign(data,{scanControls:payload.controls,scanRows:[{controlId:'1.2.3',state:'NOT_CHECKED',message:'Manual control'},{controlId:'2.3.1.1',state:'DIFFERENT',currentValue:'<img src=x onerror=alert(1)>',desiredValue:'Enabled',message:'Read-only comparison'}]});res.statusCode=202;
  }else if(url.pathname==='/api/workflows/rollback'){data=job('rollback',payload);res.statusCode=202;}
  res.end(JSON.stringify(data));return;
 }
 const file=path.join(root,url.pathname==='/'?'index.html':url.pathname);if(!file.startsWith(root)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});const errors=[];
 try{
  const context=await browser.newContext({viewport:{width:1440,height:1000}});let page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));const url=`http://127.0.0.1:${server.address().port}/#/workspace`;
  await page.goto(url);await page.locator('.operator-sign-in').waitFor();
  await page.locator('[name=actor]').fill('TEST\\executor');await page.screenshot({path:path.join(screens,'operator-startup-sign-in.png')});
  await page.locator('[name=password]').fill('wrong');await page.locator('.operator-sign-in button').click();await page.locator('.operator-sign-in-error:not(:empty)').waitFor();assert.equal(await page.locator('[name=password]').inputValue(),'');
  await page.locator('[name=password]').fill('fixture-password');await page.locator('.operator-sign-in button').click();await page.locator('.operator-sign-in').waitFor({state:'detached'});
  await page.reload();await page.locator('#wf-gpo option').waitFor({state:'attached'});assert.equal(await page.locator('.operator-sign-in').count(),0);assert.equal(confirmations,1);assert.equal(await page.locator('#gpo-login').count(),0);assert.equal(requests.filter(x=>x.path==='/api/gpo/connect').length,0);
  await page.locator('#wf-gpo option').waitFor({state:'attached'});await page.locator('#wf-pilot').check();
  await page.locator('#wf-search').fill('account');
  await page.locator('#wf-search').evaluate(el=>{el.setSelectionRange(1,5,'backward');el.dispatchEvent(new Event('input',{bubbles:true}));});
  assert.deepEqual(await page.locator('#wf-search').evaluate(el=>[el.selectionStart,el.selectionEnd,el.selectionDirection]),[1,5,'backward'],'Rendering must preserve the full text selection');
  await page.locator('#wf-search').fill('');
  await page.evaluate(()=>{document.activeElement?.blur();});
  // Establish the first snapshot, then observe a second, unchanged poll.
  await page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workflows');
  await page.waitForTimeout(100);
  await page.evaluate(()=>{window.__workflowField=document.getElementById('wf-search');});
  await page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workflows');
  await page.waitForTimeout(100);
  assert.ok(await page.evaluate(()=>window.__workflowField===document.getElementById('wf-search')),'Unchanged polling must keep the existing DOM');
  await page.locator('[data-scope-open="wf-scope"]').click();
  await page.locator('#scope-search').fill('Pilot');
  await page.locator('[data-scope-choose="OU=Pilot,DC=test,DC=local"]').click();
  await page.locator('[data-wf-control="2.3.1.1"]').check();await page.locator('[data-wf-control="2.3.1.2"]').check();
  await page.locator('[data-wf-preview]').click();await page.locator('[data-wf-batch]').click();await page.locator('#wf-approve').waitFor();
  assert.equal(requests[0].body.batch.selections.length,2);assert.equal(requests[0].body.batch.pilot,true);
  assert.ok((await page.locator('.wf-table').textContent()).includes('Disabled'));
  await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0);});await page.waitForTimeout(350);await page.screenshot({path:path.join(screens,'workflow-batch-review.png'),fullPage:true});
  async function approve(){await page.locator('#wf-approve [name=reference]').fill('CHANGE-42');await page.locator('#wf-approve [name=impact]').check();await page.locator('#wf-approve [name=confirmation]').fill('WRONG');assert.equal(await page.locator('#wf-approve [name=confirmation]').evaluate(el=>el.checkValidity()),false);await page.locator('#wf-approve [name=confirmation]').fill('APPLY');await page.locator('#wf-approve [name=refresh]').selectOption('Scope');await page.locator('#wf-approve button[type=submit],#wf-approve button.primary').click();await page.locator('.wf-dialog').waitFor();}
  await approve();assert.equal(requests.filter(r=>r.path.endsWith('/apply')).length,0);await page.locator('[data-wf-cancel]').click();assert.equal(requests.filter(r=>r.path.endsWith('/apply')).length,0);
  await approve();await page.locator('#wf-confirm button.primary').click();await page.locator('.wf-stages').first().waitFor();
  assert.ok((await page.locator('.wf-stages').first().textContent()).includes('BACKUP'));
  const apply=requests.find(r=>r.path.endsWith('/apply'));assert.equal(apply.body.refresh,'Scope');assert.deepEqual(apply.body.verificationDelays,[60,300,900]);assert.equal(apply.body.consent.changeReference,'CHANGE-42');
  // The browser closes while the recorded server job remains running.
  await page.close();const applied=jobs.find(j=>j.action==='apply');applied.state='COMPLETED';applied.completedIds=[...applied.planIds];applied.currentOperationId=null;
  history.forEach(r=>{r.result={state:'PUBLISHED',backupId:'backup-'+r.id,backupDirectory:'protected backup',message:'Publication verified',gpoPublished:true,linkVerified:true,currentValue:'Enabled',effectiveStatus:'ENDPOINT_VERIFICATION_PENDING',refreshResults:[],verification:{replicationConverged:false}};r.stages[0].finishedAt=new Date().toISOString();});
  page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(url);await page.locator('[data-wf-tab=jobs]').click();await page.locator(`[data-wf-job="${applied.id}"]`).waitFor();await page.locator(`[data-wf-job="${applied.id}"]`).click();
  assert.ok((await page.locator('#operator-modules').textContent()).includes('ENDPOINT_VERIFICATION_PENDING'));assert.ok(await page.locator(`a[href="/api/workflows/${applied.id}/report"]`).count());
  await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0);});await page.waitForTimeout(350);await page.screenshot({path:path.join(screens,'workflow-recorded-stages.png'),fullPage:true});
  await page.locator('[data-wf-tab=recovery]').click();assert.ok((await page.locator('#operator-modules').textContent()).includes('backup-'));
  await page.locator(`[data-wf-batch-rollback="${applied.id}"]`).first().click();await page.locator('#wf-confirm [name=confirmation]').fill('ROLLBACK');await page.locator('#wf-confirm [name=refresh]').selectOption('Scope');await page.locator('#wf-confirm button.primary').click();await page.locator('.wf-dialog').waitFor({state:'detached'});
  assert.equal(requests.find(r=>r.path.endsWith('/rollback')).body.sourceWorkflowId,applied.id);
  await page.locator('[data-wf-tab=prepare]').click();
  await page.locator('[data-scope-open="wf-scope"]').click();
  await page.locator('#scope-search').fill('Pilot');
  await page.locator('[data-scope-choose="OU=Pilot,DC=test,DC=local"]').click();
  await page.locator('[data-wf-all]').click();assert.equal(await page.locator('[data-wf-preview]').isDisabled(),true);await page.locator('[data-wf-scan]').click();
  await page.locator('.wf-summary').waitFor();assert.equal(requests.find(r=>r.path.endsWith('/scan')).body.controls.length,405);assert.equal(await page.locator('.wf-table img').count(),0);
  assert.ok((await page.locator('.wf-summary').textContent()).includes('NOT_CHECKED'));
  await page.setViewportSize({width:390,height:844});await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0);});await page.waitForTimeout(350);await page.screenshot({path:path.join(screens,'workflow-scan-mobile.png'),fullPage:true});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  const beforeGuideRequests=requests.length;
  await page.locator('a[href="#/dashboard"]').first().click();const summary=page.locator('[data-dashboard-remediation]');await summary.waitFor();
  assert.equal(await summary.locator('[data-remediation-total]').textContent(),'405');assert.equal(await summary.locator('[data-remediation-auto]').textContent(),'394');assert.equal(await summary.locator('[data-remediation-guided]').textContent(),'11');
  assert.equal(await summary.locator('[data-rule]').count(),11);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  await summary.screenshot({path:path.join(screens,'dashboard-remediation-mobile.png')});await page.setViewportSize({width:1440,height:1000});await summary.screenshot({path:path.join(screens,'dashboard-remediation-desktop.png')});
  await summary.locator('summary').click();await summary.locator('[data-rule="1.2.3"]').click();await page.locator('[data-remediation-guide="1.2.3"]').waitFor();await page.setViewportSize({width:390,height:844});
  for(const id of ['1.2.3','2.3.11.6','18.10.43.10.1','18.10.43.10.2']){
   await page.locator('a[href="#/benchmark"]').first().click();await page.locator('#catalog-search').fill(id);await page.waitForTimeout(350);
   if(!await page.locator(`[data-rule="${id}"]`).count())await page.locator('[data-domain]').first().click();
   await page.locator(`[data-rule="${id}"]`).first().click();await page.locator(`[data-remediation-guide="${id}"]`).waitFor();
   await page.locator('[data-tab="remediation"]').click();assert.equal(await page.locator('#gpo-selection,#gpo-apply,[data-enable-write]').count(),0);
   assert.ok(await page.locator('[data-guide-command=read] pre').count());
   await page.locator('[data-tab="verification"]').click();assert.equal(await page.locator('[data-verify]').count(),0);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  }
  const readBlock=page.locator('[data-guide-command=read]');const expectedCopy=await readBlock.locator('[data-copy-value]').getAttribute('data-copy-value');
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.guideCopied=text;}}}));
  await readBlock.locator('[data-copy-value]').click();assert.equal(await page.evaluate(()=>window.guideCopied),expectedCopy);
  await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0);});await page.screenshot({path:path.join(screens,'guided-remediation-mobile.png'),fullPage:false});
  assert.equal(requests.length,beforeGuideRequests,'Viewing guide must not submit operations');
  await page.setViewportSize({width:1440,height:1000});await page.locator('a[href="#/benchmark"]').first().click();await page.locator('#catalog-search').fill('');
  await page.locator('[data-domain="7"]').click();await page.locator('[data-domain-guidance="7"]').waitFor();
  assert.ok((await page.locator('[data-domain-guidance="7"]').textContent()).includes('405'));
  await page.locator('[data-domain-guidance="7"]').screenshot({path:path.join(screens,'empty-domain-guidance.png')});
  const beforeReports=requests.length;
  await page.locator('a[href="#/reports"]').first().click();
  await page.locator('.ent-table').waitFor();
  assert.equal(await page.locator('.ent-table tbody tr').count(),history.length);
  const downloadPromise=page.waitForEvent('download');
  await page.locator('[data-ent-export="json"]').click();
  const download=await downloadPromise;
  const reportPath=path.join(screens,'recorded-evidence.json');await download.saveAs(reportPath);
  const exported=JSON.parse(fs.readFileSync(reportPath,'utf8'));
  assert.equal(exported.count,history.length);assert.equal(exported.verifiedEvidence,0);
  await page.locator('[data-ent-filter="scope"]').fill('OU=NoMatch');
  await page.locator('[data-ent-filter="scope"]').dispatchEvent('change');
  assert.equal(await page.locator('.ent-table tbody tr td').count(),1);
  await page.locator('a[href="#/diagnostics"]').first().click();
  await page.locator('[data-ent-diagnose]').click();
  await page.locator('[data-ent-diagnose]:not([disabled])').waitFor();
  assert.ok((await page.locator('.ent-check-list').textContent()).includes('NOT_CHECKED'));
  assert.equal(requests.length,beforeReports,'Report exports and diagnostics must not mutate policies');
  await page.screenshot({path:path.join(screens,'studio-diagnostics.png'),fullPage:true});
  await page.locator('a[href="#/dashboard"]').first().click();await page.locator('.studio-overview').waitFor();
  await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0);});
  await page.screenshot({path:path.join(screens,'studio-dashboard.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.evaluate(()=>{document.activeElement?.blur();window.scrollTo(0,0);});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  await page.screenshot({path:path.join(screens,'studio-dashboard-mobile.png')});
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('a[href="#/dashboard"]').first().click();await page.locator('[data-disconnect]').click();await page.locator('[data-domain-sign-in]').waitFor();assert.equal(await page.locator('#gpo-login').count(),0);
  await page.locator('[data-domain-sign-in]').click();await page.locator('[name=actor]').fill('TEST\\executor');await page.locator('[name=password]').fill('fixture-password');await page.locator('.operator-sign-in button').click();await page.locator('.operator-sign-in').waitFor({state:'detached'});await page.locator('[data-disconnect]').waitFor();assert.equal(confirmations,2);
  boot++;connected=false;await page.reload();await page.locator('.operator-sign-in').waitFor();assert.equal(confirmations,2);
  assert.deepEqual(errors,[]);console.log('Workflow UI: PASS (batch review/approval/cancel, server stages/reopen/recovery, scan, escaping, mobile and all four guided controls without writes).');
 }finally{await browser.close();await new Promise(r=>server.close(r));}
})().catch(e=>{console.error(e);process.exitCode=1;});
