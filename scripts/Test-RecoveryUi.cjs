/* Browser integration regression. Requires Playwright; never contacts AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),screens=path.resolve(__dirname,'../work/screens');
fs.mkdirSync(screens,{recursive:true});
const gpos=[{id:'6ac1786c-016f-11d2-945f-00c04fb984f9',name:'Default Domain Controllers Policy',protected:true,selectable:true},{id:'31b2f340-016d-11d2-945f-00c04fb984f9',name:'Default Domain Policy',protected:true,selectable:true}];
const run={id:'recovery-test',startedAt:'2026-10-06T08:00:00Z',updatedAt:'2026-10-09T08:00:34Z',plan:{selection:{setting:'1.1.4',gpoId:gpos[0].id,scopeDn:'DC=test,DC=local'},preview:{gpo:gpos[0],scope:{dn:'DC=test,DC=local'},previousValue:0,desiredValue:14},executionUser:'TEST\\operator'},result:{state:'PUBLISHED',backupId:'test-backup-id',gpoPublished:true,linkVerified:true}};
const inventory={gpos,scopes:[{dn:'DC=test,DC=local',name:'test.local',kind:'Domain'},{dn:'OU=Users,DC=test,DC=local',name:'Users',kind:'OU'},{dn:'OU=Endpoints,DC=test,DC=local',name:'Endpoints',kind:'OU'}],domain:'test.local'};
let writes=[],refreshRequests=[],rollbackState='ROLLED_BACK',refreshFailure=false,workflowJobs=[];
const server=http.createServer(async(req,res)=>{
 let body='';for await(const chunk of req)body+=chunk;
 const payload=body?JSON.parse(body):{};
 const url=new URL(req.url,'http://localhost');
 if(url.pathname.startsWith('/api/')){
  let data={};
  if(url.pathname==='/api/session')data={mode:'WINDOWS',role:'Administrator',csrfToken:'test'};
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
  else if(url.pathname==='/api/gpo/history')data=[run];
  else if(url.pathname==='/api/gpo/settings')data=[{id:'1.1.4',scope:'Domain',automation:'Automated',handler:'SecurityTemplate',suggested:14,allowValueOverride:true,domainPolicySensitive:true},{id:'19.5.1.1',scope:'User',automation:'Automated',handler:'Registry',recommended:'Enabled',allowValueOverride:false,domainPolicySensitive:false}];
  else if(url.pathname==='/api/gpo/inventory')data=inventory;
  else if(url.pathname==='/api/gpo/session')data={connected:true};
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
  else if(url.pathname==='/api/workflows')data=workflowJobs;
  else if(url.pathname==='/api/batches')data=[];
  else if(url.pathname.startsWith('/api/workflows/')&&req.method==='POST'){
   const action=url.pathname.split('/').pop();let review=false;
   if(action==='rollback'){writes.push('/api/gpo/recovery-test/rollback');run.result.state=rollbackState;run.result.message='Rollback recorded';review=rollbackState!=='ROLLED_BACK';}
   if((action==='refresh'||action==='rollback'&&rollbackState==='ROLLED_BACK')&&payload.refresh!=='None'){
    writes.push('/api/gpo/recovery-test/refresh');refreshRequests.push({refresh:payload.refresh});
    if(refreshFailure){review=true;run.result.message='gpupdate /force needs review';}
    else{run.result.refreshResults=[{computer:'authorized.test.local',state:'SCHEDULED',message:'gpupdate /force scheduled'}];run.result.message='gpupdate /force scheduled';}
   }
   data={id:payload.requestId,action,state:review?'NEEDS_REVIEW':'COMPLETED',message:run.result.message,planIds:payload.planIds,completedIds:payload.planIds,createdAt:new Date().toISOString()};workflowJobs=[data];res.statusCode=202;
  }
  else if(url.pathname.endsWith('/rollback')){writes.push(url.pathname);run.result.state=rollbackState;run.result.message='Rollback recorded';data=run;}
  else if(url.pathname.endsWith('/refresh')){
   writes.push(url.pathname);refreshRequests.push(payload);
   if(refreshFailure){res.statusCode=503;data={code:'REFRESH_TEST_FAILURE',message:'Refresh test failure'};}
   else{run.result.refreshResults=[{computer:'authorized.test.local',state:'SCHEDULED',message:'gpupdate /force scheduled'}];run.result.message='gpupdate /force scheduled';data=run;}
  }
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.join(root,url.pathname==='/'?'index.html':url.pathname);
 if(!file.startsWith(root)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 const ext=path.extname(file);res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[ext]||'application/octet-stream');res.end(fs.readFileSync(file));
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/#/operations`);
  await page.locator('.ds-table').waitFor();
  assert.equal(await page.locator('.ds-activity-row').evaluate(el=>getComputedStyle(el).display),'grid');
  assert.ok(await page.locator('.ds-activity-duration').textContent().then(s=>s.includes('3')));
  await page.screenshot({path:path.join(screens,'operations-desktop.png'),fullPage:true});
  await page.locator('.ds-table button.ds-danger').click();
  await page.locator('.ds-recovery input').fill('WRONG');
  assert.equal(await page.locator('.ds-recovery input').evaluate(el=>el.checkValidity()),false);
  await page.locator('.ds-recovery input').fill('ROLLBACK');
  await page.screenshot({path:path.join(screens,'rollback-details.png')});
  await page.locator('.ds-recovery button[type=submit]').click();
  await page.locator('.confirm-dialog').waitFor();
  assert.ok((await page.locator('.confirm-dialog').textContent()).includes('test-backup-id'));
  assert.equal(writes.length,0,'Confirmation must precede writes');
  await page.locator('[data-confirm-cancel]').click();
  assert.equal(writes.length,0,'Cancel must not write');
  await page.locator('.ds-table button.ds-danger').click();
  await page.locator('.ds-recovery input').fill('ROLLBACK');
  await page.locator('.ds-recovery button[type=submit]').click();
  await page.locator('[data-confirm-run]').click();
  await page.locator('.ds-table button.ds-danger').waitFor({state:'detached'});
  assert.deepEqual(writes,['/api/gpo/recovery-test/rollback']);
  await page.locator('[data-ops-layout=cards]').click();
  assert.equal(await page.locator('[data-rollback]').count(),0,'Restored run cannot be restored again');
  assert.equal(await page.locator('[data-gpupdate]').count(),1,'Restored card exposes one refresh action');
  // Default refresh=None in the original plan must not hide recovery refresh.
  await page.locator('[data-inspect]').first().click();
  await page.locator('.product-drawer .ds-recovery [data-gpupdate]').click();
  await page.locator('#refresh-target').selectOption('Scope');
  await page.locator('[data-confirm-run]').click();
  await page.locator('.busy-layer').waitFor({state:'detached'});
  assert.deepEqual(refreshRequests,[{refresh:'Scope'}]);
  await page.locator('[data-inspect]').first().click();
  assert.ok((await page.locator('.product-drawer .ds-refresh-results').textContent()).includes('authorized.test.local'));
  await page.locator('button[data-product-close]').click();
  async function recoveryScenario(strategy,resultState='ROLLED_BACK',failRefresh=false){
   run.result={state:'PUBLISHED',backupId:'test-backup-id',gpoPublished:true,linkVerified:true};
   writes=[];refreshRequests=[];rollbackState=resultState;refreshFailure=failRefresh;
   await page.reload();await page.locator('[data-rollback]').waitFor();
   await page.locator('[data-rollback] input').fill('ROLLBACK');
   await page.locator('[data-rollback] select').selectOption(strategy);
   await page.locator('[data-rollback] button[type=submit]').click();
   await page.locator('.confirm-dialog').waitFor();
   assert.ok((await page.locator('.confirm-dialog').textContent()).includes('gpupdate /force'));
   assert.equal(writes.length,0);
   await page.locator('[data-confirm-run]').click();
   await page.locator('.busy-layer').waitFor({state:'detached'});
  }
  for(const strategy of ['Scope','Pdc']){
   await recoveryScenario(strategy);
   assert.deepEqual(writes,['/api/gpo/recovery-test/rollback','/api/gpo/recovery-test/refresh']);
   assert.deepEqual(refreshRequests,[{refresh:strategy}]);
  }
  await recoveryScenario('None');assert.deepEqual(writes,['/api/gpo/recovery-test/rollback']);
  await recoveryScenario('Scope','ROLLBACK_REVIEW_REQUIRED');
  assert.deepEqual(writes,['/api/gpo/recovery-test/rollback'],'Incomplete restore must not refresh');
  await recoveryScenario('Scope','ROLLED_BACK',true);
  assert.equal(run.result.state,'ROLLED_BACK','Refresh failure must preserve completed restore');
  assert.ok((await page.locator('.ds-toast').textContent()).includes('gpupdate /force'));
  refreshFailure=false;
  await page.goto(`http://127.0.0.1:${server.address().port}/#/benchmark`);
  await page.locator('[data-domain="1"]').click();
  const sub=page.locator('[data-subsection="1.1"]');if(await sub.count())await sub.click();
  await page.locator('[data-rule="1.1.4"]').first().click();
  await page.locator('[data-tab=remediation]').click();
  await page.locator('[data-gpo-toggle]').click();
  await page.locator('.gpo-modal').waitFor();
  assert.equal(await page.locator('.gpo-option').first().evaluate(el=>getComputedStyle(el).display),'grid');
  assert.ok(await page.locator('.gpo-option-copy').first().boundingBox().then(b=>b.width>300));
  await page.screenshot({path:path.join(screens,'gpo-desktop.png')});
  await page.locator('#gpo-search').fill('Domain Controllers');
  assert.equal(await page.locator('.gpo-option').count(),1);
  await page.locator('#gpo-search').fill('no-such-policy');
  assert.equal(await page.locator('.gpo-modal-empty').count(),1);
  await page.locator('#gpo-search').fill('');
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(screens,'gpo-mobile.png')});
  assert.ok(await page.locator('.gpo-modal').evaluate(el=>el.scrollWidth<=el.clientWidth));
  await page.locator('.gpo-option').first().click();
  await page.goto(`http://127.0.0.1:${server.address().port}/#/operations`);
  await page.locator('.ds-activity-row').waitFor();
  await page.screenshot({path:path.join(screens,'operations-mobile.png'),fullPage:true});
  assert.ok(await page.locator('.ds-activity').evaluate(el=>el.scrollWidth<=el.clientWidth));
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(`http://127.0.0.1:${server.address().port}/#/benchmark`);
  if(await page.locator('[data-dismiss-notice]').count())await page.locator('[data-dismiss-notice]').click();
  await page.locator('[data-domain="19"]').click({force:true});
  await page.locator('[data-rule="19.5.1.1"]').first().click();
  await page.locator('[data-tab=remediation]').click();
  assert.equal(await page.locator('#gpo-selection [name=endpointScopeDn]').count(),1);
  assert.equal(await page.locator('#gpo-selection [name=verificationUser]').count(),1);
  assert.equal(await page.locator('#gpo-selection input[value=Pdc]').count(),0,'User policy exposed a PDC refresh choice');
  await page.locator('#gpo-selection [name=scopeDn]').selectOption('OU=Users,DC=test,DC=local');
  await page.locator('#gpo-selection [name=endpointScopeDn]').selectOption('OU=Endpoints,DC=test,DC=local');
  await page.locator('#gpo-selection [name=verificationUser]').fill('TEST\\pilot.user');
  assert.deepEqual(errors,[]);
  console.log('Recovery UI: PASS (desktop/mobile, recovery refresh, user OU/endpoint OU/verification identity targeting, and user PDC exclusion).');
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
