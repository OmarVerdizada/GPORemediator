/* Browser integration regression. Requires Playwright; never contacts AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),screens=path.resolve(__dirname,'../work/screens');
fs.mkdirSync(screens,{recursive:true});
const gpos=[{id:'6ac1786c-016f-11d2-945f-00c04fb984f9',name:'Protected controller policy',protected:true,selectable:true},{id:'31b2f340-016d-11d2-945f-00c04fb984f9',name:'Protected domain policy',protected:true,selectable:true}];
gpos.push({id:'11111111-1111-1111-1111-111111111111',name:'GPO-Pilot-Computers',protected:false,selectable:true});
const run={id:'recovery-test',startedAt:'2026-10-06T08:00:00Z',updatedAt:'2026-10-09T08:00:34Z',plan:{selection:{setting:'1.1.4',gpoId:gpos[0].id,scopeDn:'DC=test,DC=local'},preview:{gpo:gpos[0],scope:{dn:'DC=test,DC=local'},previousValue:0,desiredValue:14},executionUser:'TEST\\operator'},result:{state:'PUBLISHED',backupId:'test-backup-id',gpoPublished:true,linkVerified:true}};
const inventory={gpos,scopes:[{dn:'DC=test,DC=local',name:'test.local',kind:'Domain'},{dn:'OU=Users,DC=test,DC=local',name:'Users',kind:'OU'},{dn:'OU=Endpoints,DC=test,DC=local',name:'Endpoints',kind:'OU'}],domain:'test.local'};
let writes=[],refreshRequests=[],rollbackState='ROLLED_BACK',refreshFailure=false,workflowJobs=[];
const jobPosts=[],manualMappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const previewSelections=[];let previewDenied=null,accessDenied=null,accessDelay=0;const accessRequests=[];
inventory.domainController='dc.test.local';inventory.executionUser='TEST\\operator';
const server=http.createServer(async(req,res)=>{
 // The target-access POST is a read-only probe that can finish after a tab switch.
 // Keep it out of the job counter while still rejecting previews or actual writes.
 if(req.method==='POST'&&new URL(req.url,'http://localhost').pathname!=='/api/gpo/target-access')jobPosts.push(req.url);
 let body='';for await(const chunk of req)body+=chunk;
 const payload=body?JSON.parse(body):{};
 const url=new URL(req.url,'http://localhost');
 if(url.pathname.startsWith('/api/')){
  let data={};
  if(url.pathname==='/api/session')data={mode:'WINDOWS',csrfToken:'test'};
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
  else if(url.pathname==='/api/gpo/history')data=[run];
  else if(url.pathname==='/api/gpo/settings')data=manualMappings;
  else if(url.pathname==='/api/gpo/target-access'){accessRequests.push(payload);const denied=accessDenied,delay=accessDelay;if(delay)await new Promise(r=>setTimeout(r,delay));if(denied){res.statusCode=403;res.end(JSON.stringify({code:denied,message:'Fixture permission denied'}));return;}data={authorized:true,executionUser:'TEST\\operator'};}
  else if(url.pathname==='/api/gpo/preview'){
   previewSelections.push(payload);
   if(previewDenied){res.statusCode=403;res.end(JSON.stringify({code:previewDenied,message:'Fixture permission denied'}));return;}
   data={id:'preview-fixture',selection:payload,executionUser:'TEST\\operator',writeAuthorized:true,preview:{gpo:gpos.find(x=>x.id===payload.gpoId),scope:{dn:payload.scopeDn,kind:payload.accountScope==='Domain'?'Domain':'OU',name:'Users'},previousValue:'0',desiredValue:'1',existingLink:null,refreshComputers:['ws.test.local'],warnings:['User OU policy applies to all eligible users.'],impact:{inheritance:'NORMAL',conflicts:[],existingLinkScopes:[],securityFiltering:[],affectedObjects:{targetKind:'User',scopeDn:payload.scopeDn,users:3,sampleUsers:['one','two','three'],computers:0,servers:0,workstations:0,disabled:0,sampleHosts:[],truncated:false}}}};
  }
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
  page.setDefaultTimeout(20000);page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/#/benchmark`);
  const largeDomain=page.locator('[data-domain="18"]');await largeDomain.scrollIntoViewIfNeeded();
  await largeDomain.click();assert.equal(await largeDomain.getAttribute('aria-expanded'),'true');
  const allRules=JSON.parse(fs.readFileSync(path.join(root,'benchmark-v4.json'),'utf8')).rules.filter(r=>r.id.startsWith('18.')).length;
  assert.ok(await page.locator('#catalog-domain-18 .recipe-card').count()<allRules);
  await page.screenshot({path:path.join(screens,'benchmark-subsections-desktop.png')});
  await page.locator('[data-catalog-section="18"]').selectOption('ALL');
  assert.equal(await page.locator('#catalog-domain-18 .recipe-card').count(),allRules);
  const next=page.locator('[data-domain="19"]');await next.scrollIntoViewIfNeeded();const anchor=(await next.boundingBox()).y;await next.click();
  assert.ok(Math.abs((await next.boundingBox()).y-anchor)<6,'Changing expanded domain moved the clicked header');
  assert.equal(await largeDomain.getAttribute('aria-expanded'),'false');
  await page.keyboard.press('ArrowUp');assert.equal(await page.locator('[data-domain="18"]').evaluate(el=>el===document.activeElement),true);
  await page.locator('#catalog-search').fill('17.2.1');await page.locator('[data-rule="17.2.1"]').first().waitFor();
  await page.locator('[data-domain="17"]').click();assert.equal(await page.locator('[data-rule="17.2.1"]').count(),0);
  await page.locator('[data-domain="17"]').click();await page.locator('[data-rule="17.2.1"]').first().waitFor();
  await page.locator('#catalog-search').fill('');await page.locator('[data-domain="1"]').waitFor();
  await page.setViewportSize({width:390,height:844});await page.locator('[data-domain="18"]').click();
  await page.locator('[data-catalog-section="18"]').selectOption({index:0});
  await page.locator('[data-domain="18"]').scrollIntoViewIfNeeded();
  assert.ok(await page.locator('.catalog-section-bar').evaluate(el=>el.scrollWidth<=el.clientWidth),'Subsection navigation overflows on mobile');
  await page.screenshot({path:path.join(screens,'benchmark-subsections-mobile.png')});
  await page.setViewportSize({width:1440,height:1000});
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
  await page.waitForFunction(()=>['Rolled back','Rolled back'].some(x=>document.querySelector('.ds-table')?.textContent.includes(x)));
  assert.deepEqual(writes,['/api/gpo/recovery-test/rollback']);
  await page.locator('[data-ops-layout=cards]').click();
  assert.equal(await page.locator('[data-rollback]').count(),1,'Restored run must offer another confirmed restore');
  await page.locator('[data-rollback] input').fill('ROLLBACK');
  await page.locator('[data-rollback] button[type=submit]').click();await page.locator('[data-confirm-run]').click();
  await page.waitForFunction(()=>!document.querySelector('.busy-layer'));
  assert.deepEqual(writes,['/api/gpo/recovery-test/rollback','/api/gpo/recovery-test/rollback'],'Second confirmed rollback was not submitted');
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
  run.result={state:'PUBLISHED',backupId:'test-backup-id',gpoPublished:true,linkVerified:true,effectiveStatus:'VERIFIED_ON_SAMPLE',endpointChecks:[{hostname:'DC-01.test.local',state:'VERIFIED',message:'Value read directly.',actualValue:'MinimumPasswordLength=14'}]};
  run.result.verificationStages=[{stage:'GPO_CONFIGURATION',status:'GPO_APPLIED',evidence:'Stored value only.'},{stage:'GPO_APPLICABILITY',status:'INSUFFICIENT_EVIDENCE',evidence:'Target RSoP required.'},{stage:'AD_SYSVOL_REPLICATION',status:'VERIFIED',evidence:'Fixture content matches.'},{stage:'CLIENT_PROCESSING',status:'GPUPDATE_SCHEDULED',evidence:'No completion telemetry.'},{stage:'ENDPOINT_CONFIGURATION',status:'ENDPOINT_VERIFIED',evidence:'Sample configuration only.'}];
  await page.reload();
  await page.goto(`http://127.0.0.1:${server.address().port}/#/benchmark`);
  await page.locator('[data-domain="1"]').click();
  const sub=page.locator('[data-subsection="1.1"]');if(await sub.count())await sub.click();
  await page.locator('[data-rule="1.1.4"]').first().click();
  await page.locator('[data-tab=remediation]').click();
  await page.locator('[data-gpo-toggle]').click();
  await page.locator(`[data-gpo="${gpos[1].id}"]`).click();
  await page.locator('#gpo-selection [name=value]').fill('20');
  await page.locator('[data-tab=overview]').click();
  const postsBeforeManual=jobPosts.length;
  assert.ok((await page.locator('.manual-script-source').textContent()).includes("$Action = 'Preview'"));
  assert.ok((await page.locator('.manual-script-source').textContent()).includes(`$GpoId = '${gpos[1].id}'`));
  assert.ok((await page.locator('.manual-script-source').textContent()).includes('operator-selected values'),'Edited values did not reach the manual script');
  assert.ok((await page.locator('.manual-script-source').textContent()).includes('"value":["20"]'));
  await page.locator('[data-manual-action=Apply]').click();
  let displayedManual=await page.locator('.manual-script-source code').textContent();
  assert.ok(displayedManual.includes("$Action = 'Apply'"));
  assert.equal(await page.locator('.manual-code-actions [data-copy-value]').getAttribute('data-copy-value'),displayedManual);
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.manualCopied=text;}}}));
  await page.locator('.manual-code-actions [data-copy-value]').click();
  assert.equal(await page.evaluate(()=>window.manualCopied),displayedManual);
  const downloadPromise=page.waitForEvent('download');
  await page.locator('[data-manual-download]').click();
  const manualDownload=await downloadPromise,manualFile=path.resolve(__dirname,'../work/audit/manual-ui-export.ps1');
  await manualDownload.saveAs(manualFile);
  const manualBytes=fs.readFileSync(manualFile);
  assert.equal(manualBytes.subarray(0,3).toString('hex'),'efbbbf','PS1 exports need a UTF-8 BOM for Windows PowerShell 5.1');
  assert.equal(manualBytes.subarray(3).toString('utf8'),displayedManual,'Downloaded code differs from the visible script');
  await page.locator('.manual-procedure').screenshot({path:path.join(screens,'manual-procedure-desktop.png'),style:'#service-bar,.sidebar,.skip-link,.toast,.ds-toast{visibility:hidden !important}'});
  await page.setViewportSize({width:390,height:844});
  const manualBounds=await page.locator('.manual-procedure').boundingBox();
  assert.ok(manualBounds.x>=0&&manualBounds.x+manualBounds.width<=390,'Manual procedure escapes mobile viewport');
  await page.locator('.manual-procedure').screenshot({path:path.join(screens,'manual-procedure-mobile.png'),style:'#service-bar,.sidebar,.skip-link,.toast,.ds-toast{visibility:hidden !important}'});
  await page.setViewportSize({width:1440,height:1000});
  assert.equal(jobPosts.length,postsBeforeManual,'Viewing, switching, copying and downloading manual scripts must never submit a server job');
  await page.locator('[data-tab=remediation]').click();
  await page.locator('.policy-value-editor').screenshot({path:path.join(screens,'custom-policy-value.png')});
  await page.locator('[data-recommended-values]').click();
  assert.equal(await page.locator('#gpo-selection [name=value]').inputValue(),'14','Recommendation reset failed');
  await page.locator('[data-tab=verification]').click();
  await page.locator('.ux-more-tabs summary').click();
  assert.equal(await page.locator('.control-header').evaluate(el=>getComputedStyle(el).overflow),'visible');
  await page.locator('[data-tab=impact]').evaluate(el=>{const b=el.getBoundingClientRect();if(!el.contains(document.elementFromPoint(b.x+b.width/2,b.y+b.height/2)))throw new Error('Advanced menu item is clipped or covered');});
  await page.screenshot({path:path.join(screens,'advanced-tabs-desktop.png')});
  await page.locator('[data-tab=impact]').click();
  assert.equal(await page.locator('.ux-more-tabs').getAttribute('open'),null,'Selecting an advanced tab must close its dropdown');
  await page.locator('.ux-more-tabs summary').click();
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('.ux-more-tabs').getAttribute('open'),null,'Escape must close advanced tabs');
  await page.locator('.ux-more-tabs summary').click();
  await page.locator('h1').first().click();
  assert.equal(await page.locator('.ux-more-tabs').getAttribute('open'),null,'Outside click must close advanced tabs');
  await page.setViewportSize({width:390,height:844});
  await page.locator('.ux-more-tabs summary').click();
  const menuBounds=await page.locator('.ux-more-tabs>div').boundingBox();
  await page.screenshot({path:path.join(screens,'advanced-tabs-mobile.png')});
  assert.ok(menuBounds.x>=0&&menuBounds.x+menuBounds.width<=390,'Advanced menu escapes mobile viewport: '+JSON.stringify(menuBounds));
  await page.locator('[data-tab=audit]').click();
  assert.equal(await page.locator('.ux-more-tabs').getAttribute('open'),null);
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('[data-tab=verification]').click();
  await page.locator('.endpoint-evidence').waitFor();
  await page.locator('.manual-check-command').waitFor();
  assert.ok((await page.locator('.manual-check-command').textContent()).includes('secedit.exe /export /mergedpolicy'));
  assert.equal(await page.locator('.manual-check-head [data-copy-value]').count(),1);
  assert.equal(await page.locator('.assurance-stage-list>.assurance-stage').count(),5);
  assert.notEqual(await page.locator('.assurance-stage.good').first().evaluate(el=>getComputedStyle(el).borderLeftColor),await page.locator('.assurance-stage.info').first().evaluate(el=>getComputedStyle(el).borderLeftColor));
  assert.equal(await page.locator('.assurance-group-heading').count(),2);
  assert.equal(await page.locator('.assurance-grid').count(),0,'Duplicate legacy status boxes must not contradict server evidence');
  assert.equal(await page.locator('.assurance-stage code').first().isVisible(),false,'Technical status codes should stay in collapsed evidence details');
  assert.ok((await page.locator('.assurance-stage-list').textContent()).includes('INSUFFICIENT_EVIDENCE'));
  assert.ok((await page.locator('.assurance-stage-list').textContent()).includes('GPUPDATE_SCHEDULED'));
  await page.screenshot({path:path.join(screens,'audit-verification-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(screens,'audit-verification-mobile.png'),fullPage:true});
  for(const card of await page.locator('.assurance-stage').all()){
    const bounds=await card.boundingBox();
    assert.ok(bounds.x>=0&&bounds.x+bounds.width<=390,'Assurance card escapes mobile viewport');
  }
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('[data-tab=remediation]').click();
  await page.locator('[data-gpo-toggle]').click();
  await page.locator('.gpo-modal').waitFor();
  assert.equal(await page.locator('.gpo-option').first().evaluate(el=>getComputedStyle(el).display),'grid');
  assert.ok(await page.locator('.gpo-option-copy').first().boundingBox().then(b=>b.width>300));
  await page.screenshot({path:path.join(screens,'gpo-desktop.png')});
  await page.locator('#gpo-search').fill('Protected domain policy');
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
  await page.locator('[data-catalog-section="19"]').selectOption('19.5.1');
  await page.locator('[data-rule="19.5.1.1"]').first().click();
  assert.ok((await page.locator('.manual-script-source').textContent()).includes("$Action = 'Preview'"),'Changing controls must reset manual script mode');
  await page.locator('[data-tab=remediation]').click();
  assert.equal(await page.locator('#gpo-selection [name=endpointScopeDn]').count(),1);
  assert.equal(await page.locator('#gpo-selection [name=verificationUser]').count(),1);
  await page.locator('#gpo-selection .target-scope-note').screenshot({path:path.join(screens,'user-scope-card-desktop.png')});
  const userViewport=page.viewportSize();
  await page.setViewportSize({width:390,height:844});
  await page.locator('#gpo-selection .target-scope-note').screenshot({path:path.join(screens,'user-scope-card-mobile.png')});
  await page.setViewportSize(userViewport);
  assert.equal(await page.locator('#gpo-selection input[value=Pdc]').count(),0,'User policy exposed a PDC refresh choice');
  await page.locator('[data-scope-open="scopeDn"]').click();
  await page.locator('#scope-search').fill('Users');
  await page.locator('[data-scope-choose="OU=Users,DC=test,DC=local"]').click();
  await page.locator('[data-scope-open="endpointScopeDn"]').click();
  await page.locator('#scope-search').fill('Endpoints');
  await page.locator('[data-scope-choose="OU=Endpoints,DC=test,DC=local"]').click();
  assert.equal(await page.locator('#gpo-selection [name=verificationUser]').getAttribute('required'),null);
  await page.locator('[data-gpo-toggle]').click();
  await page.locator(`[data-gpo="${gpos[1].id}"]`).click();
  await page.locator('#gpo-selection .refresh-choice:has(input[value=Scope])').click();
  await page.locator('#gpo-selection button[type=submit],#gpo-selection>.primary-action').click();
  await page.waitForFunction(()=>!!document.querySelector('.plan-card'));
  assert.equal(previewSelections.at(-1).verificationUser,'');
  assert.equal(previewSelections.at(-1).scopeDn,'OU=Users,DC=test,DC=local');
  assert.equal(previewSelections.at(-1).refresh,'Scope');
  await page.screenshot({path:path.join(screens,'ou-wide-user-policy.png'),fullPage:true});
  // Domain password controls may use any active GPO, but always target the
  // domain root at link priority 1 so the resulting account policy is effective.
  await page.goto(`http://127.0.0.1:${server.address().port}/#/benchmark`);
  await page.locator('#catalog-search').fill('1.1.1');await page.locator('[data-rule="1.1.1"]').first().click();
  await page.locator('[data-tab=remediation]').click();
  assert.ok((await page.locator('.target-scope-note').textContent()).includes('Domain account policy'));
  assert.equal(await page.locator('#gpo-selection input[name=refresh][value=Scope]').count(),0);
  assert.equal(await page.locator('#gpo-selection input[name=firstLink]').count(),0);
  assert.equal(await page.locator('#gpo-selection>.primary-action').isDisabled(),true);
  await page.locator('[data-gpo-toggle]').click();assert.equal(await page.locator('.gpo-option').count(),3);
  await page.locator('[data-gpo="11111111-1111-1111-1111-111111111111"]').click();
  assert.equal(await page.locator('.target-access-error').count(),0);assert.equal(await page.locator('#gpo-selection>.primary-action').isDisabled(),false);
  await page.locator('[data-scope-open="scopeDn"]').click();
  assert.ok((await page.locator('.visual-scope-head p').textContent()).includes('Select a domain or OU'));
  assert.ok(await page.locator('.visual-scope-item:has-text("Endpoints")').count()>0);
  assert.equal(await page.locator('[data-scope-choose^="OU="]').count(),2,'Local account OU targets are missing');
  await page.locator('[data-scope-choose="OU=Endpoints,DC=test,DC=local"]').click();
  assert.equal(await page.locator('#gpo-selection input[name=refresh][value=Pdc]').count(),0);
  await page.locator('.refresh-choice:has(input[value=Scope])').click();
  await page.locator('#gpo-selection>.primary-action').click();await page.waitForFunction(()=>!!document.querySelector('.plan-card'));
  assert.equal(previewSelections.at(-1).accountScope,'LocalComputers');assert.equal(previewSelections.at(-1).scopeDn,'OU=Endpoints,DC=test,DC=local');assert.equal(previewSelections.at(-1).refresh,'Scope');
  await page.locator('[data-scope-open="scopeDn"]').click();
  await page.locator('[data-scope-choose="DC=test,DC=local"]').click();
  await page.locator('.refresh-choice:has(input[value=Pdc])').click();
  await page.screenshot({path:path.join(screens,'domain-account-targeting.png'),fullPage:true});
  await page.locator('#gpo-selection>.primary-action').click();await page.waitForFunction(()=>!!document.querySelector('.plan-card'));
  assert.equal(previewSelections.at(-1).gpoId,'11111111-1111-1111-1111-111111111111');
  assert.equal(previewSelections.at(-1).accountScope,'Domain');assert.equal(previewSelections.at(-1).firstLink,true);assert.equal(previewSelections.at(-1).refresh,'Pdc');
  await page.goto(`http://127.0.0.1:${server.address().port}/#/benchmark`);
  await page.locator('#catalog-search').fill('2.3.1.1');await page.locator('[data-rule="2.3.1.1"]').first().click();await page.locator('[data-tab=remediation]').click();
  await page.locator('[data-gpo-toggle]').click();await page.locator('[data-gpo="11111111-1111-1111-1111-111111111111"]').click();
  await page.locator('[data-scope-open="scopeDn"]').click();assert.equal(await page.locator('[data-scope-choose="DC=test,DC=local"]').count(),1,'Computer domain target missing');
  await page.locator('[data-scope-choose="OU=Endpoints,DC=test,DC=local"]').click();
  assert.equal(await page.locator('#gpo-selection input[value=Pdc]').count(),0);assert.equal(await page.locator('#gpo-selection input[value=Scope]').count(),1);
  await page.screenshot({path:path.join(screens,'computer-ou-targeting.png'),fullPage:true});
  // Selection itself checks permissions without creating a preview.
  const plansBeforeAccess=previewSelections.length;accessDenied='GPO_EDIT_ACCESS_DENIED';
  await page.locator('[data-gpo-toggle]').click();await page.locator('[data-gpo="11111111-1111-1111-1111-111111111111"]').click();
  await page.waitForFunction(()=>document.querySelector('#target-access-feedback')?.textContent.includes('Edit settings'));
  assert.equal(previewSelections.length,plansBeforeAccess);assert.ok(accessRequests.length>0);assert.ok((await page.locator('#target-access-feedback').textContent()).includes(inventory.executionUser));
  accessDenied=null;await page.locator('[data-scope-open="scopeDn"]').click();await page.locator('[data-scope-choose="OU=Endpoints,DC=test,DC=local"]').click();
  await page.waitForFunction(()=>document.querySelector('#target-access-feedback')?.textContent.includes('Initial write'));
  // An old target's delayed denial must not overwrite a new target's result.
  accessDenied='OU_LINK_ACCESS_DENIED';accessDelay=600;
  await page.locator('[data-scope-open="scopeDn"]').click();await page.locator('[data-scope-choose="OU=Users,DC=test,DC=local"]').click();
  await page.waitForRequest(r=>new URL(r.url()).pathname==='/api/gpo/target-access');
  accessDenied=null;accessDelay=0;await page.locator('[data-scope-open="scopeDn"]').click();await page.locator('[data-scope-choose="OU=Endpoints,DC=test,DC=local"]').click();
  await page.waitForFunction(()=>document.querySelector('#target-access-feedback')?.textContent.includes('Initial write'));await page.waitForTimeout(700);assert.equal(await page.locator('#target-access-feedback .target-access-error').count(),0);
  for(const [code,needle] of [['GPO_EDIT_ACCESS_DENIED','Edit settings'],['OU_LINK_ACCESS_DENIED','Link GPOs'],['SYSVOL_WRITE_ACCESS_DENIED','SYSVOL'],['GPO_ACCESS_UNVERIFIED','could not be verified']]){
   previewDenied=code;await page.locator('#gpo-selection>.primary-action').click();
   await page.waitForFunction(text=>[...document.querySelectorAll('.target-access-error')].some(el=>el.textContent.includes(text)),needle);
   assert.equal(await page.locator('.plan-card').count(),0);
  }
  await page.screenshot({path:path.join(screens,'target-access-guidance.png'),fullPage:true});
  previewDenied=null;await page.locator('#gpo-selection>.primary-action').click();await page.waitForFunction(()=>!!document.querySelector('.plan-card'));assert.equal(await page.locator('.target-access-error').count(),0);
  // A delayed probe on the SAME target cannot delete a newer successful plan.
  accessDenied='OU_LINK_ACCESS_DENIED';accessDelay=800;
  await page.locator('[data-gpo-toggle]').click();await page.locator('[data-gpo="11111111-1111-1111-1111-111111111111"]').click();
  await page.waitForRequest(r=>new URL(r.url()).pathname==='/api/gpo/target-access');
  await page.locator('#gpo-selection>.primary-action').click();await page.waitForFunction(()=>!!document.querySelector('.plan-card'));
  await page.waitForTimeout(900);assert.equal(await page.locator('.plan-card').count(),1,'Delayed access probe deleted the plan');
  accessDenied=null;accessDelay=0;
  // The same selection/submit chain must work for audit and organization-input controls.
  for(const id of ['17.1.1','2.3.7.4']){
   await page.goto(`http://127.0.0.1:${server.address().port}/#/benchmark`);
   await page.locator('#catalog-search').fill(id);await page.locator(`[data-rule="${id}"]`).first().click();await page.locator('[data-tab=remediation]').click();
   await page.locator('[data-gpo-toggle]').click();await page.locator('[data-gpo="11111111-1111-1111-1111-111111111111"]').click();
   await page.locator('[data-scope-open="scopeDn"]').click();await page.locator('[data-scope-choose="OU=Endpoints,DC=test,DC=local"]').click();
   if(id==='2.3.7.4')await page.locator('[name=customValue]').fill('Authorized use only');
   await page.locator('#gpo-selection>.primary-action').click();await page.waitForFunction(()=>!!document.querySelector('.plan-card'));
   assert.equal(previewSelections.at(-1).setting,id);assert.equal(previewSelections.at(-1).scopeDn,'OU=Endpoints,DC=test,DC=local');
  }
  assert.deepEqual(errors,[]);
  console.log('Recovery UI: PASS (desktop/mobile, recovery refresh, user OU/endpoint OU/verification identity targeting, and user PDC exclusion).');
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
