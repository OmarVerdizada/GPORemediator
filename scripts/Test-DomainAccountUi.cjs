/* User-reported incident: GPO threshold 5, effective AD threshold 0. No live AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),shots=path.resolve(__dirname,'../work/screens/3.17.7');fs.mkdirSync(shots,{recursive:true});
const dn='DC=example,DC=test',gpo={id:'31b2f340-016d-11d2-945f-00c04fb984f9',name:'Default Domain Policy',protected:true,selectable:true};
const selection={setting:'1.2.2',gpoId:gpo.id,scopeDn:dn,accountScope:'Domain',refresh:'Pdc',firstLink:true,value:5};
const domainPolicy={property:'LockoutThreshold',value:'0',desiredValue:'5',domainController:'dc01.example.test'};
const plan={id:'domain-incident',selection,executionUser:'EXAMPLE\\operator',domain:'example.test',domainController:domainPolicy.domainController,writeAuthorized:true,preview:{gpo,scope:{dn,name:'example.test',kind:'Domain'},previousValue:'5',desiredValue:'5',domainPolicy,noChange:false,refreshComputers:[domainPolicy.domainController],warnings:[],preflight:{ready:true,checks:[]}}};
const result={state:'PUBLISHED',message:'GPO saved.',gpoPublished:true,linkVerified:true,currentValue:'5',domainPolicy,effectiveStatus:'ENDPOINT_MISMATCH',refreshResults:[{computer:domainPolicy.domainController,state:'COMPLETED',message:'gpupdate exited successfully.'}],endpointChecks:[{hostname:domainPolicy.domainController,state:'MISMATCH',actualValue:'0',message:'AD LockoutThreshold = 0; requested 5.'}],verification:{checkedAt:'2026-10-28T04:47:15Z',replicationConverged:true},verificationStages:[{stage:'GPO_CONFIGURATION',status:'GPO_APPLIED',evidence:'Stored GPO value is 5.'},{stage:'ENDPOINT_CONFIGURATION',status:'ENDPOINT_MISMATCH',evidence:'Domain LockoutThreshold is 0.'}]};
const history=[{id:plan.id,plan,result,updatedAt:'2026-10-28T04:47:15Z'}],requests=[];
const mappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
let requireSignIn=false,dependencyMode=false,windowValue=30,publicationRun=null,jobs=[];
const durationSelection={...selection,setting:'1.2.1',value:15,itemValues:[['15']]};
const dependency={code:'DOMAIN_LOCKOUT_DEPENDENCY',message:'Requested duration 15 minutes is below reset-counter window 30 minutes. Review 1.2.4 first.',setting:'1.2.4',value:15,property:'LockoutObservationWindow',currentValue:'30'};
function lockoutPlan(s){return {...plan,id:'preview-'+s.setting,selection:s,preview:{...plan.preview,previousValue:'15',desiredValue:'15',dependency:s.setting==='1.2.1'&&windowValue>15?dependency:null,domainPolicy:{...domainPolicy,property:s.setting==='1.2.4'?'LockoutObservationWindow':'LockoutDuration',value:s.setting==='1.2.4'?String(windowValue):'30',desiredValue:'15'}}};}
const inventory={domain:'example.test',domainController:domainPolicy.domainController,executionUser:plan.executionUser,gpos:[gpo],scopes:[plan.preview.scope]};
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');let body='';for await(const chunk of req)body+=chunk;
 if(url.pathname.startsWith('/api/')){
  requests.push({path:url.pathname,method:req.method,body:body?JSON.parse(body):null});let data={};
  if(url.pathname==='/api/session')data={mode:'WINDOWS',csrfToken:'fixture',operator:plan.executionUser,operatorConfirmationRequired:requireSignIn,domainSignIn:true};
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
  else if(url.pathname==='/api/gpo/session')data={connected:true};
  else if(url.pathname==='/api/gpo/settings')data=mappings;
  else if(url.pathname==='/api/gpo/inventory')data=inventory;
  else if(url.pathname==='/api/gpo/history')data=history;
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
  else if(url.pathname==='/api/workflows')data=jobs;
  else if(url.pathname==='/api/workflows/verify'&&publicationRun){publicationRun.result={...publicationRun.result,state:'PUBLISHED',gpoPublished:true,linkVerified:true,message:'Read-only verification confirmed the complete post-write state; original publication failure retained.'};data={id:'recovery-check',state:'COMPLETED',planIds:[publicationRun.id],completedIds:[publicationRun.id]};jobs=[data];res.statusCode=202;}
  else if(url.pathname==='/api/gpo/publication-recovery/rollback-preview')data={canRestore:true,manifestPhase:'PUBLISHED',reason:'READY',backupId:'retained-backup',message:'Verified retained snapshot and complete current state.',beforeDomainPolicy:{property:'LockoutObservationWindow',value:'30'},afterDomainPolicy:{value:'15'}};
  else if(url.pathname==='/api/workflows/rollback'&&publicationRun){publicationRun.result={...publicationRun.result,state:'ROLLED_BACK',gpoPublished:false,linkVerified:false,domainPolicy:{...publicationRun.result.domainPolicy,value:'30',desiredValue:'30'},currentValue:'30',effectiveStatus:'ROLLBACK_ENDPOINT_PENDING',message:'Saved GPO and AD snapshot restored.'};data={id:'restore-check',state:'COMPLETED',planIds:[publicationRun.id],completedIds:[publicationRun.id]};jobs=[data];res.statusCode=202;}
  else if(url.pathname==='/api/gpo/target-access')data={authorized:true};
  else if(url.pathname==='/api/gpo/'+plan.id+'/replan')data=dependencyMode?lockoutPlan(durationSelection):{...plan,id:'repair-plan'};
  else if(url.pathname==='/api/gpo/preview')data=lockoutPlan(JSON.parse(body));
  else if(url.pathname==='/api/setup/config')data={exists:true,...inventory,approvedGpoIds:[gpo.id],authorizedOus:[dn],allowedHosts:[],endpointTargeting:'SelectedOu'};
  else if(['/api/workflows','/api/batches','/api/password-policies','/api/audit'].includes(url.pathname))data=[];
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
}catch(error){res.statusCode=500;res.end(error.message);}});
(async()=>{let browser;try{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(15000);
 const base='http://127.0.0.1:'+server.address().port;
 await page.goto(base+'/#/benchmark');await page.locator('#catalog-search').fill('1.2.2');await page.locator('[data-rule="1.2.2"]').first().click();await page.locator('[data-tab=verification]').click();
 await page.locator('[data-effective-outcome=MISMATCH]').waitFor();
 assert.match(await page.locator('.result-summary-head h2').textContent(),/not effective/);
 assert.equal(await page.locator('.effective-value strong').textContent(),'0');
 assert.match(await page.locator('.measured-values').textContent(),/Requested\s*5/);
 assert.equal(await page.locator('.configured-value>strong').textContent(),'5');
 assert.match(await page.locator('.configured-value>.value-source').textContent(),/Default Domain Policy/);
 assert.equal(await page.locator('.stepper').count(),1,'Duplicate workflow/context bars remain');
 assert.equal(await page.locator('.brand-lockup .ds-sidebar-toggle').count(),1,'Sidebar toggle must sit inside the brand header');
 assert(!/Published/.test(await page.locator('.result-summary-head').textContent()),'Publication hid the actual domain mismatch');
 assert.equal(requests.filter(x=>x.method!=='GET'&&x.path!=='/api/gpo/target-access').length,0,'Reading the result wrote a policy');
 await page.evaluate(()=>window.scrollTo(0,0));await page.waitForTimeout(200);
 assert((await page.locator('#service-bar').boundingBox()).y<2,'Header must stay at the viewport top');
 await page.screenshot({path:path.join(shots,'domain-mismatch-desktop.png'),fullPage:true});
 for(const width of [390,320]){await page.setViewportSize({width,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Mismatch layout overflows '+width);await page.screenshot({path:path.join(shots,'domain-mismatch-'+width+'.png'),fullPage:true});}
 await page.setViewportSize({width:1440,height:1000});
 result.verificationStages[1].status='ENDPOINT_VERIFIED';result.domainPolicy={...domainPolicy,value:'5'};result.effectiveStatus='DOMAIN_VALUE_MATCHES_ON_SELECTED_DC';result.endpointChecks=[{hostname:domainPolicy.domainController,state:'VERIFIED',actualValue:'5',message:'AD LockoutThreshold = 5.'}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('[data-effective-outcome=VERIFIED]').waitFor();assert.equal(await page.locator('.effective-value strong').textContent(),'5');
 // A persisted 3.17.3 record falsely said VERIFIED for AD 30/requested 15.
 result.currentLink={target:dn,order:1,enforced:false,enabled:true};result.domainPolicy={property:'LockoutDuration',value:'30',desiredValue:'15',domainController:domainPolicy.domainController,notes:['Account lockout is disabled because LockoutThreshold is 0.']};result.endpointChecks=[{hostname:domainPolicy.domainController,state:'VERIFIED',actualValue:'30',message:'Legacy threshold check.'}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('[data-effective-outcome=MISMATCH]').waitFor();assert.equal(await page.locator('.effective-value strong').textContent(),'30');assert.match(await page.locator('.verification-explanation').textContent(),/exact requested value/);assert.match(await page.locator('.domain-policy-notes').textContent(),/Threshold is 0/);assert.match(await page.locator('.recorded-result-context').textContent(),/Enabled · priority 1/);
 await page.screenshot({path:path.join(shots,'legacy-duration-mismatch.png'),fullPage:true});
 result.verificationStages[1].status='INSUFFICIENT_EVIDENCE';result.domainPolicy=null;result.effectiveStatus='DOMAIN_POLICY_UNAVAILABLE';result.endpointChecks=[{hostname:domainPolicy.domainController,state:'UNAVAILABLE',actualValue:null,message:'Domain policy could not be read.'}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('[data-effective-outcome=PENDING]').waitFor();assert.equal(await page.locator('.effective-value strong').textContent(),'AD value unavailable');assert.match(await page.locator('.result-summary-head h2').textContent(),/not verified/);
 result.verificationStages[1].status='ENDPOINT_MISMATCH';result.domainPolicy=domainPolicy;result.effectiveStatus='ENDPOINT_MISMATCH';result.endpointChecks=[{hostname:domainPolicy.domainController,state:'MISMATCH',actualValue:'0',message:'AD LockoutThreshold = 0; requested 5.'}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('[data-effective-outcome=MISMATCH]').waitFor();await page.locator('[data-replan]').click();await page.locator('.domain-value-plan').waitFor();
 assert.equal(await page.locator('.diff-before strong').textContent(),'0');assert.equal(await page.locator('.diff-after strong').textContent(),'5');assert.match(await page.locator('.domain-value-plan').textContent(),/AD \+ GPO/);assert.equal(requests.filter(x=>x.path.endsWith('/replan')).length,1);
 await page.evaluate(()=>window.scrollTo(0,0));await page.waitForTimeout(200);
 await page.screenshot({path:path.join(shots,'domain-repair-plan.png'),fullPage:true});assert.deepEqual(errors,[]);
 // A failed duration repair now yields an actionable preview instead of a toast dead end.
 dependencyMode=true;await page.locator('[data-tab=verification]').click();await page.locator('[data-replan]').click();await page.locator('[data-dependency-blocked]').waitFor();assert.equal(await page.locator('#gpo-apply').count(),0);assert.match(await page.locator('.policy-dependency').textContent(),/1.2.4/);
 await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(shots,'lockout-prerequisite-desktop.png'),fullPage:true});
 const beforeGuide=requests.length;await page.locator('[data-dependency-plan]').click();await page.locator('.domain-value-plan').waitFor();let related=requests.filter(x=>x.path==='/api/gpo/preview').at(-1).body;assert.equal(related.setting,'1.2.4');assert.equal(related.itemValues[0][0],'15');assert.equal(related.gpoId,gpo.id);assert.equal(related.scopeDn,dn);assert.equal(await page.locator('#approval-ok').isChecked(),false);
 assert.equal(requests.slice(beforeGuide).filter(x=>/\/(apply|rollback|refresh)$/.test(x.path)).length,0,'Preparing prerequisite must not write or refresh');
 await page.locator('[data-dependency-return]').click();await page.locator('[data-dependency-blocked]').waitFor();assert.equal(await page.locator('#gpo-apply').count(),0,'Returning before prerequisite completion must remain blocked');
 await page.setViewportSize({width:390,height:844});await page.locator('[data-dependency-blocked]').scrollIntoViewIfNeeded();await page.waitForTimeout(400);await page.locator('[data-dependency-blocked]').screenshot({path:path.join(shots,'lockout-prerequisite-mobile.png')});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.setViewportSize({width:1440,height:1000});
 await page.locator('[data-dependency-plan]').click();await page.locator('.domain-value-plan').waitFor();windowValue=15;await page.locator('[data-dependency-return]').click();await page.locator('.domain-value-plan').waitFor();const original=requests.filter(x=>x.path==='/api/gpo/preview').at(-1).body;assert.equal(original.setting,'1.2.1');assert.equal(original.itemValues[0][0],'15');assert.equal(await page.locator('[data-dependency-blocked]').count(),0);assert.equal(await page.locator('#approval-ok').isChecked(),false);assert.deepEqual(errors,[]);
 console.log('PASS guided lockout repair: explicit 1.2.4 preview, preserved GPO/domain, no automatic writes, blocked early return, live original re-preview, mobile fit');
 const publicationPlan=lockoutPlan({...durationSelection,setting:'1.2.4'});publicationPlan.id='publication-recovery';publicationPlan.preview.domainPolicy.value='30';publicationPlan.preview.previousValue='30';
 publicationRun={id:publicationPlan.id,plan:publicationPlan,updatedAt:new Date().toISOString(),result:{...result,state:'REVIEW_REQUIRED',message:'Original publication check failed.',backupId:'retained-backup',gpoPublished:false,linkVerified:false,currentValue:'15',domainPolicy:{property:'LockoutObservationWindow',value:'15',desiredValue:'15',domainController:domainPolicy.domainController},effectiveStatus:'DOMAIN_VALUE_MATCHES_ON_SELECTED_DC',endpointChecks:[{hostname:domainPolicy.domainController,state:'VERIFIED',actualValue:'15'}],verificationStages:[]}};history.unshift(publicationRun);
 await page.goto(base+'/#/benchmark');await page.locator('.service-right [data-refresh]').click();await page.locator('.busy-layer').waitFor({state:'detached'});await page.locator('#catalog-search').fill('1.2.4');await page.locator('[data-rule="1.2.4"]').first().click();await page.locator('[data-tab=verification]').click();await page.locator('.effective-value').waitFor();assert.equal(await page.locator('[data-gpupdate]').isDisabled(),true);
 await page.locator('[data-verify]').click();await page.locator('[data-effective-outcome=VERIFIED]').waitFor();assert.equal(await page.locator('[data-gpupdate]').isDisabled(),false);
 await page.goto(base+'/#/operations');await page.locator('[data-inspect="publication-recovery"]').first().click();await page.locator('[data-rollback-inspect="publication-recovery"]').click();await page.locator('.busy-layer').waitFor({state:'detached'});await page.locator('[data-rollback="publication-recovery"] input[name=confirmation]').fill('ROLLBACK');await page.locator('[data-rollback="publication-recovery"] button[type=submit]').click();await page.locator('[data-confirm-run]').click();await page.locator('.busy-layer').waitFor({state:'detached'});
 await page.goto(base+'/#/benchmark');await page.locator('#catalog-search').fill('1.2.4');await page.locator('[data-rule="1.2.4"]').first().click();await page.locator('[data-tab=verification]').click();await page.locator('.effective-value').waitFor();assert.equal(await page.locator('.effective-value strong').textContent(),'30');assert.match(await page.locator('.measured-values').textContent(),/Restore target\s*30/);assert.equal(await page.locator('[data-gpupdate]').isDisabled(),false);await page.screenshot({path:path.join(shots,'rollback-actual-ad.png'),fullPage:true});assert.deepEqual(errors,[]);
 console.log('PASS publication recovery UI: certified Verify unlocks refresh; rollback displays actual AD 30 and restore target 30');
 publicationRun.result.domainPolicy=null;await page.locator('.service-right [data-refresh]').click();await page.locator('.busy-layer').waitFor({state:'detached'});assert.match(await page.locator('.measured-values').textContent(),/Restore target\s*30/,'GPO-only rollback must show the saved setting rather than the forward request');
 publicationRun.result={...publicationRun.result,state:'FAILED_SAFE',message:'Restore preflight denied.'};await page.locator('.service-right [data-refresh]').click();await page.locator('.busy-layer').waitFor({state:'detached'});assert.equal(await page.locator('.result-actions [data-replan]').count(),0);assert.equal(await page.getByRole('button',{name:'Review rollback',exact:true}).count(),1);
 console.log('PASS GPO-only rollback UI: saved restore value and retained rollback context after a safe preflight failure');
 publicationRun.result={...publicationRun.result,state:'ROLLBACK_REVIEW_REQUIRED',domainPolicy:{...publicationRun.result.domainPolicy,value:'15',desiredValue:'30'},effectiveStatus:'ROLLBACK_ENDPOINT_PENDING',message:'Rollback stopped before restore. Resolve access failure and inspect recovery.'};
 await page.locator('.service-right [data-refresh]').click();await page.locator('.busy-layer').waitFor({state:'detached'});assert.equal(await page.locator('.effective-value strong').textContent(),'15');assert.match(await page.locator('.measured-values').textContent(),/Restore target\s*30/);assert.equal(await page.locator('.result-actions [data-replan]').count(),0,'Failed rollback must not offer to reapply the original forward value');await page.getByRole('button',{name:'Review rollback',exact:true}).click();await page.locator('[data-rollback-inspect="publication-recovery"]').waitFor();assert.deepEqual(errors,[]);
 console.log('PASS failed rollback UI: actual AD 15 versus restore target 30, explicit recovery review and no forward-value repair');
 requireSignIn=true;const login=await browser.newPage({viewport:{width:1440,height:1000}});await login.goto(base+'/#/dashboard');await login.locator('.operator-sign-in').waitFor();
 assert.equal(await login.locator('.operator-sign-in-emblem svg').count(),1,'Sign-in uses a different brand mark');
 assert.equal(await login.locator('.operator-sign-in button').evaluate(e=>getComputedStyle(e).backgroundImage),'none');
 await login.screenshot({path:path.join(shots,'sign-in-desktop.png'),fullPage:true});
 await login.setViewportSize({width:390,height:844});assert(await login.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await login.screenshot({path:path.join(shots,'sign-in-mobile.png'),fullPage:true});
 console.log('PASS domain account UI: actual AD 0 versus requested/GPO 5, visible mismatch, repair plan, single workflow bar, aligned sidebar, consistent sign-in and desktop/mobile fit; no live AD.');
}finally{await browser?.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
