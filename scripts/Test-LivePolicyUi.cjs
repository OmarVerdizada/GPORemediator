/* User-reported incident: GPO threshold 5, effective AD threshold 0. No live AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),shots=path.resolve(__dirname,'../work/screens/3.17.2');fs.mkdirSync(shots,{recursive:true});
const dn='OU=Workstations,DC=example,DC=test',gpo={id:'31b2f340-016d-11d2-945f-00c04fb984f9',name:'Default Domain Policy',protected:true,selectable:true};
const selection={setting:'1.2.2',gpoId:gpo.id,scopeDn:dn,accountScope:'LocalComputers',refresh:'None',firstLink:false,value:5};
const domainPolicy={property:'LockoutThreshold',value:'0',desiredValue:'5',domainController:'dc01.example.test'};
const plan={id:'domain-incident',selection,executionUser:'EXAMPLE\\operator',domain:'example.test',domainController:domainPolicy.domainController,writeAuthorized:true,preview:{gpo,scope:{dn,name:'Workstations',kind:'OU'},previousValue:'5',desiredValue:'5',domainPolicy:null,existingLink:null,noChange:false,refreshComputers:[domainPolicy.domainController],warnings:[],preflight:{ready:true,checks:[]}}};
const result={state:'PUBLISHED',message:'GPO saved.',gpoPublished:true,linkVerified:false,currentValue:'5',domainPolicy:null,effectiveStatus:'GPO_LINK_MISMATCH',refreshResults:[{computer:domainPolicy.domainController,state:'COMPLETED',message:'gpupdate exited successfully.'}],endpointChecks:[],verification:{checkedAt:'2026-10-28T04:47:15Z',replicationConverged:true},verificationStages:[{stage:'GPO_CONFIGURATION',status:'GPO_APPLIED',evidence:'Stored GPO value is 5.'},{stage:'ENDPOINT_CONFIGURATION',status:'ENDPOINT_MISMATCH',evidence:'Domain LockoutThreshold is 0.'}]};
const history=[{id:plan.id,plan,result,updatedAt:'2026-10-28T04:47:15Z'}],requests=[];
const mappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
let requireSignIn=false,jobs=[],pollFailed=false;
const inventory={domain:'example.test',domainController:domainPolicy.domainController,executionUser:plan.executionUser,gpos:[gpo],scopes:[plan.preview.scope,{dn:'OU=Other,DC=example,DC=test',name:'Other',kind:'OU'}]};
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
  else if(url.pathname==='/api/workflows/verify'){jobs=[{id:'live-job',state:'QUEUED',action:'verify',planIds:[plan.id],message:'Accepted'}];data=jobs[0];}
  else if(url.pathname==='/api/workflows'){if(pollFailed){res.statusCode=503;res.end(JSON.stringify({code:'FIXTURE_OFFLINE',message:'Fixture connection interrupted'}));return;}data=jobs;}
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
  else if(url.pathname==='/api/gpo/target-access')data={authorized:true};
  else if(url.pathname==='/api/gpo/'+plan.id+'/replan')data={...plan,id:'repair-plan'};
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
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(18000);
 await page.addInitScript(()=>sessionStorage.setItem('gr-sidebar-collapsed','true'));
 await page.goto('http://127.0.0.1:'+server.address().port+'/#/benchmark');await page.locator('#catalog-search').fill('1.2.2');await page.locator('[data-rule="1.2.2"]').first().click();await page.locator('[data-tab=verification]').click();
 await page.locator('.result-summary').waitFor();
 assert.match(await page.locator('.verification-explanation').textContent(),/link is missing/);
 assert.match(await page.locator('.measured-values').textContent(),/Before · stored GPO/);
 const rail=await page.locator('.sidebar').boundingBox(),logo=await page.locator('.brand-emblem').boundingBox(),toggle=await page.locator('.ds-sidebar-toggle').boundingBox();
 assert(logo.x>=rail.x&&toggle.x+toggle.width<=rail.x+rail.width&&toggle.y>=logo.y+logo.height,'Collapsed logo and toggle overlap or overflow');
 await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(shots,'collapsed-sidebar.png'),fullPage:true});
 await page.locator('[data-replan]').click();await page.locator('[data-link-state=REQUIRED]').waitFor();
 assert.equal(await page.locator('.diff-before strong').textContent(),'5');assert.match(await page.locator('.stored-gpo-fact').textContent(),/Stored GPO value\s*5/);assert.match(await page.locator('.diff-before .value-source').textContent(),/Default Domain Policy/);assert.match(await page.locator('.diff-before .value-source').textContent(),new RegExp(gpo.id));assert.match(await page.locator('.target-value-boundary').textContent(),/inherited policy/);
 await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(shots,'unlinked-ou-plan.png'),fullPage:true});
 for(const [link,firstLink,expected] of [[{enabled:false,order:1},false,'DISABLED'],[{enabled:true,order:2},true,'PRIORITY'],[{enabled:true,order:1},true,'PRESENT']]){
  plan.preview.existingLink=link;plan.selection.firstLink=firstLink;
  await page.locator('[data-tab=verification]').click();await page.locator('[data-replan]').click();await page.locator('[data-link-state='+expected+']').waitFor();
  assert.equal(await page.locator('.diff-before strong').textContent(),'5','Preview must identify the stored GPO value independently of the target link');
 }
 await page.locator('[data-tab=verification]').click();await page.locator('[data-verify]').click();await page.locator('[data-live-verification]').waitFor();
 assert.match(await page.locator('.live-verification').textContent(),/Waiting for the server worker/);assert.equal(await page.locator('.result-summary').count(),0,'Old result remained visible as the current check');
 await page.locator('[data-tab=remediation]').click();await page.locator('[data-scope-open=scopeDn]').click();await page.locator('[data-scope-choose="OU=Other,DC=example,DC=test"]').click();await page.locator('[data-tab=verification]').click();
 assert.equal(await page.locator('[data-live-verification]').count(),0,'A queued check for another OU leaked into the selected target');assert.equal(await page.locator('.verification-empty').count(),1);
 await page.locator('[data-tab=remediation]').click();await page.locator('[data-scope-open=scopeDn]').click();await page.locator('[data-scope-choose="'+dn+'"]').click();await page.locator('[data-tab=verification]').click();await page.locator('[data-live-verification]').waitFor();
 jobs[0].state='RUNNING';result.state='VERIFYING';history[0].updatedAt=new Date().toISOString();history[0].stages=[{phase:'REPLICATION_ENDPOINT_CHECK',startedAt:new Date().toISOString()}];history[0].liveChecks=[{phase:'GPO',state:'VERIFIED',subject:gpo.id,message:'Stored setting matches.'},{phase:'LINK',state:'VERIFIED',subject:dn,message:'Direct link enabled.'},{phase:'ENDPOINT',state:'CHECKING',subject:'ws.example.test',message:'Reading effective policy.'}];
 await page.locator('[data-check-state=CHECKING]').filter({hasText:'ws.example.test'}).waitFor();
 assert.equal(await page.locator('[data-check-state=VERIFIED]').count(),2);
 await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(shots,'live-checking.png'),fullPage:true});
 pollFailed=true;try{await page.getByText(/Live updates unavailable/).waitFor();}catch(error){fs.writeFileSync(path.join(shots,'polling-failure.html'),await page.content());fs.writeFileSync(path.join(shots,'polling-requests.json'),JSON.stringify(requests));await page.screenshot({path:path.join(shots,'polling-failure.png'),fullPage:true});throw error;}assert.equal(await page.locator('.result-summary.success').count(),0);
 pollFailed=false;history[0].liveChecks[2]={phase:'ENDPOINT',state:'UNAVAILABLE',subject:'ws.example.test',message:'WinRM connection unavailable.'};
 await page.locator('[data-check-state=UNAVAILABLE]').waitFor();
 jobs[0].state='CHECKS_INCOMPLETE';jobs[0].message='Endpoint check unavailable; review WinRM connectivity.';result.state='PUBLISHED';result.linkVerified=true;result.effectiveStatus='ENDPOINT_VERIFICATION_PENDING';result.endpointChecks=[{hostname:'ws.example.test',state:'UNAVAILABLE',actualValue:null,message:'WinRM connection unavailable.'}];
 await page.locator('[data-effective-outcome=PENDING]').waitFor();assert.equal(await page.locator('.effective-value strong').textContent(),'Not checked');assert.match(await page.locator('.verification-explanation').textContent(),/WinRM connection unavailable/);
 assert.equal(requests.filter(x=>x.path==='/api/workflows/verify').length,1,'Polling resubmitted an operation');
 assert.equal(requests.filter(x=>/\/(apply|refresh|rollback)$/.test(x.path)).length,0,'Read-only verification caused a mutation');
 result.effectiveStatus='ENDPOINT_MISMATCH';result.endpointChecks=[{hostname:'ws1.example.test',state:'VERIFIED',actualValue:'5',message:'Measured 5.'},{hostname:'ws2.example.test',state:'MISMATCH',actualValue:'0',message:'Measured 0.'}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('[data-effective-outcome=MISMATCH]').waitFor();assert.equal(await page.locator('.effective-value strong').textContent(),'Mixed values · see hosts','Different endpoint values must not be summarized as the first value');
 for(const width of [390,320]){await page.setViewportSize({width,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Mobile overflow '+width);await page.screenshot({path:path.join(shots,'result-'+width+'.png'),fullPage:true});}
 assert.deepEqual(errors,[]);console.log('PASS live checking: queued, streamed stage/host updates, interrupted polling, unavailable result, missing-link plan, collapsed rail, mobile and exactly one read-only submission; fixture only.');
}finally{await browser?.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
