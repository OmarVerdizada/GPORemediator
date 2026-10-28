/* User-reported incident: GPO threshold 5, effective AD threshold 0. No live AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),shots=path.resolve(__dirname,'../work/screens/3.16.8');fs.mkdirSync(shots,{recursive:true});
const dn='DC=example,DC=test',gpo={id:'31b2f340-016d-11d2-945f-00c04fb984f9',name:'Default Domain Policy',protected:true,selectable:true};
const selection={setting:'1.2.2',gpoId:gpo.id,scopeDn:dn,accountScope:'Domain',refresh:'Pdc',firstLink:true,value:5};
const domainPolicy={property:'LockoutThreshold',value:'0',desiredValue:'5',domainController:'dc01.example.test'};
const plan={id:'domain-incident',selection,executionUser:'EXAMPLE\\operator',domain:'example.test',domainController:domainPolicy.domainController,writeAuthorized:true,preview:{gpo,scope:{dn,name:'example.test',kind:'Domain'},previousValue:'5',desiredValue:'5',domainPolicy,noChange:false,refreshComputers:[domainPolicy.domainController],warnings:[],preflight:{ready:true,checks:[]}}};
const result={state:'PUBLISHED',message:'GPO saved.',gpoPublished:true,linkVerified:true,currentValue:'5',domainPolicy,effectiveStatus:'ENDPOINT_MISMATCH',refreshResults:[{computer:domainPolicy.domainController,state:'COMPLETED',message:'gpupdate exited successfully.'}],endpointChecks:[{hostname:domainPolicy.domainController,state:'MISMATCH',actualValue:'0',message:'AD LockoutThreshold = 0; requested 5.'}],verification:{checkedAt:'2026-10-28T04:47:15Z',replicationConverged:true},verificationStages:[{stage:'GPO_CONFIGURATION',status:'GPO_APPLIED',evidence:'Stored GPO value is 5.'},{stage:'ENDPOINT_CONFIGURATION',status:'ENDPOINT_MISMATCH',evidence:'Domain LockoutThreshold is 0.'}]};
const history=[{id:plan.id,plan,result,updatedAt:'2026-10-28T04:47:15Z'}],requests=[];
const mappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
let requireSignIn=false;
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
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(15000);
 const base='http://127.0.0.1:'+server.address().port;
 await page.goto(base+'/#/benchmark');await page.locator('#catalog-search').fill('1.2.2');await page.locator('[data-rule="1.2.2"]').first().click();await page.locator('[data-tab=verification]').click();
 await page.locator('[data-effective-outcome=MISMATCH]').waitFor();
 assert.match(await page.locator('.result-summary-head h2').textContent(),/not effective/);
 assert.equal(await page.locator('.effective-value strong').textContent(),'0');
 assert.match(await page.locator('.measured-values').textContent(),/Requested\s*5/);
 assert.match(await page.locator('.configured-value').textContent(),/Stored GPO value: 5/);
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
 result.verificationStages[1].status='INSUFFICIENT_EVIDENCE';result.domainPolicy=null;result.effectiveStatus='DOMAIN_POLICY_UNAVAILABLE';result.endpointChecks=[{hostname:domainPolicy.domainController,state:'UNAVAILABLE',actualValue:null,message:'Domain policy could not be read.'}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('[data-effective-outcome=PENDING]').waitFor();assert.equal(await page.locator('.effective-value strong').textContent(),'Not checked');assert.match(await page.locator('.result-summary-head h2').textContent(),/not verified/);
 result.verificationStages[1].status='ENDPOINT_MISMATCH';result.domainPolicy=domainPolicy;result.effectiveStatus='ENDPOINT_MISMATCH';result.endpointChecks=[{hostname:domainPolicy.domainController,state:'MISMATCH',actualValue:'0',message:'AD LockoutThreshold = 0; requested 5.'}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('[data-effective-outcome=MISMATCH]').waitFor();await page.locator('[data-replan]').click();await page.locator('.domain-value-plan').waitFor();
 assert.equal(await page.locator('.diff-before strong').textContent(),'0');assert.equal(await page.locator('.diff-after strong').textContent(),'5');assert.match(await page.locator('.domain-value-plan').textContent(),/AD \+ GPO/);assert.equal(requests.filter(x=>x.path.endsWith('/replan')).length,1);
 await page.evaluate(()=>window.scrollTo(0,0));await page.waitForTimeout(200);
 await page.screenshot({path:path.join(shots,'domain-repair-plan.png'),fullPage:true});assert.deepEqual(errors,[]);
 requireSignIn=true;const login=await browser.newPage({viewport:{width:1440,height:1000}});await login.goto(base+'/#/dashboard');await login.locator('.operator-sign-in').waitFor();
 assert.equal(await login.locator('.operator-sign-in-emblem svg').count(),1,'Sign-in uses a different brand mark');
 assert.equal(await login.locator('.operator-sign-in button').evaluate(e=>getComputedStyle(e).backgroundImage),'none');
 await login.screenshot({path:path.join(shots,'sign-in-desktop.png'),fullPage:true});
 await login.setViewportSize({width:390,height:844});assert(await login.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await login.screenshot({path:path.join(shots,'sign-in-mobile.png'),fullPage:true});
 console.log('PASS domain account UI: actual AD 0 versus requested/GPO 5, visible mismatch, repair plan, single workflow bar, aligned sidebar, consistent sign-in and desktop/mobile fit; no live AD.');
}finally{await browser?.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
