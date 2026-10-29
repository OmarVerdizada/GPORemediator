/* User-reported incident: GPO threshold 5, effective AD threshold 0. No live AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),shots=path.resolve(__dirname,'../work/screens/3.17.0');fs.mkdirSync(shots,{recursive:true});
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
 const verified={...history[0],id:'verified-check',result:{state:'PUBLISHED',gpoPublished:true,linkVerified:true,effectiveStatus:'VERIFIED_ON_SAMPLE',verification:{replicationConverged:true},endpointChecks:[{hostname:'ws.example.test',state:'VERIFIED',actualValue:'5',message:'Value measured.'}]}};
 const active={...history[0],id:'active-check',result:{state:'VERIFYING',effectiveStatus:'PENDING'},stages:[{phase:'CONNECTING',startedAt:new Date().toISOString()}]};
 history[0].result.message='Selected target link requires review.';active.updatedAt=new Date().toISOString();history.push(verified,active);jobs.push({id:'active-job',state:'RUNNING',action:'verify',planIds:[active.id],message:'Checking endpoints'});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(18000);
 await page.addInitScript(()=>{for(const [key,value] of [['gr-catalog-layout','recipes'],['gr-favorites','["1.2.2"]'],['gr-accent','violet'],['gr-density','compact']])sessionStorage.setItem(key,value)});
 const base='http://127.0.0.1:'+server.address().port;
 await page.goto(base+'/#/dashboard');await page.locator('.dashboard-page').waitFor();await page.locator('.dashboard-active-row').waitFor();
 assert.equal(await page.locator('.dashboard-heading h1').textContent(),'Dashboard');assert.equal(await page.locator('.dashboard-summary strong').allTextContents().then(v=>v.join(',')),'1,1,1');
 assert.equal(await page.locator('nav [href="#/workspace"],nav [href="#/password-policies"],.command-trigger').count(),0);
 assert.equal(await page.locator('.studio-overview,.studio-pulse,.ux-kpi-grid,.pr-heatmap').count(),0,'Decorative dashboard renderers remain');
 const appearance=page.locator('.ds-preferences');await appearance.locator('summary').click();assert.equal(await appearance.locator('select').count(),1);assert.equal(await page.locator('#preference-accent,#preference-density').count(),0);await appearance.locator('summary').click();
 for(const theme of ['light','dark']){await appearance.locator('summary').click();await page.locator('#preference-theme').selectOption(theme);await page.keyboard.press('Escape');await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(shots,'dashboard-'+theme+'.png'),fullPage:true});}
 await appearance.locator('summary').click();await page.locator('#preference-theme').selectOption('light');await page.keyboard.press('Escape');
 await page.locator('.dashboard-result-row').first().click();await page.locator('.product-drawer').waitFor();await page.locator('button[data-product-close]').click();
 for(const width of [390,320]){await page.setViewportSize({width,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Dashboard overflow '+width);const rail=await page.locator('.sidebar').boundingBox(),nav=await page.locator('.sidebar nav').boundingBox();assert(nav.y>=rail.y&&nav.y+nav.height<=rail.y+rail.height+1,'Mobile navigation is hidden below the brand');assert.equal(await page.locator('.sidebar .brand-lockup').isVisible(),false);await page.screenshot({path:path.join(shots,'dashboard-'+width+'.png'),fullPage:true});}
 await page.setViewportSize({width:1440,height:1000});await page.goto(base+'/#/benchmark');await page.locator('#catalog-search').fill('1.2.2');await page.locator('[data-rule="1.2.2"]').first().waitFor();
 assert.equal(await page.locator('[data-catalog-layout],[data-favorite],[data-view="FAVORITES"],.recipe-card').count(),0,'Retired catalog interfaces remain');
 await page.locator('[data-rule="1.2.2"]').first().click();assert.equal(await page.locator('.favorite-action').count(),0);
 await page.locator('.ux-more-tabs summary').click();await page.locator('[data-tab=impact]').click();await page.locator('.impact-context-table').waitFor();assert.equal(await page.locator('[data-impact-node],.policy-graph').count(),0);
 await page.goto(base+'/#/workspace');await page.waitForURL('**/#/operations');await page.locator('#ops-search').waitFor();
 await page.goto(base+'/#/password-policies');await page.waitForURL('**/#/dashboard');await page.locator('.dashboard-page').waitFor();
 jobs[0].state='COMPLETED';active.result=verified.result;history[2]=active;
 await page.waitForFunction(()=>document.querySelector('.dashboard-summary strong')?.textContent==='0');assert.equal(await page.locator('.dashboard-summary strong').allTextContents().then(v=>v.join(',')),'0,1,2');
 assert.equal(requests.filter(r=>r.path==='/api/password-policies'||r.path==='/api/batches').length,0,'Retired sections still fetch data');assert.equal(requests.filter(r=>/\/(apply|refresh|rollback)$/.test(r.path)).length,0);assert.deepEqual(errors,[]);
 console.log('PASS streamlined workspace: removed feature entry points, stale preferences ignored, both themes/mobile, truthful live dashboard, target context table, job completion, legacy route redirects and no writes.');
}finally{await browser?.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
