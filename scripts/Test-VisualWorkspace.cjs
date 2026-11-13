/* Browser-only product review. All API responses are local fixtures. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),phase=process.env.VISUAL_PHASE||'after',shots=path.resolve(__dirname,'../work/screens/workspace-design',phase);
fs.mkdirSync(shots,{recursive:true});
const mappings=JSON.parse(fs.readFileSync(path.resolve(root,'../../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const gpo={id:'11111111-1111-1111-1111-111111111111',name:'Workstation security baseline',selectable:true},dn='OU=Workstations,DC=example,DC=local';
const scope={dn,name:'Workstations',kind:'OU'},inventory={domain:'example.local',domainController:'dc01.example.local',executionUser:'EXAMPLE\\operator',gpos:[gpo],scopes:[scope,{dn:'DC=example,DC=local',name:'example.local',kind:'Domain'}]};
function record(id,setting,state,checks){return {id,startedAt:'2026-11-12T06:00:00Z',updatedAt:'2026-11-12T06:04:00Z',approval:{changeReference:'CHG-1042'},plan:{id,domain:inventory.domain,executionUser:inventory.executionUser,selection:{setting,gpoId:gpo.id,scopeDn:dn,accountScope:'LocalComputers',refresh:'None'},preview:{gpo,scope,previousValue:'0',desiredValue:'5',warnings:[]}},result:{state:'PUBLISHED',gpoPublished:true,linkVerified:true,currentValue:'5',currentLink:{enabled:true,order:1},effectiveStatus:state,message:'GPO settings saved. Inspect the recorded endpoint evidence.',endpointChecks:checks,refreshResults:[],verification:{replicationConverged:true,checkedAt:'2026-11-12T06:04:00Z'}}};}
const checks=[{hostname:'ws01.example.local',state:'VERIFIED',actualValue:'5',message:'Requested value read from endpoint.'},{hostname:'ws02.example.local',state:'MISMATCH',actualValue:'0',message:'Actual value differs from requested 5.'},{hostname:'ws03.example.local',state:'UNAVAILABLE',actualValue:null,message:'WinRM connection unavailable.'}];
const history=[record('run-review','1.2.2','ENDPOINT_MISMATCH',checks),record('run-good','18.7.3','VERIFIED_ON_SAMPLE',[checks[0]]),record('run-pending','17.7.5','ENDPOINT_VERIFICATION_PENDING',[checks[2]])];
let jobs=[],number=0,plans=[],batch=null,signInRequired=false,signInRelease;const requests=[];
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');let raw='';for await(const c of req)raw+=c;const payload=raw?JSON.parse(raw):{};
 if(url.pathname.startsWith('/api/')){requests.push({path:url.pathname,method:req.method,payload});let data={};
 const p=url.pathname;
 if(p==='/api/session')data={mode:'WINDOWS',csrfToken:'fixture',operator:inventory.executionUser,domainSignIn:true,operatorConfirmationRequired:signInRequired};
 else if(p==='/api/operator/sign-in'){await new Promise(resolve=>signInRelease=resolve);signInRequired=false;data={success:true};}
 else if(p==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
 else if(p==='/api/gpo/session')data={connected:true,sessionId:'visual-session'};
 else if(p==='/api/gpo/settings')data=mappings;
 else if(p==='/api/gpo/inventory')data=inventory;
 else if(p==='/api/gpo/history')data=history;
 else if(p==='/api/gpo/readiness')data={ready:true,checkedAt:'2026-11-12T06:00:00Z',checks:[{id:'dns',label:'Domain DNS',state:'PASS',message:'Selected controller resolves successfully.'},{id:'sysvol',label:'SYSVOL access',state:'PASS',message:'Policy share is readable.'},{id:'disk',label:'Backup volume',state:'WARN',required:false,message:'Review retention before the next large batch.'}]};
 else if(p==='/api/setup/discover')data={...inventory,warnings:[]};
 else if(p==='/api/gpo/access-report')data={ready:true,executionUser:inventory.executionUser,domainController:inventory.domainController,checkedAt:'2026-11-12T06:00:00Z',note:'Read-only permission inspection.',checks:[{label:'Selected GPO',target:gpo.name,requiredRight:'Edit settings',state:'ALLOWED',remedy:'No action required.'}]};
 else if(p==='/api/audit')data={integrityValid:true,events:[{id:2,event:'VERIFY_COMPLETED',operator:inventory.executionUser,controlId:'1.2.2',gpoId:gpo.id,createdAt:'2026-11-12T06:04:00Z',hash:'a'.repeat(64)},{id:1,event:'PLAN_APPROVED',operator:inventory.executionUser,controlId:'1.2.2',gpoId:gpo.id,createdAt:'2026-11-12T06:00:00Z',hash:'b'.repeat(64)}]};
 else if(p==='/api/gpo/target-access')data={authorized:true};
 else if(p==='/api/setup/config')data={exists:true,...inventory,approvedGpoIds:['*'],authorizedOus:['*'],endpointTargeting:'SelectedOu'};
 else if(p==='/api/workflows'&&req.method==='GET')data=jobs;
 else if(p==='/api/batches')data=batch?[batch]:[];
 else if(p.startsWith('/api/batches/'))data={batch,plans};
 else if(p==='/api/workflows/preview'){
  plans=payload.batch.selections.map((s,i)=>({id:'bulk-'+i,selection:s,writeAuthorized:true,executionUser:inventory.executionUser,preview:{gpo,scope,previousValue:null,desiredValue:'5',warnings:[],verificationComputers:['ws01.example.local']}}));
  batch={id:'visual-batch',planIds:plans.map(p=>p.id)};data={id:'preview-job',action:'preview',state:'COMPLETED',batchId:batch.id,planIds:batch.planIds,completedIds:batch.planIds,message:'Preview ready.'};jobs.push(data);
 }else if(p==='/api/workflows/apply'){
  data={id:'apply-job',action:'apply',state:'RUNNING',batchId:batch.id,planIds:batch.planIds,completedIds:[],currentOperationId:plans[0].id,message:'Checking GPO publication',updatedAt:'2026-11-12T06:05:00Z'};jobs.push(data);
 }else if(p==='/api/workflows/verify'){data={id:'verify-'+(++number),action:'verify',state:'QUEUED',planIds:payload.planIds,completedIds:[],message:'Accepted'};jobs.push(data);}
 else if(p.startsWith('/api/workflows/'))data=jobs.find(j=>j.id===p.split('/').pop())||{};
 else if(['/api/audit','/api/password-policies'].includes(p))data=[];
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return;}
 res.setHeader('Content-Type',({'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
}catch(e){res.writeHead(500);res.end(e.message);}});
(async()=>{let browser;try{await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(15000);const base='http://127.0.0.1:'+server.address().port;
 let chosenTheme='light';await page.addInitScript(()=>sessionStorage.setItem('gr-theme',new URL(location.href).searchParams.get('theme')||'light'));
 const goto=async route=>{await page.goto(base+'/?theme='+chosenTheme+'&review='+Date.now()+'#/'+route);await page.waitForFunction(()=>document.querySelector('#main-content')?.getAttribute('aria-busy')==='false');await page.evaluate(()=>document.fonts.ready);assert.equal(await page.locator('html').getAttribute('data-gr-theme'),chosenTheme);};
 const shot=async name=>{const modal=page.locator('.bulk-dialog,.product-drawer');const hasModal=await modal.count()>0;await page.screenshot({path:path.join(shots,name+'.png'),fullPage:!hasModal,animations:'disabled'});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),name+' page overflow');if(hasModal)assert(await modal.first().evaluate(el=>{const r=el.getBoundingClientRect();return r.left>=-1&&r.top>=-1&&r.right<=innerWidth+1&&r.bottom<=innerHeight+1&&el.scrollWidth<=el.clientWidth+1;}),name+' modal overflow '+JSON.stringify(await modal.first().evaluate(el=>({rect:el.getBoundingClientRect().toJSON(),sw:el.scrollWidth,cw:el.clientWidth,vw:innerWidth,vh:innerHeight}))));};
 for(const theme of ['light','dark'])for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});chosenTheme=theme;
  await goto('dashboard');await shot(`dashboard-${theme}-${width}`);
  assert(await page.locator('.brand-emblem img').evaluate(img=>img.complete&&img.naturalWidth>0),'Logo asset must load');
  if(phase!=='before')assert.equal(await page.locator('.experience-queue').count(),1);
  await page.locator('nav [href="#/operations"]').click();await page.locator('.ops-summary').waitFor();await shot(`operations-${theme}-${width}`);
  await page.locator('[data-inspect="run-review"]').first().click();await page.locator('.product-drawer').waitFor();await shot(`drawer-${theme}-${width}`);await page.keyboard.press('Escape');
  await goto('benchmark');await page.locator('#catalog-search').fill('1.2');await page.locator('[data-rule="1.2.2"]').first().waitFor();await shot(`benchmark-${theme}-${width}`);
  await page.locator('[data-rule="1.2.2"]').first().click();await page.locator('[data-tab=verification]').click();await page.locator('.result-summary').waitFor();await shot(`verification-${theme}-${width}`);
  if(phase!=='before'){
   assert.equal(await page.locator('.evidence-matrix tbody tr').count(),3);
   assert.match(await page.locator('.evidence-matrix').textContent(),/Value differs/);assert.match(await page.locator('.evidence-matrix').textContent(),/Unavailable/);
   assert.equal(await page.locator('.result-summary').getAttribute('data-effective-outcome'),'MISMATCH');
  }
  await goto('benchmark');await page.locator('[data-bulk-mode]').click();for(const id of ['1.2.2','17.7.5']){await page.locator('#catalog-search').fill(id);await page.locator(`[data-bulk-select="${id}"]`).check();}await page.locator('[data-bulk-open]').click();await page.selectOption('#bulk-gpoId',gpo.id);await page.selectOption('#bulk-scopeDn',dn);await shot(`bulk-${theme}-${width}`);await page.keyboard.press('Escape');
  for(const route of ['reports','diagnostics','assurance','audit']){await goto(route);if(route==='audit')await page.locator('.audit-event-row').first().waitFor();await shot(`${route}-${theme}-${width}`);assert.equal(await page.locator('.experience-heading .section-mark').count(),1);
   if(route==='diagnostics')assert.deepEqual(await page.locator('.ent-metrics>div').evaluateAll(nodes=>nodes.map(el=>el.dataset.metricTone)),['success','warning','danger','neutral']);
  }
  await page.locator('[data-settings-nav]').click();await page.locator('#gr-auto-panel.open .gr-auto-card').first().waitFor();await page.waitForFunction(()=>document.querySelector('#gr-auto-panel .gr-auto-body')?.getAttribute('aria-busy')==='false');
  assert.equal(await page.locator('#root').evaluate(el=>el.inert),true);
  await page.screenshot({path:path.join(shots,`settings-${theme}-${width}.png`),animations:'disabled'});
  await page.locator('#gr-auto-panel [data-close]').click();assert.equal(await page.locator('#gr-auto-panel').evaluate(el=>el.inert),true);await page.waitForFunction(()=>document.activeElement?.matches('[data-settings-nav]'));
 }
 await page.setViewportSize({width:1440,height:1000});await goto('reports');await page.selectOption('[data-ent-filter=status]','NEEDS_REVIEW');assert.equal(await page.locator('.ent-print-report tbody tr').count(),1);await page.selectOption('[data-ent-filter=status]','ALL');
 await goto('diagnostics');const readinessCount=requests.filter(x=>x.path==='/api/gpo/readiness').length;await page.locator('[data-ent-diagnose]').click();await page.waitForFunction(()=>document.querySelector('[data-ent-diagnose]')?.disabled===false);assert(requests.filter(x=>x.path==='/api/gpo/readiness').length>readinessCount);
 await goto('assurance');await page.selectOption('#assurance-gpo',gpo.id);await page.locator('[data-scope-open="assurance-scope"]').click();await page.locator(`[data-scope-choose="${dn}"]`).click();await page.locator('#assurance-access button[type=submit],#assurance-access button.primary').click();await page.getByRole('heading',{name:'Effective access report'}).waitFor();await shot('access-report');
 await page.setViewportSize({width:1440,height:1000});await goto('benchmark');await page.locator('#catalog-search').fill('1.2.2');await page.locator('[data-rule="1.2.2"]').first().click();await page.locator('[data-tab=verification]').click();await page.locator('[data-verify]').click();await page.locator('[data-live-verification]').waitFor();assert.equal(await page.locator('.result-summary').count(),0);
 const verify=jobs.at(-1);verify.state='RUNNING';history[0].result.state='VERIFYING';history[0].liveChecks=[{phase:'ENDPOINT',state:'CHECKING',subject:'ws02.example.local',message:'Reading current value'}];
 await page.getByText('Reading current value',{exact:true}).waitFor();await shot('verify-running');
 verify.state='COMPLETED';history[0].result.state='PUBLISHED';await page.locator('.result-summary').waitFor();assert.equal(requests.filter(x=>x.path==='/api/workflows/verify').length,1);
 await goto('benchmark');await page.locator('[data-bulk-mode]').click();for(const id of ['1.2.2','17.7.5']){await page.locator('#catalog-search').fill(id);await page.locator(`[data-bulk-select="${id}"]`).check();}await page.locator('[data-bulk-open]').click();await page.selectOption('#bulk-gpoId',gpo.id);await page.selectOption('#bulk-scopeDn',dn);await page.locator('[data-bulk-form] button[type=submit]').click();await page.locator('[data-bulk-approval]').waitFor();await page.fill('#bulk-reference','CHG-1042');await page.locator('#bulk-impact').check();await page.fill('#bulk-confirmation','APPLY');await page.locator('[data-bulk-approval] button[type=submit]').click();await page.getByRole('heading',{name:'Applying selected controls',exact:true}).waitFor();await shot('bulk-running');
 if(phase!=='before'){
  assert.match(await page.locator('.execution-rail').textContent(),/1.2.2/);assert.equal(await page.locator('.execution-rail [data-execution-state=current]').count(),1);
  assert.equal(await page.locator('progress[aria-label="Controls processed"]').getAttribute('value'),'0');
  jobs.at(-1).completedIds=[plans[0].id];jobs.at(-1).currentOperationId='rebased-operation';
  history.push({...record(plans[0].id,plans[0].selection.setting,'ENDPOINT_VERIFICATION_PENDING',[checks[2]]),plan:plans[0]});
  history.push({...record('rebased-operation',plans[1].selection.setting,'ENDPOINT_VERIFICATION_PENDING',[]),plan:{...plans[1],id:'rebased-operation'},result:{state:'APPLYING'},stages:[{phase:'PUBLICATION_CHECK'}]});
  await page.waitForFunction(()=>document.querySelector('.execution-rail [data-execution-state=current]')?.textContent.includes('17.7.5'));
  assert.equal(await page.locator('progress[aria-label="Controls processed"]').getAttribute('value'),'1');await shot('bulk-running-next');
  assert.match(await page.locator('.bulk-table tbody tr').nth(1).textContent(),/Processing.*Check in progress/);
  history.at(-1).stages=[{phase:'REPLICATION_ENDPOINT_CHECK'}];
  await page.waitForFunction(()=>document.querySelector('.execution-rail>p')?.textContent.includes('replication endpoint check'));
  jobs.at(-1).currentOperationId=null;
  await page.waitForFunction(()=>document.querySelectorAll('.execution-rail [data-execution-state=current]').length===0);
  assert.match(await page.locator('.execution-rail h4').textContent(),/Waiting/,'No active control may be inferred from the queue');
  await page.emulateMedia({reducedMotion:'reduce'});
  assert(await page.evaluate(()=>[...document.querySelectorAll('.bulk-dialog,.checking-dot,.execution-rail li')].every(el=>getComputedStyle(el).animationName==='none')),'Reduced motion must suppress workspace animations');
  await page.keyboard.press('Escape');await goto('operations');await page.locator('[data-inspect="run-review"]').first().click();await page.locator('.product-drawer').waitFor();
  assert.equal(await page.locator('.product-drawer').evaluate(el=>el.getAnimations({subtree:true}).length),0,'Reduced motion must also suppress JS entrance animations');
 }
 await page.keyboard.press('Escape');await page.emulateMedia({reducedMotion:'no-preference'});signInRequired=true;
 for(const theme of ['light','dark'])for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await page.goto(base+'/?theme='+theme+'&login='+Date.now()+'#/dashboard');await page.locator('.operator-sign-in-card').waitFor();await page.evaluate(()=>document.fonts.ready);await page.screenshot({path:path.join(shots,`sign-in-${theme}-${width}.png`),animations:'disabled'});assert(await page.locator('.operator-sign-in-emblem img').evaluate(img=>img.complete&&img.naturalWidth>0));}
 await page.fill('.operator-sign-in [name=password]','fixture-only');await page.locator('.operator-sign-in button[type=submit]').click();await page.waitForFunction(()=>document.querySelector('.operator-sign-in form')?.getAttribute('aria-busy')==='true');assert.match(await page.locator('.operator-sign-in-status').textContent(),/Checking/);await page.waitForFunction(()=>document.querySelector('.operator-sign-in button[type=submit]')?.disabled===true);assert(signInRelease);signInRelease();await page.locator('.dashboard-page').waitFor();
 assert.equal(requests.filter(x=>/\/(apply|refresh|rollback)$/.test(x.path)).length,1,'Only the explicitly approved mock apply may be submitted');assert.deepEqual(errors,[]);
 console.log('PASS '+phase+': Dashboard, Benchmark, Operations, drawer, Verification, Bulk Apply in both themes at desktop/mobile; live read-only verification and approved mocked bulk progress.');
 }finally{await browser?.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
