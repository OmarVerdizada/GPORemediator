/* Reproduce the reviewed user-rights target form and interrupted operation. No AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),shots=path.resolve(__dirname,'../work/screens/3.17.2');fs.mkdirSync(shots,{recursive:true});
const mappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const dn='OU=Mixed,DC=example,DC=test',gpo={id:'11111111-1111-1111-1111-111111111111',name:'Pilot policy',protected:false,selectable:true};
const inventory={domain:'example.test',domainController:'dc.example.test',executionUser:'EXAMPLE\\operator',gpos:[gpo],scopes:[{dn,name:'Mixed users and computers',kind:'OU'}]};
const reviewed='Windows member computers reviewed; IIS roles and approved principal exceptions checked.';
const selection={setting:'2.2.6',gpoId:gpo.id,scopeDn:dn,accountScope:'LocalComputers',refresh:'None',firstLink:false,value:0,reviewContext:reviewed,itemValues:[['S-1-5-19','S-1-5-20','S-1-5-32-544']]};
const plan={id:'interrupted-right',selection,executionUser:inventory.executionUser,domain:inventory.domain,domainController:inventory.domainController,writeAuthorized:true,preview:{gpo,scope:inventory.scopes[0],previousValue:null,desiredValue:'S-1-5-19,S-1-5-20,S-1-5-32-544',existingLink:null,refreshComputers:[],warnings:[],preflight:{ready:true,checks:[]}}};
const error='Stage WRITING_POLICY failed (UnauthorizedAccessException). Check GPO Edit settings and SYSVOL write access. <unsafe>';
const history=[{id:plan.id,plan,result:{state:'REVIEW_REQUIRED',message:error,gpoPublished:false,linkVerified:false,currentValue:null,effectiveStatus:'UNKNOWN',endpointChecks:[],refreshResults:[]},stages:[{phase:'WRITING_POLICY',startedAt:'2026-10-30T04:27:44Z'}],updatedAt:'2026-10-30T04:27:44Z'}];
const requests=[];
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');let body='';for await(const chunk of req)body+=chunk;
 if(url.pathname.startsWith('/api/')){
  const data=body?JSON.parse(body):null;requests.push({path:url.pathname,method:req.method,data});let response={};
  if(url.pathname==='/api/session')response={mode:'WINDOWS',csrfToken:'fixture',operator:inventory.executionUser,operatorConfirmationRequired:false};
  else if(url.pathname==='/api/service')response={mode:'WINDOWS',writesEnabled:true,processId:1};
  else if(url.pathname==='/api/gpo/session')response={connected:true};
  else if(url.pathname==='/api/gpo/settings')response=mappings;
  else if(url.pathname==='/api/gpo/inventory')response=inventory;
  else if(url.pathname==='/api/gpo/history')response=history;
  else if(url.pathname==='/api/gpo/readiness')response={ready:true,checks:[]};
  else if(url.pathname==='/api/gpo/target-access')response={authorized:true};
  else if(url.pathname==='/api/gpo/preview')response={...plan,id:'fresh-preview',selection:data};
  else if(url.pathname==='/api/gpo/'+plan.id+'/replan')response={...plan,id:'repair-plan'};
  else if(url.pathname==='/api/setup/config')response={exists:true,...inventory,approvedGpoIds:[gpo.id],authorizedOus:[dn],endpointTargeting:'SelectedOu',allowedHosts:[]};
  else if(['/api/workflows','/api/audit'].includes(url.pathname))response=[];
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(response));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
}catch(error){res.statusCode=500;res.end(error.message);}});
(async()=>{let browser;try{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1100}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(15000);
 async function screenshot(name){await page.evaluate(()=>window.scrollTo({top:0,behavior:'instant'}));await page.screenshot({path:path.join(shots,name),fullPage:true,animations:'disabled'});}
 await page.goto('http://127.0.0.1:'+server.address().port+'/#/benchmark');
 async function selectControl(id){await page.goto('http://127.0.0.1:'+server.address().port+'/#/benchmark');await page.locator('#catalog-search').fill(id);await page.locator('[data-rule="'+id+'"]').first().click();await page.locator('[data-tab=remediation]').click();}
 await selectControl('2.2.6');await page.locator('[data-reviewed-execution]').click();
 await page.locator('#gpo-selection [data-policy-target=Computer]').waitFor();
 assert.match(await page.locator('.policy-target-guidance').textContent(),/computer accounts.*user rights/s);
 const field=page.locator('#review-context');await field.fill('Test');
 assert.match(await page.locator('#review-context-count').textContent(),/4 \/ 2048/);
 assert.equal(await field.evaluate(x=>x.validity.valid),true,'Short nonempty review must be accepted');
 assert.equal(await field.getAttribute('minlength'),null);
 await page.locator('[data-gpo-toggle]').click();await page.locator('[data-gpo="'+gpo.id+'"]').click();
 await page.locator('[data-scope-open=scopeDn]').click();await page.locator('[data-scope-choose="'+dn+'"]').click();
 assert.equal(await field.inputValue(),'Test','Target selection lost the review draft');
 assert.equal(await page.locator('.step[aria-current=step] span').textContent(),'Target','Old operation overrode target selection');
 const before=requests.filter(x=>x.path==='/api/gpo/preview').length;
 await field.fill('          ');await page.locator('#gpo-selection button.primary-action').click();
 assert.equal(requests.filter(x=>x.path==='/api/gpo/preview').length,before,'Whitespace review reached preview');
 await field.fill(reviewed);assert.equal(await field.evaluate(x=>x.validity.valid),true);
 const bounds=await field.boundingBox(),gpoBounds=await page.locator('.gpo-picker-trigger').boundingBox();assert(bounds.width>=gpoBounds.width-2,'Review field is narrower than the target form');
 await page.locator('[data-policy-value="0"]').fill(selection.itemValues[0].join('\n'));
 await screenshot('reviewed-computer-target.png');
 await page.locator('#gpo-selection button.primary-action').click();await page.locator('.plan-card').waitFor();
 const posted=requests.filter(x=>x.path==='/api/gpo/preview').at(-1).data;
 assert.equal(await page.locator('.diff-before strong').textContent(),'Not configured in selected GPO');
 assert(!/Not checked/.test(await page.locator('.plan-card').textContent()),'Absent GPO setting must be explicit');
 const targetIdentity=await page.locator('.plan-facts .pr-identity code').boundingBox(),targetCell=await page.locator('.plan-facts>div').nth(1).boundingBox();
 assert(targetIdentity.x+targetIdentity.width<=targetCell.x+targetCell.width,'Target DN overflows into the next plan fact');
 assert.equal(posted.reviewContext,reviewed);assert.deepEqual(posted.itemValues,selection.itemValues);assert.equal(posted.scopeDn,dn);
 assert.equal(await page.locator('.step[aria-current=step] span').textContent(),'Preview','Old operation overrode the fresh plan stage');
 assert.equal(await page.locator('.step').filter({hasText:'Apply'}).locator('b').textContent(),'5');
 await page.locator('[data-tab=verification]').click();assert.equal(await page.locator('.verification-explanation').textContent(),error);
 assert.equal(await page.locator('.verification-explanation').evaluate(x=>!!x.closest('details')),false,'Primary failure is hidden');
 assert.match(await page.locator('.configured-value').textContent(),/Read unavailable/);
 assert.equal(await page.locator('.verification-explanation unsafe').count(),0,'Failure message became markup');
 assert.match(await page.locator('.operation-failure-guidance').textContent(),/read-only Re-verify/);
 await screenshot('interrupted-operation.png');
 await page.locator('[data-replan]').click();await page.locator('.plan-card').waitFor();
 assert.equal(await page.locator('[data-tab=remediation]').getAttribute('aria-selected'),'true');
 assert.equal(await page.locator('.step[aria-current=step] span').textContent(),'Preview');assert.equal(await field.inputValue(),reviewed);
 await screenshot('repair-plan.png');
 for(const width of [390,320]){await page.setViewportSize({width,height:950});const box=await field.boundingBox(),form=await page.locator('#gpo-selection').boundingBox();assert(box.width>=form.width-2&&box.x>=form.x&&box.x+box.width<=width,'Review field overflows or shrinks at '+width);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Page overflow at '+width);}
 await screenshot('reviewed-target-320.png');
 await page.setViewportSize({width:1440,height:1100});await page.locator('#appearance-trigger').click();await page.locator('#preference-theme').selectOption('dark');await page.locator('#appearance-trigger').click();await screenshot('reviewed-target-dark.png');
 await selectControl('19.7.5.2');await page.locator('#gpo-selection [data-policy-target=User]').waitFor();assert.match(await page.locator('.policy-target-guidance').textContent(),/OU containing the user accounts/);
 assert.deepEqual(errors,[]);assert(!requests.some(x=>/\/workflows\/|\/apply$|\/rollback$|\/refresh$/.test(x.path)),'Presentation check submitted a policy operation');
 console.log('PASS reviewed 2.2.6 form, visible user/computer scope, whitespace validation, preserved principal/review drafts, fresh repair steps, visible escaped failure, unknown-value semantics, light/dark and 320/390px layouts; no policy operations');
}finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}})().catch(e=>{console.error(e);process.exitCode=1;});
