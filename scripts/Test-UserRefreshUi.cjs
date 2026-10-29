/* Real user-policy result and refresh dialog; private HTTP fixtures, no AD. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),shots=path.resolve(__dirname,'../work/screens/user-refresh');fs.mkdirSync(shots,{recursive:true});
const gpoId='11111111-1111-1111-1111-111111111111',scopeDn='OU=Users,DC=example,DC=local',endpointDn='OU=Clients,DC=example,DC=local';
const settings=JSON.parse(fs.readFileSync(path.resolve(root,'../../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const inventory={domain:'example.local',domainController:'dc.example.local',gpos:[{id:gpoId,name:'User Pilot GPO',selectable:true}],scopes:[{dn:'DC=example,DC=local',name:'example.local',kind:'Domain'},{dn:scopeDn,name:'Users',kind:'OU'},{dn:endpointDn,name:'Clients',kind:'OU'}]};
const record={id:'user-run',updatedAt:'2026-10-27T04:09:00Z',approval:{},plan:{selection:{gpoId,scopeDn,setting:'19.7.5.2',accountScope:'Users',refresh:'None'},preview:{gpo:inventory.gpos[0],scope:inventory.scopes[1],desiredValue:'3'}},result:{state:'PUBLISHED',message:'Published; user session evidence pending.',gpoPublished:true,linkVerified:true,currentValue:'3',effectiveStatus:'ENDPOINT_VERIFICATION_PENDING',verificationStages:[{stage:'GPO_CONFIGURATION',status:'GPO_APPLIED',evidence:'Saved value 3'}],endpointChecks:[{hostname:'<user-session>',state:'PENDING',message:'Choose a sampled user and session endpoint to verify HKCU.',actualValue:null}]}};
const mutations=[];let workflowJobs=[];
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/')){let body='';for await(const chunk of req)body+=chunk;const payload=body?JSON.parse(body):{};let data={};
 if(url.pathname==='/api/session')data={mode:'WINDOWS',operator:'EXAMPLE\\operator',csrfToken:'fixture'};
 else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
 else if(url.pathname==='/api/gpo/settings')data=settings;
 else if(url.pathname==='/api/gpo/inventory')data=inventory;
 else if(url.pathname==='/api/gpo/history')data=[record];
 else if(url.pathname==='/api/gpo/session')data={connected:true};
 else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
 else if(url.pathname==='/api/gpo/target-access')data={authorized:true};
 else if(url.pathname==='/api/workflows/refresh'&&req.method==='POST'){mutations.push(payload);res.statusCode=202;data={id:'user-refresh-job',state:'QUEUED',action:'refresh',message:'Fixture user refresh accepted',planIds:[record.id],completedIds:[]};workflowJobs=[data];}
 else if(url.pathname==='/api/workflows')data=workflowJobs;
 else if(['/api/batches','/api/password-policies'].includes(url.pathname))data=[];
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;}
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
}catch(e){res.statusCode=500;res.end(e.message);}});
(async()=>{let browser;try{await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(15000);
 await page.goto('http://127.0.0.1:'+server.address().port+'/#/benchmark');await page.fill('#catalog-search','19.7.5.2');await page.locator('[data-rule="19.7.5.2"]').first().click();await page.locator('[data-tab=verification]').click();await page.locator('.recorded-result-context').waitFor();
 assert.equal(await page.locator('[data-gpupdate]').isDisabled(),true);assert.match(await page.locator('.refresh-block-reason').textContent(),/no session endpoint OU/);assert.equal(await page.locator('.manual-check-command').count(),0,'Placeholder session must not produce an impossible host command');
 record.plan.selection.endpointScopeDn=endpointDn;
 await page.locator('.service-right [data-refresh]').click();await page.waitForFunction(()=>!document.querySelector('[data-gpupdate]')?.disabled);
 assert.match(await page.locator('[data-gpupdate]').textContent(),/target:user/);
 await page.locator('[data-gpupdate]').click();assert.equal(await page.locator('#refresh-target').inputValue(),'Scope');assert.equal(await page.locator('#refresh-target option').count(),1);assert.match(await page.locator('#refresh-target').textContent(),/User sessions/);assert(!/PDC emulator/.test(await page.locator('.confirm-dialog').textContent()));assert.match(await page.locator('.confirm-dialog').textContent(),/Scheduling does not prove completion/);assert.equal(mutations.length,0);
 await page.screenshot({path:path.join(shots,'user-refresh-dialog-desktop.png'),fullPage:true});await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:path.join(shots,'user-refresh-dialog-mobile.png'),fullPage:true});
 await page.locator('[data-confirm-cancel]').click();assert.equal(mutations.length,0,'Cancel must never schedule user refresh');
 await page.locator('[data-gpupdate]').click();await page.locator('[data-confirm-run]').click();await page.waitForFunction(()=>!document.querySelector('.busy-layer'));assert.equal(mutations.length,1);assert.equal(mutations[0].refresh,'Scope');assert.deepEqual(mutations[0].planIds,[record.id]);
 await page.setViewportSize({width:1440,height:1000});
 workflowJobs[0].state='CHECKS_INCOMPLETE';workflowJobs[0].message='User profile evidence pending.';
 record.result.endpointChecks=[{hostname:'client1.example.local',state:'PENDING',message:'User profile evidence pending.',actualValue:null}];
 await page.locator('.service-right [data-refresh]').click();await page.locator('.verification-details summary').first().click();await page.locator('.manual-check-details summary').click();await page.locator('.manual-check-command').waitFor();assert.match(await page.locator('.manual-check-head').textContent(),/affected signed-in user/);assert(!/Administrator/.test(await page.locator('.manual-check-head').textContent()));assert.match(await page.locator('.manual-check-command').textContent(),/HKEY_CURRENT_USER/);assert(!/<user-session>/.test(await page.locator('.manual-check-command').textContent()));assert.deepEqual(errors,[]);
 console.log('PASS real user result: missing session OU disabled, no placeholder command, Scope-only user dialog, cancel/no-write, recorded operation request, user-context manual check and mobile fit');
}finally{await browser?.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
