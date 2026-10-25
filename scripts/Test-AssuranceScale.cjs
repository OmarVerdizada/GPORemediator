/* Real UI/assets and local recorded API responses. No AD or policy mutations. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),vm=require('node:vm'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),screens=path.resolve(__dirname,'../work/screens/frontend-polish');
fs.mkdirSync(screens,{recursive:true});
const bootstrap=fs.readFileSync(path.join(root,'theme-bootstrap.js'),'utf8');
for(const [saved,system,expected] of [['dark',false,'dark'],['light',true,'light'],['system',true,'dark'],['invalid',false,'light']]){
 const document={documentElement:{dataset:{}}};
 vm.runInNewContext(bootstrap,{document,sessionStorage:{getItem:key=>key==='gr-theme'?saved:null},matchMedia:()=>({matches:system})});
 assert.equal(document.documentElement.dataset.grTheme,expected);
}
vm.runInNewContext(bootstrap,{document:{documentElement:{dataset:{}}},sessionStorage:{getItem(){throw Error('blocked');}},matchMedia:()=>({matches:false})});
const html=fs.readFileSync(path.join(root,'index.html'),'utf8');assert.ok(html.indexOf('/theme-bootstrap.js')<html.indexOf('/app.css'),'appearance must apply before styles paint');
const mappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const inventory={domain:'example.local',domainController:'dc.example.local',executionUser:'EXAMPLE\\operator',gpos:[{id:'11111111-1111-1111-1111-111111111111',name:'Workstation baseline',selectable:true,protected:false}],scopes:[{name:'example.local',dn:'DC=example,DC=local',kind:'Domain'},{name:'Workstations',dn:'OU=Workstations,DC=example,DC=local',kind:'OU'}]};
inventory.scopes.push(...Array.from({length:5000},(_,i)=>({kind:'OU',dn:'OU=Unit'+i+',DC=example,DC=local',name:'Unit'+i})));
inventory.gpos.push(...Array.from({length:250},(_,i)=>({id:'fixture-gpo-'+i,name:'Policy '+i,selectable:true})));
const history=Array.from({length:10000},(_,i)=>({id:'run'+i,updatedAt:new Date(1700000000000+i*1000).toISOString(),plan:{id:'run'+i,selection:{gpoId:inventory.gpos[0].id,scopeDn:inventory.scopes[1].dn,setting:'18.1.1.1',accountScope:'LocalComputers',refresh:'None'},preview:{gpo:inventory.gpos[0],scope:inventory.scopes[1],verificationComputers:['pc.example.local']},executionUser:'EXAMPLE\\operator'},result:{state:'NO_CHANGE',effectiveStatus:'ENDPOINT_VERIFICATION_PENDING',message:'Fixture',refreshResults:[]}}));
const events=Array.from({length:10000},(_,i)=>({id:i,event:'EVENT'+i,operator:'EXAMPLE\\operator',createdAt:new Date().toISOString(),hash:'a'.repeat(64)}));
const requests=[];
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');let text='';for await(const part of req)text+=part;
 if(url.pathname.startsWith('/api/')){
  requests.push({path:url.pathname,method:req.method,body:text?JSON.parse(text):null});let data={};
  if(url.pathname==='/api/session')data={mode:'WINDOWS',csrfToken:'fixture',operator:'EXAMPLE\\operator'};
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:false,processId:1};
  else if(url.pathname==='/api/gpo/settings')data=mappings;
  else if(url.pathname==='/api/gpo/inventory')data=inventory;
  else if(url.pathname==='/api/gpo/session')data={connected:true};
  else if(url.pathname==='/api/gpo/target-access')data={authorized:true};
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
  else if(url.pathname==='/api/setup/config')data={exists:true,...inventory,approvedGpoIds:['*'],authorizedOus:['DC=example,DC=local'],allowedHosts:[],endpointTargeting:'SelectedOu'};
  else if(url.pathname==='/api/setup/discover')data={...inventory,warnings:[]};
  else if(url.pathname==='/api/gpo/history')data=history;
  else if(url.pathname==='/api/audit')data={integrityValid:true,events};
  else if(url.pathname==='/api/gpo/access-report')data={ready:false,executionUser:'EXAMPLE\\operator',domainController:'dc.example.local',checks:[{id:'file',label:'Selected policy file',state:'DENIED',target:'C:\fixture\GPT.INI',requiredRight:'Write',remedy:'Repair only this GPO <unsafe>',required:true}]};
  else if(/^\/api\/gpo\/run\d+\/explain$/.test(url.pathname))data={state:'CONFLICT_RECORDED',hostname:'pc.example.local',items:[{key:'Test',state:'OTHER_GPO_WINS',winningName:'Competing policy'}],findings:[],gpos:[],events:[],effectiveChecks:[],pendingRestart:{state:'UNKNOWN'}};
  else if(['/api/gpo/history','/api/workflows','/api/batches','/api/audit','/api/password-policies'].includes(url.pathname))data=[];
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
}catch(e){res.statusCode=500;res.end(e.message);}});
(async()=>{let browser;try{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
 const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(20000);
 await page.goto('http://127.0.0.1:'+server.address().port+'/#/operations');await page.locator('.ds-table tbody tr').first().waitFor();
 assert.equal(await page.locator('.ds-table tbody tr').count(),50,'10000 operations render at most 50 rows');
 const first=await page.locator('.ds-table tbody tr').first().locator('[data-inspect]').getAttribute('data-inspect');await page.locator('[data-list-page=ops][data-page="1"]').click();assert.notEqual(await page.locator('.ds-table tbody tr').first().locator('[data-inspect]').getAttribute('data-inspect'),first);
 await page.fill('#ops-search','run9999'); // IDs are not a search field; filter with execution account below.
 await page.fill('#ops-search','EXAMPLE');assert.equal(await page.locator('.ds-table tbody tr').count(),50);assert.match(await page.locator('.list-pagination').textContent(),/Page 1/);
 await page.evaluate(()=>location.hash='#/audit');await page.locator('.audit-event-row').first().waitFor();assert.equal(await page.locator('.audit-event-row').count(),100);
 await page.locator('[data-list-page=audit][data-page="1"]').click();assert.match(await page.locator('.audit-event-row').first().textContent(),/#100/);
 await page.fill('#audit-search','EVENT9999');assert.equal(await page.locator('.audit-event-row').count(),1);assert.match(await page.locator('.audit-event-row').textContent(),/EVENT9999/);
 await page.evaluate(()=>location.hash='#/assurance');await page.locator('#assurance-access').waitFor();
 await page.selectOption('#assurance-gpo',inventory.gpos[0].id);await page.locator('[data-scope-open="assurance-scope"]').click();
 assert.equal(await page.locator('.visual-scope-row').count(),240,'5000 OUs bounded in DOM');
 await page.locator('[data-list-page=scope][data-page="1"]').click();assert.equal(await page.locator('.visual-scope-row').count(),240);
 await page.fill('#scope-search','Unit4999');assert.equal(await page.locator('[data-scope-choose="OU=Unit4999,DC=example,DC=local"]').count(),1);
 await page.locator('[data-scope-choose="OU=Unit4999,DC=example,DC=local"]').click();await page.locator('[data-assurance=firstLink]').check();await page.locator('#assurance-access button.primary').click();await page.locator('[aria-label="Exact target permissions"]').waitFor();
 assert.match(await page.locator('[aria-label="Exact target permissions"]').textContent(),/C:\fixture\GPT.INI/);assert.equal(await page.locator('unsafe').count(),0);assert.equal(requests.find(x=>x.path==='/api/gpo/access-report').body.firstLink,true,'permission report checks requested link-priority change');
 await page.fill('#assurance-run-search','run9999');await page.selectOption('#assurance-operation','run9999');await page.selectOption('#assurance-host','pc.example.local');
 await page.locator('#assurance-explain button.primary').click();await page.locator('[aria-label="Per-setting policy sources"]').waitFor();assert.match(await page.locator('[aria-label="Per-setting policy sources"]').textContent(),/Competing policy/);
 assert.ok(requests.some(x=>x.path==='/api/gpo/run9999/explain'&&x.method==='POST'));
 for(const theme of ['light','dark']){
  await page.locator('.ds-preferences').evaluate(el=>el.open=true);await page.selectOption('#preference-theme',theme);await page.locator('.ds-preferences').evaluate(el=>el.open=false);
  await page.waitForFunction(()=>{const light=s=>(s.match(/[\d.]+/g)||[]).slice(0,3).map(Number).map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4;}).reduce((sum,x,i)=>sum+x*[.2126,.7152,.0722][i],0);return ['#assurance-gpo-search','#assurance-gpo','#assurance-control','#assurance-access button.primary'].every(selector=>{const el=document.querySelector(selector),css=getComputedStyle(el),a=light(css.color),b=light(css.backgroundColor);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05)>=4.5});});
  for(const width of [1440,390,320]){await page.setViewportSize({width,height:900});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),theme+' '+width+' assurance overflow');}
 }
 const shots=path.resolve(__dirname,'../work/screens/assurance');fs.mkdirSync(shots,{recursive:true});await page.setViewportSize({width:1440,height:1000});await page.locator('.ds-preferences').evaluate(el=>el.open=true);await page.selectOption('#preference-theme','light');await page.locator('.ds-preferences').evaluate(el=>el.open=false);await page.evaluate(()=>scrollTo(0,0));await page.screenshot({animations:'disabled',path:path.join(shots,'desktop-light.png')});await page.setViewportSize({width:390,height:900});await page.locator('.ds-preferences').evaluate(el=>el.open=true);await page.selectOption('#preference-theme','dark');await page.locator('.ds-preferences').evaluate(el=>el.open=false);await page.screenshot({animations:'disabled',path:path.join(shots,'mobile-dark.png')});
 assert.ok(!requests.some(x=>/\/(apply|rollback|refresh)$/.test(x.path)),'diagnostic actions never write/refresh policy');assert.deepEqual(errors,[]);
 console.log('PASS 10000 operations/audit, 5000 OU pagination/search, exact access and RSoP UI, safe encoding, light/dark/mobile, no policy mutations.');
}finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}})().catch(e=>{console.error(e);process.exitCode=1;});
