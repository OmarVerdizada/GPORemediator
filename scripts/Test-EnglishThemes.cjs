/* Recorded AD data only: English migration, theme contrast and mobile layout. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),screens=path.resolve(__dirname,'../work/screens/english-themes');fs.mkdirSync(screens,{recursive:true});
for(const name of fs.readdirSync(root).filter(x=>/\.(js|html|css|json)$/.test(x))){assert(!/[\u0259\u018f\u0131\u0130\u011f\u011e\u015f\u015e\u00e7\u00c7\u00f6\u00d6\u00fc\u00dc]/.test(fs.readFileSync(path.join(root,name),'utf8')),name+' contains legacy localized content');}
const mappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const inventory={domain:'example.local',domainController:'dc.example.local',executionUser:'EXAMPLE\\operator',gpos:[{id:'11111111-1111-1111-1111-111111111111',name:'Workstation baseline',selectable:true,protected:false}],scopes:[{name:'example.local',dn:'DC=example,DC=local',kind:'Domain'},{name:'Workstations',dn:'OU=Workstations,DC=example,DC=local',kind:'OU'}]};
const now='2026-11-10T06:45:00Z';
const selection={setting:'1.1.1',gpoId:inventory.gpos[0].id,scopeDn:inventory.scopes[1].dn,refresh:'Scope',accountScope:'LocalComputers'};
const run={id:'theme-check',updatedAt:now,plan:{selection,executionUser:inventory.executionUser,preview:{gpo:inventory.gpos[0],scope:inventory.scopes[1],previousValue:'12',desiredValue:'24'}},result:{state:'PUBLISHED',backupId:'fixture-backup',gpoPublished:true,linkVerified:true,effectiveStatus:'ENDPOINT_MISMATCH',currentValue:'24',verification:{replicationConverged:true,checkedAt:now},endpointChecks:[{hostname:'ws.example.local',state:'MISMATCH',message:'Current value differs.',actualValue:'12'}],refreshResults:[{computer:'ws.example.local',state:'FAILED',message:'Remote refresh failed.'}],verificationStages:[{stage:'ENDPOINT_CONFIGURATION',status:'ENDPOINT_MISMATCH',evidence:'Value differs.'}]}};
const requests=[];let login=false;
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');let body='';for await(const chunk of req)body+=chunk;
 if(url.pathname.startsWith('/api/')){
  requests.push({method:req.method,path:url.pathname});let data={};
  if(url.pathname==='/api/session')data={mode:'WINDOWS',csrfToken:'fixture',operator:'EXAMPLE\\operator',operatorConfirmationRequired:login,domainSignIn:true};
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:true,processId:1};
  else if(url.pathname==='/api/gpo/settings')data=mappings;
  else if(url.pathname==='/api/gpo/inventory')data=inventory;
  else if(url.pathname==='/api/gpo/preview')data={...run.plan,id:'theme-preview',selection:JSON.parse(body),writeAuthorized:true,preview:{...run.plan.preview,warnings:[],refreshComputers:[]}};
  else if(url.pathname==='/api/gpo/target-access')data={authorized:true,executionUser:inventory.executionUser};
  else if(url.pathname==='/api/gpo/session')data={connected:true};
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[{id:'SYSVOL',label:'SYSVOL',state:'PASS',message:'Policies directory is accessible.'}]};
  else if(url.pathname==='/api/setup/config')data={exists:true,domain:'example.local',domainController:'dc.example.local',approvedGpoIds:['*'],authorizedOus:['DC=example,DC=local'],allowedHosts:[],endpointTargeting:'SelectedOu'};
  else if(url.pathname==='/api/setup/discover')data={domain:'example.local',domainController:'dc.example.local',warnings:[]};
  else if(url.pathname==='/api/gpo/history')data=[run]; else if(url.pathname==='/api/audit')data={integrityValid:true,events:[]}; else if(['/api/workflows','/api/batches'].includes(url.pathname))data=[];
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
 }catch(e){res.statusCode=500;res.end(e.message);}});
async function inspect(page,label){
 const report=await page.evaluate(()=>{
  const cache=new Map(),ctx=document.createElement('canvas').getContext('2d',{willReadFrequently:true});
  function rgba(css){if(!cache.has(css)){ctx.clearRect(0,0,1,1);ctx.fillStyle=css;ctx.fillRect(0,0,1,1);cache.set(css,[...ctx.getImageData(0,0,1,1).data]);}return cache.get(css);}
  function over(f,b,opacity=1){const a=f[3]/255*opacity;return b.map((n,i)=>Math.round(f[i]*a+n*(1-a)));}
  function luminance(c){return c.map(n=>{n/=255;return n<=.04045?n/12.92:((n+.055)/1.055)**2.4;}).reduce((sum,n,i)=>sum+n*[.2126,.7152,.0722][i],0);}
  const results=[];
  for(const el of document.querySelectorAll('body *')){
   if(el.closest('[inert], [hidden], .sr-only, .skip-link, :disabled')||el.matches('svg *,script,style,template,option'))continue;
   const collapsed=el.closest('details:not([open])');
   if(collapsed&&el!==collapsed&&!collapsed.querySelector('summary')?.contains(el))continue;
   const style=getComputedStyle(el),r=el.getBoundingClientRect();
   if(!r.width||!r.height||r.right<=0||r.left>=innerWidth||style.visibility!=='visible')continue;
   const hasText=[...el.childNodes].some(n=>n.nodeType===Node.TEXT_NODE&&n.textContent.trim());
   const input=el.matches('input:not([type=checkbox]):not([type=radio]), textarea');
   if(!hasText&&!input&&!el.matches('select'))continue;
   if(input&&!el.value&&!el.placeholder)continue;
   const foreground=input&&!el.value?getComputedStyle(el,'::placeholder').color:style.color;
   let bg=[255,255,255],opacity=1;
   const chain=[];for(let n=el;n;n=n.parentElement)chain.unshift(getComputedStyle(n));
   for(const p of chain){bg=over(rgba(p.backgroundColor),bg);opacity*=Number(p.opacity);}
   if(!opacity)continue;
   const contrast=(a,b)=>(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
   const ratio=contrast(luminance(over(rgba(foreground),bg,opacity)),luminance(bg));
   if(ratio<4.49)results.push({el:el.className?.baseVal??el.className??'',p:el.parentElement?.className?.baseVal??el.parentElement?.className,txt:(input?el.name:el.textContent.trim()).slice(0,72),fg:foreground,bg:bg.join(','),o:opacity,r:+ratio.toFixed(2)});
  }
  return {width:document.documentElement.scrollWidth,viewport:innerWidth,results};
 });
 assert.ok(report.width<=report.viewport+1,label+' horizontal overflow');
 assert.deepEqual(report.results,[],label+' text contrast below 4.5:1');
 assert.equal(await page.locator('html').getAttribute('lang'),'en',label+' document language');
}
async function selectTheme(page,theme){
 await page.locator('.ds-preferences summary').click();
 await page.locator('#preference-theme').selectOption(theme);
 await page.keyboard.press('Escape');
}
async function go(page,route){
 await page.evaluate(route=>{location.hash='#/'+route;},route);
 await page.locator('[data-gpo-nav][href="#/'+route+'"][aria-current=page]').waitFor();
 await page.locator('#main-content[aria-busy=false]').waitFor();
}
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
 const url='http://127.0.0.1:'+server.address().port,errors=[];
 try{
  for(const theme of ['light','dark']){
   const context=await browser.newContext({colorScheme:theme,reducedMotion:'reduce',viewport:{width:1440,height:1000}});
   await context.addInitScript(()=>sessionStorage.setItem('gr-lang','az'));
   login=true;
   const signedOut=await context.newPage();
   signedOut.on('pageerror',e=>errors.push(e.message));
   await signedOut.goto(url+'/#/dashboard');
   await signedOut.locator('.operator-sign-in').waitFor();
   assert.equal(await signedOut.locator('#gr-auto-panel').evaluate(el=>getComputedStyle(el).visibility),'hidden');
   await signedOut.locator('[name=password]').fill('fixture-only');
   await signedOut.locator('[data-sign-in-theme]').selectOption(theme);
   assert.equal(await signedOut.locator('[name=password]').inputValue(),'fixture-only','Sign-in appearance cleared a field');
   await inspect(signedOut,theme+' sign-in');
   await signedOut.screenshot({path:path.join(screens,theme+'-sign-in.png'),animations:'disabled'});
   await signedOut.setViewportSize({width:320,height:780});await inspect(signedOut,theme+' mobile sign-in');
   await signedOut.close();

   login=false;
   const page=await context.newPage();
   page.on('pageerror',e=>errors.push(e.message));
   await page.emulateMedia({colorScheme:theme==='light'?'dark':'light'});
   await page.goto(url+'/#/dashboard');await page.locator('.dashboard-page').waitFor();
   assert.equal(await page.locator('html').getAttribute('data-gr-theme'),theme,'The theme must persist into a fresh tab and override the OS');
   assert.equal(await page.evaluate(()=>sessionStorage.getItem('gr-lang')),'en');
   await inspect(page,theme+' dashboard');
   await page.locator('.ds-preferences summary').click();await inspect(page,theme+' appearance');await page.keyboard.press('Escape');
   await page.evaluate(()=>window.dispatchEvent(new CustomEvent('gr:open')));
   await page.waitForFunction(()=>document.querySelector('#gr-auto-panel.open [name=domain]')?.value==='example.local');
   await page.locator('.gr-auto-connection,.gr-auto-advanced').evaluateAll(els=>els.forEach(el=>el.open=true));
   await inspect(page,theme+' settings');
   await page.setViewportSize({width:390,height:844});await inspect(page,theme+' mobile settings');
   await page.locator('#gr-auto-panel [data-close]').click();await inspect(page,theme+' mobile dashboard');
   await page.setViewportSize({width:1440,height:1000});
   for(const route of ['operations','reports','diagnostics','assurance','audit','benchmark']){
     await go(page,route);await inspect(page,theme+' '+route);
     if(route==='operations'){
       await page.locator('[data-inspect]').first().click();await inspect(page,theme+' operation details');
       await page.locator('.product-drawer [data-gpupdate]').click();
       await page.locator('[data-confirm-run]').hover();await inspect(page,theme+' confirmation hover');
       await page.locator('[data-confirm-cancel]').click();
     }
     if(route==='reports'){
       await page.emulateMedia({media:'print'});
       assert.equal(await page.locator('html').evaluate(el=>getComputedStyle(el).colorScheme),'light','Print must always use the light palette');
       await page.emulateMedia({media:'screen'});
     }
   }
   await page.locator('[data-bulk-mode]').click();
   await page.locator('#catalog-search').fill('1.1.1');await page.locator('[data-bulk-select="1.1.1"]').check();
   await page.locator('[data-bulk-open]').click();await inspect(page,theme+' bulk form');
   await page.locator('.bulk-dialog [data-bulk-close]').first().click();
   await page.locator('[data-rule="1.1.1"]').first().click();await inspect(page,theme+' control overview');
   await page.locator('[data-tab=remediation]').click();
   await page.locator('[data-gpo-toggle]').click();await inspect(page,theme+' GPO picker');
   await page.locator('[data-gpo="'+inventory.gpos[0].id+'"]').click();
   await page.locator('#gpo-selection>.primary-action:not(:disabled)').waitFor();
   const value=page.locator('#gpo-selection [name=value]');await value.fill('20');
   const draft=await value.elementHandle();await selectTheme(page,theme==='light'?'dark':'light');
   assert.equal(await draft.evaluate(el=>el.isConnected&&el.value==='20'),true,'Theme change replaced or cleared the active draft');
   await selectTheme(page,theme);await inspect(page,theme+' target form');
   await page.locator('[data-scope-open]').first().click();await inspect(page,theme+' OU picker');
   await page.locator('[data-scope-choose="'+inventory.scopes[1].dn+'"]').click();
   await page.locator('#gpo-selection>.primary-action').click();await page.locator('.plan-card').waitFor();await inspect(page,theme+' approval');
   await page.locator('[data-tab=verification]').click();await page.locator('.result-summary.danger').waitFor();await inspect(page,theme+' verification');
   await page.screenshot({path:path.join(screens,theme+'-verification.png'),fullPage:true,animations:'disabled'});
   await page.setViewportSize({width:390,height:844});await inspect(page,theme+' mobile verification');

   await page.emulateMedia({colorScheme:'dark'});await selectTheme(page,'system');
   assert.equal(await page.locator('html').getAttribute('data-gr-theme'),'dark');
   await page.emulateMedia({colorScheme:'light'});await page.waitForFunction(()=>document.documentElement.dataset.grTheme==='light');
   await context.close();
  }
  assert.deepEqual(errors,[]);
  assert.equal(requests.filter(r=>r.method!=='GET'&&!['/api/gpo/target-access','/api/gpo/preview'].includes(r.path)).length,0,'Appearance checks triggered an unexpected API mutation');
  console.log('PASS light/dark/system: sign-in and persistence, desktop/mobile screens, text contrast, intact drafts, light print palette and no policy mutations.');
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
