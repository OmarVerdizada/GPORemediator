/* Recorded AD data only: English migration, theme contrast and mobile layout. */
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'../frontend/source'),screens=path.resolve(__dirname,'../work/screens/english-themes');fs.mkdirSync(screens,{recursive:true});
for(const name of fs.readdirSync(root).filter(x=>/\.(js|html|css|json)$/.test(x))){assert(!/[\u0259\u018f\u0131\u0130\u011f\u011e\u015f\u015e\u00e7\u00c7\u00f6\u00d6\u00fc\u00dc]/.test(fs.readFileSync(path.join(root,name),'utf8')),name+' contains legacy localized content');}
const mappings=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const inventory={domain:'example.local',domainController:'dc.example.local',executionUser:'EXAMPLE\\operator',gpos:[{id:'11111111-1111-1111-1111-111111111111',name:'Workstation baseline',selectable:true,protected:false}],scopes:[{name:'example.local',dn:'DC=example,DC=local',kind:'Domain'},{name:'Workstations',dn:'OU=Workstations,DC=example,DC=local',kind:'OU'}]};
const requests=[];
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');let body='';for await(const chunk of req)body+=chunk;
 if(url.pathname.startsWith('/api/')){
  requests.push({method:req.method,path:url.pathname});let data={};
  if(url.pathname==='/api/session')data={mode:'WINDOWS',csrfToken:'fixture',operator:'EXAMPLE\\operator',operatorConfirmationRequired:false};
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:false,processId:1};
  else if(url.pathname==='/api/gpo/settings')data=mappings;
  else if(url.pathname==='/api/gpo/inventory')data=inventory;
  else if(url.pathname==='/api/gpo/target-access')data={authorized:true,executionUser:inventory.executionUser};
  else if(url.pathname==='/api/gpo/session')data={connected:true};
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[{id:'SYSVOL',label:'SYSVOL',state:'PASS',message:'Policies directory is accessible.'}]};
  else if(url.pathname==='/api/setup/config')data={exists:true,domain:'example.local',domainController:'dc.example.local',approvedGpoIds:['*'],authorizedOus:['DC=example,DC=local'],allowedHosts:[],endpointTargeting:'SelectedOu'};
  else if(url.pathname==='/api/setup/discover')data={domain:'example.local',domainController:'dc.example.local',warnings:[]};
  else if(['/api/gpo/history','/api/workflows','/api/batches','/api/audit'].includes(url.pathname))data=[];
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
 }catch(e){res.statusCode=500;res.end(e.message);}});
async function inspect(page,label){
 const result=await page.evaluate(()=>{
  const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none';};
  const rgba=s=>(s.match(/[\d.]+/g)||[]).map(Number);
  const luminance=c=>c.slice(0,3).map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4;}).reduce((a,x,i)=>a+x*[.2126,.7152,.0722][i],0);
  function contrast(el){const style=getComputedStyle(el),foreground=rgba(style.color);let bg=[255,255,255];const chain=[];for(let e=el;e;e=e.parentElement)chain.unshift(e);for(const e of chain){const c=rgba(getComputedStyle(e).backgroundColor);if(c.length>=3){const a=c.length===4?c[3]:1;bg=bg.map((x,i)=>c[i]*a+x*(1-a));}}const a=luminance(foreground),b=luminance(bg);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);}
  const controls=[...document.querySelectorAll('#gr-auto-panel.open :is(h3,.gr-auto-field,.gr-auto-help,.gr-auto-btn,input,select,textarea),.studio-pulse-item small,.studio-pulse-item strong,.ds-preferences-panel label,.policy-value-editor :is(header strong,input),.target-card h2,.domain-policy-boundary :is(strong,p)')].filter(visible);
  return {lang:document.documentElement.lang,text:document.body.innerText,overflow:document.documentElement.scrollWidth>innerWidth+1,contrast:controls.map(e=>({name:(e.getAttribute('name')||e.className||e.tagName),ratio:contrast(e)})).filter(x=>x.ratio<4.5),languageOptions:[...document.querySelectorAll('[data-preference=language] option')].map(x=>x.value)};
 });
 assert.equal(result.lang,'en',label+' document language');assert(!/[\u0259\u018f\u0131\u0130\u011f\u011e\u015f\u015e\u00e7\u00c7\u00f6\u00d6\u00fc\u00dc]/.test(result.text),label+' contains untranslated text');assert(!result.overflow,label+' horizontal overflow');assert.deepEqual(result.languageOptions.length?result.languageOptions:['en'],['en']);assert.deepEqual(result.contrast,[],label+' text contrast below 4.5:1');
}
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});try{
 const context=await browser.newContext({viewport:{width:1440,height:1000}});await context.addInitScript(()=>{sessionStorage.setItem('gr-lang','az');sessionStorage.setItem('gr-theme','light');});const page=await context.newPage(),errors=[];page.setDefaultTimeout(20000);page.on('pageerror',e=>errors.push(e.message));const url=`http://127.0.0.1:${server.address().port}`;
 await page.goto(url+'/#/dashboard');await page.locator('.studio-overview').waitFor();assert.equal(await page.evaluate(()=>sessionStorage.getItem('gr-lang')),'en');
 for(const theme of ['light','dark']){
  await page.locator('.ds-preferences').evaluate(el=>{el.open=true;});await page.locator('[data-preference=theme]').selectOption(theme);await inspect(page,theme+' dashboard');await page.screenshot({path:path.join(screens,theme+'-dashboard.png'),fullPage:true});
  await page.evaluate(()=>window.dispatchEvent(new CustomEvent('gr:open')));await page.locator('#gr-auto-panel.open [name=domain]').waitFor({state:'attached'});await page.waitForFunction(()=>document.querySelector('#gr-auto-panel [name=domain]')?.value==='example.local');await page.locator('.gr-auto-connection').evaluate(el=>{el.open=true;});await page.locator('.gr-auto-advanced').evaluate(el=>{el.open=true;});await inspect(page,theme+' settings');await page.screenshot({path:path.join(screens,theme+'-settings.png')});
  await page.setViewportSize({width:390,height:844});await inspect(page,theme+' mobile settings');await page.screenshot({path:path.join(screens,theme+'-settings-mobile.png')});await page.locator('#gr-auto-panel [data-close]').click();await inspect(page,theme+' mobile dashboard');await page.screenshot({path:path.join(screens,theme+'-dashboard-mobile.png'),fullPage:true});await page.setViewportSize({width:1440,height:1000});
  await page.evaluate(()=>{location.hash='#/benchmark';});await page.locator('#catalog-search').fill('');await page.locator('#catalog-search').fill('1.1.1');await page.locator('[data-rule="1.1.1"]').first().click();await page.locator('[data-tab=remediation]').click();await inspect(page,theme+' control');await page.screenshot({path:path.join(screens,theme+'-control.png'),fullPage:true});await page.evaluate(()=>{location.hash='#/dashboard';});await page.locator('.studio-overview').waitFor();
 }
 await page.emulateMedia({colorScheme:'dark'});await page.locator('.ds-preferences').evaluate(el=>{el.open=true;});await page.locator('[data-preference=theme]').selectOption('system');assert.equal(await page.locator('html').getAttribute('data-gr-theme'),'dark');await page.emulateMedia({colorScheme:'light'});await page.waitForFunction(()=>document.documentElement.dataset.grTheme==='light');assert.equal(await page.locator('html').getAttribute('data-gr-theme'),'light');
 assert.deepEqual(errors,[]);assert.equal(requests.filter(r=>r.method!=='GET'&&r.path!=='/api/gpo/target-access').length,0,'Theme navigation triggered an API mutation');console.log('PASS English-only migration, light/dark/system themes, WCAG text contrast, desktop/mobile layout and no policy mutations.');
 }finally{await browser.close();server.close();}})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
