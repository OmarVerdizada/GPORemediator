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
const requests=[];
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');let text='';for await(const part of req)text+=part;
 if(url.pathname.startsWith('/api/')){
  requests.push({path:url.pathname,method:req.method});let data={};
  if(url.pathname==='/api/session')data={mode:'WINDOWS',csrfToken:'fixture',operator:'EXAMPLE\\operator'};
  else if(url.pathname==='/api/service')data={mode:'WINDOWS',writesEnabled:false,processId:1};
  else if(url.pathname==='/api/gpo/settings')data=mappings;
  else if(url.pathname==='/api/gpo/inventory')data=inventory;
  else if(url.pathname==='/api/gpo/session')data={connected:true};
  else if(url.pathname==='/api/gpo/target-access')data={authorized:true};
  else if(url.pathname==='/api/gpo/readiness')data={ready:true,checks:[]};
  else if(url.pathname==='/api/setup/config')data={exists:true,...inventory,approvedGpoIds:['*'],authorizedOus:['DC=example,DC=local'],allowedHosts:[],endpointTargeting:'SelectedOu'};
  else if(url.pathname==='/api/setup/discover')data={...inventory,warnings:[]};
  else if(['/api/gpo/history','/api/workflows','/api/batches','/api/audit','/api/password-policies'].includes(url.pathname))data=[];
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));return;
 }
 const file=path.resolve(root,'.'+decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));
 if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.statusCode=404;res.end();return;}
 res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.woff2':'font/woff2'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
}catch(e){res.statusCode=500;res.end(e.message);}});
(async()=>{let browser;try{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
 const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(15000);
 await page.addInitScript(()=>sessionStorage.setItem('gr-theme','dark'));
 await page.goto('http://127.0.0.1:'+server.address().port+'/#/dashboard');await page.locator('.studio-overview').waitFor();await page.evaluate(()=>document.fonts.ready);
 const appearance=page.locator('.ds-preferences'),trigger=appearance.locator('summary');
 await trigger.click();await page.locator('#preference-theme').focus();await page.locator('#preference-theme').selectOption('light');
 assert.equal(await page.evaluate(()=>document.activeElement.id),'preference-theme','theme change must preserve keyboard focus');
 await page.keyboard.press('Escape');assert.equal(await appearance.getAttribute('open'),null);assert.equal(await page.evaluate(()=>document.activeElement.id),'appearance-trigger');
 await trigger.click();await page.locator('h1').first().click();assert.equal(await appearance.getAttribute('open'),null,'outside click closes appearance');
 for(const theme of ['light','dark']){
  await appearance.evaluate(el=>el.open=true);await page.locator('#preference-theme').selectOption(theme);
  for(const accent of ['blue','cyan','violet']){
   await appearance.evaluate(el=>el.open=true);await page.locator('#preference-accent').selectOption(accent);
   assert.equal(await page.locator('html').getAttribute('data-accent'),accent);
   const ratios=await page.evaluate(()=>{
    const luminance=s=>(s.match(/[\d.]+/g)||[]).slice(0,3).map(Number).map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4;}).reduce((sum,x,i)=>sum+x*[.2126,.7152,.0722][i],0);
    return [['--color-on-primary','--color-primary'],['--color-text-muted','--color-surface'],['--color-text-muted','--color-surface-muted'],['--color-success','--color-success-soft'],['--color-warning','--color-warning-soft'],['--color-danger','--color-danger-soft']].map(([fg,bg])=>{
     const element=document.createElement('span');element.style.cssText='position:fixed;visibility:hidden;color:var('+fg+');background-color:var('+bg+')';document.body.append(element);
     const style=getComputedStyle(element),a=luminance(style.color),b=luminance(style.backgroundColor);element.remove();return {fg,bg,ratio:(Math.max(a,b)+.05)/(Math.min(a,b)+.05)};
    });
   });
   assert.ok(ratios.every(x=>x.ratio>=4.5),theme+' '+accent+' semantic text contrast: '+JSON.stringify(ratios));
  }
  await appearance.evaluate(el=>el.open=false);
  for(const width of [1440,768,390,320]){
   await page.setViewportSize({width,height:900});
   for(const route of ['dashboard','benchmark','workspace','reports','diagnostics','audit','password-policies','operations']){
    await page.evaluate(route=>location.hash='#/'+route,route);await page.locator('#main-content').waitFor();await page.waitForFunction(()=>document.querySelector('#main-content')?.getAttribute('aria-busy')==='false');
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),theme+' '+width+' '+route+' horizontal overflow');
   }
   if(width<=390){
    const metrics=await page.locator('.sidebar nav').evaluate(nav=>({scroll:nav.scrollWidth>nav.clientWidth,links:[...nav.querySelectorAll('.nav-link')].map(a=>({width:a.getBoundingClientRect().width,caption:a.querySelector('.ds-nav-mobile')?.scrollWidth,available:a.getBoundingClientRect().width-8}))}));
    assert.ok(metrics.scroll,'mobile navigation should scroll internally');assert.ok(metrics.links.every(a=>a.width>=64&&(!a.caption||a.caption<=a.available)),'mobile navigation labels overlap');
   }
   await page.evaluate(()=>location.hash='#/password-policies');await page.locator('#fgpp-preview').waitFor();
   await page.screenshot({path:path.join(screens,theme+'-'+width+'-password-policies.png'),fullPage:true,animations:'disabled'});
  }
 }
 await page.setViewportSize({width:390,height:844});await appearance.evaluate(el=>el.open=true);
 await page.locator('#preference-large-text').check();await page.locator('#preference-high-contrast').check();
 assert.equal(await page.locator('html').getAttribute('data-large-text'),'true');assert.equal(await page.locator('html').getAttribute('data-contrast'),'true');
 assert.equal(await page.evaluate(()=>getComputedStyle(document.documentElement).getPropertyValue('--color-text-muted').trim()),await page.evaluate(()=>getComputedStyle(document.documentElement).getPropertyValue('--color-text').trim()),'high contrast must retain semantic text contrast');
 const help=appearance.locator('[data-product-action=help]');assert.ok((await help.boundingBox()).width>200,'popover help button inherited icon width');
 await page.screenshot({path:path.join(screens,'mobile-appearance.png'),animations:'disabled'});await page.keyboard.press('Escape');
 await page.evaluate(()=>location.hash='#/audit');await page.waitForFunction(()=>document.querySelector('[href="#/audit"]')?.getAttribute('aria-current')==='page');
 assert.equal(await page.evaluate(()=>document.activeElement.id),'main-content','route changes must move keyboard focus to the new main content');
 assert.ok(await page.locator('.sidebar nav').evaluate(nav=>nav.scrollLeft>0),'active mobile destination must scroll into view');
 await page.evaluate(()=>location.hash='#/benchmark');await page.locator('#catalog-search').fill('1.1.1');await page.locator('[data-rule="1.1.1"]').first().click();await page.locator('[data-tab=overview]').focus();await page.keyboard.press('ArrowRight');
 assert.equal(await page.locator('[data-tab=remediation]').getAttribute('aria-selected'),'true');assert.equal(await page.locator('[data-tab=remediation]').evaluate(el=>document.activeElement===el),true);
 await page.keyboard.press('End');assert.equal(await page.locator('[data-tab=verification]').getAttribute('aria-selected'),'true');await page.keyboard.press('Home');assert.equal(await page.locator('[data-tab=overview]').getAttribute('aria-selected'),'true');
 await page.setViewportSize({width:1440,height:560});await page.locator('[data-settings-nav]').scrollIntoViewIfNeeded();
 assert.ok(await page.locator('.sidebar nav').evaluate(nav=>nav.scrollHeight>nav.clientHeight),'short desktops need scrollable navigation');
 await page.locator('.skip-link').focus();await page.waitForFunction(()=>document.querySelector('.skip-link').getBoundingClientRect().top>=0);await page.locator('.skip-link').click();assert.equal(await page.evaluate(()=>document.activeElement.id),'main-content');
 assert.deepEqual(errors,[]);assert.equal(requests.filter(x=>x.method!=='GET'&&x.path!=='/api/gpo/target-access').length,0,'visual navigation must never write policy');
 console.log('PASS appearance bootstrap/focus/Escape/outside click; all routes in both themes at 320/390/768/1440px; mobile labels, short sidebar, keyboard skip and no policy writes.');
 }finally{if(browser)await browser.close();server.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
