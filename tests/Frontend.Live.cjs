// Browser smoke test against the real backend in isolated, configuration-only mode.
const {chromium}=require('playwright');
const {spawn}=require('node:child_process');
const net=require('node:net'),path=require('node:path'),fs=require('node:fs'),assert=require('node:assert/strict');
(async()=>{
  const root=path.resolve(__dirname,'..'),probe=net.createServer();
  await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
  const dir=fs.mkdtempSync(path.join(root,'work','ui-live-'));
  const exe=path.join(root,'runtime','GpoRemediator.exe');
  const service=spawn(exe,['--contentRoot',path.join(root,'backend'),'--LocalSetup','true','--Mode','Setup','--urls',`http://127.0.0.1:${port}`,'--DatabasePath',path.join(dir,'setup.db')],{cwd:path.join(root,'backend'),windowsHide:true,stdio:'ignore'});
  let browser;
  try{
    const origin=`http://127.0.0.1:${port}`;
    let ready=false;
    for(let i=0;i<80;i++){try{const s=await fetch(origin+'/api/session',{signal:AbortSignal.timeout(500)});if(s.ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,250));}
    assert.ok(ready,'Real backend did not start');
    browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||'msedge',headless:true});
    const page=await browser.newPage({viewport:{width:1440,height:950}}),errors=[],bad=[];
    page.on('pageerror',e=>errors.push(e.message));page.on('response',r=>{if(r.status()>=400)bad.push(r.url());});
    await page.goto(origin+'/#/');await page.locator('#gr-auto-panel.open').waitFor();
    await page.waitForFunction(()=>document.querySelector('#windows-setup [name="domain"]')&&!document.querySelector('#windows-setup [name="domain"]').disabled);
    await page.locator('[data-close]').click();await page.waitForFunction(()=>document.querySelector('.product-main')?.getAttribute('aria-busy')==='false');
    assert.equal(await page.locator('.sidebar nav a,.sidebar nav button').count(),4);
    await page.locator('[data-gpo-nav][href="#/benchmark"]').click();await page.locator('#catalog-search').fill('1.1.3');await page.locator('[data-rule="1.1.3"]').click();
    for(const tab of ['overview','impact','verification','audit','remediation'])await page.locator(`[data-tab="${tab}"]`).click();
    await page.locator('[data-gpo-nav][href="#/dashboard"]').click();
    await page.screenshot({path:path.join(root,'work','frontend-live-setup.png'),fullPage:true});
    assert.deepEqual(errors,[]);assert.deepEqual(bad,[]);
    const response=await fetch(origin+'/workspace.js');assert.equal(response.headers.get('cache-control'),'no-store');
    console.log('PASS: real packaged backend + browser, setup, catalog, control tabs, routes, four navigation items, no API failures, no cached UI.');
  }finally{if(browser)await browser.close();service.kill();}
})().catch(e=>{console.error(e);process.exitCode=1;});
