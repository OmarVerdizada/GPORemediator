// Run with Node and Playwright installed. All AD responses are isolated fixtures;
// this suite never connects to a domain or changes a real GPO.
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../frontend/dist');
const mappings = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../backend/data/gpo-production-mappings.json'))).mappings;
for(const mapping of mappings)mapping.operationalImpact=mapping.domainPolicySensitive?'HIGH':mapping.requiresRestart?'HIGH':mapping.requiresGpUpdate?'MEDIUM':'LOW';
const inventory = { domain:'example.test',domainController:'dc.example.test',executionUser:'TEST\\operator',gpos:[{id:'gpo-1',name:'Test policy',protected:false,selectable:true}],scopes:[{dn:'DC=example,DC=test',name:'Domain',kind:'Domain'}] };
let writesEnabled=false,processId=100,connectCount=0,previewCount=0,writeGateRestarts=0;
let mode='WINDOWS',connected=false,connectionExpired=false,readinessFails=false,hangConnect=false,catalogFails=false,history=[],plan,requests=[],previewBody,loginBody,setupBody,writeModeBody;
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://localhost').pathname;
  const reply=(data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(data));};
  if(url.startsWith('/api/')){
    requests.push(url);
    let raw='';for await(const chunk of req)raw+=chunk;
    const body=raw?JSON.parse(raw):null;
    if(url==='/api/session')return reply({mode,role:'Administrator',operator:'TEST\\operator',csrfToken:'fixture-'+processId,setupRequired:false});
    if(url==='/api/service')return reply({mode,writesEnabled:mode==='WINDOWS'&&writesEnabled,managed:true,processId});
    if(url==='/api/setup/config'&&body){setupBody=body;return reply({saved:true,restartScheduled:false});}
    if(url==='/api/setup/config')return reply({exists:true,domain:'example.test',domainController:'dc.example.test',allowedOperators:['TEST\\operator'],backupPath:'C:\\Backups'});
    if(url==='/api/setup/write-mode'&&body){writeModeBody=body;if(body.enable){writesEnabled=true;connected=false;processId++;writeGateRestarts++;}return reply({saved:true,restartScheduled:body.autoRestart});}
    if(url==='/api/setup/discover')return reply({domain:'example.test',operator:'TEST\\operator'});
    if(mode==='SETUP')return reply({code:'WINDOWS_MODE_REQUIRED',message:'Setup only'},409);
    if(url==='/api/gpo/settings')return reply(mappings);
    if(url==='/api/gpo/history')return reply(history);
    if(url==='/api/audit')return reply({integrityValid:true,pageSize:500,events:[{id:1,event:'GPO_EXECUTION_RESULT',operator:'TEST\\operator',jobId:'plan-1',controlId:'1.1.3',gpoId:'gpo-1',details:'{}',createdAt:new Date().toISOString(),previousHash:'GENESIS',hash:'abcdef0123456789abcdef0123456789'}]});
    if(url==='/api/gpo/connect'){loginBody=body;connectCount++;if(hangConnect)return;connected=true;return reply(inventory);}
    if(url==='/api/gpo/inventory')return connected&&!connectionExpired?reply(inventory):reply({code:'GPO_LOGIN_REQUIRED',message:'Connect again'},409);
    if(url==='/api/gpo/session')return connected&&!connectionExpired?reply({connected:true,executionUser:inventory.executionUser,expiresAt:new Date(Date.now()+30*60000).toISOString(),idleTimeoutMinutes:30}):reply({code:'GPO_LOGIN_REQUIRED',message:'Connect again'},409);
    if(url==='/api/gpo/readiness')return connectionExpired?reply({code:'GPO_LOGIN_REQUIRED',message:'Connect again'},409):readinessFails?reply({code:'WINDOWS_TIMEOUT',message:'Readiness timeout'},409):reply({ready:true,checks:[{id:'session',label:'Kerberos / WinRM session',state:'PASS',message:'Authenticated remote session'},{id:'backup',label:'Backup repository',state:'PASS',message:'Backup directory is writable'}]});
    if(url==='/api/gpo/plan-1/evidence')return reply({operationId:plan.id,integrityHash:'fixture-hash'});
    if(url==='/api/gpo/preview'){
      previewBody=body;previewCount++;
      plan={id:'plan-1',selection:body,executionUser:inventory.executionUser,preview:{gpo:inventory.gpos[0],scope:inventory.scopes[0],previousValue:'0',desiredValue:String(body.value),warnings:[],refreshComputers:[]}};
      return reply(plan);
    }
    if(url==='/api/gpo/plan-1/replan'){plan={...plan,id:'plan-2'};return reply(plan);}
    if(/^\/api\/gpo\/plan-1\/(apply|verify|rollback|refresh)$/.test(url)){
      assert.equal(req.headers['x-csrf-token'],'fixture-'+processId);
      if(url.endsWith('/apply')){assert.equal(body.confirmation,'APPLY');assert.equal(body.changeReference,'CHG-1');}
      const result={state:url.endsWith('/rollback')?'ROLLED_BACK':url.endsWith('/verify')?'VERIFIED':url.endsWith('/refresh')?'REFRESH_SCHEDULED':'PUBLISHED',message:'Fixture operation completed',gpoPublished:true,linkVerified:true,backupId:'backup-1',refreshResults:[],effectiveStatus:'VERIFIED_ON_SAMPLE',verification:{replicationConverged:true,replicationWarnings:[]},endpointChecks:[{hostname:'server01.example.com',state:'VERIFIED'}]};
      history=[{id:plan.id,plan,result}];return reply(history[0]);
    }
    return reply({code:'NOT_FOUND',message:'Unexpected test API: '+url},404);
  }
  if(url==='/benchmark-v4.json'&&catalogFails)return reply({message:'Unavailable'},503);
  const file=path.join(root,url==='/'?'index.html':url);
  if(!file.startsWith(root+path.sep)||!fs.existsSync(file)){res.writeHead(404);return res.end();}
  const ext=path.extname(file);res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json'})[ext]||'application/octet-stream');res.end(fs.readFileSync(file));
});
(async()=>{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||'msedge',headless:true});
  try{
    const context=await browser.newContext({viewport:{width:1600,height:900}});
    const page=await context.newPage();const errors=[];page.on('pageerror',e=>{errors.push(e.message);console.error('Browser page error:',e.message);});
    await page.addInitScript(()=>{localStorage.setItem('gr-favorites','broken json');localStorage.setItem('gr-lang','en');});
    const origin=`http://127.0.0.1:${server.address().port}`;
    const idle=()=>page.waitForFunction(()=>document.querySelector('#operator-modules .product-main')?.getAttribute('aria-busy')==='false');
    await page.goto(origin+'/#/');await idle();assert.equal(new URL(page.url()).hash,'#/dashboard');
    assert.equal(await page.locator('.sidebar nav a,.sidebar nav button').count(),5);
    assert.equal(await page.locator('script[src*="/assets/"]').count(),0);
    await page.locator('[data-gpo-nav][href="#/operations"]').click();await page.locator('.empty-state').waitFor();await page.waitForTimeout(450);assert.equal(await page.locator('.empty-state').count(),1);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    await page.screenshot({path:path.resolve(__dirname,'../work/frontend-operations-empty.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);await page.screenshot({path:path.resolve(__dirname,'../work/frontend-operations-mobile.png'),fullPage:true});await page.setViewportSize({width:1600,height:900});
    await page.locator('[data-gpo-nav][href="#/benchmark"]').click();
    await page.locator('#catalog-search').pressSequentially('1.1.3');assert.equal(await page.locator('#catalog-search').inputValue(),'1.1.3');
    await page.waitForFunction(()=>document.activeElement?.id==='catalog-search');
    await page.locator('[data-rule="1.1.3"]').click();
    for(const tab of ['impact','verification','audit','remediation','overview'])await page.locator(`[data-tab="${tab}"]`).click();
    await page.locator('[data-tab="remediation"]').click();
    hangConnect=true;await page.locator('#gpo-login [name="userName"]').fill('TEST/operator');await page.locator('#gpo-login [name="password"]').fill('fixture-only');
    await page.locator('#gpo-login button').click();await page.locator('[data-cancel-request]:not([hidden])').waitFor();await page.locator('[data-cancel-request]').click();await idle();
    assert.match(await page.locator('.inline-notice').innerText(),/Stopped waiting/);
    hangConnect=false;readinessFails=true;
    await page.locator('#gpo-login [name="userName"]').fill('TEST/operator');await page.locator('#gpo-login [name="password"]').fill('fixture-only');
    await page.locator('#gpo-login button').click();await idle();
    assert.match(await page.locator('.inline-notice').innerText(),/Readiness timeout/);assert.equal(loginBody.userName,'TEST\\operator');
    readinessFails=false;connectionExpired=true;await page.locator('[data-settings-nav]').click();
    const readinessButton=page.locator('[data-readiness]');
    if(await readinessButton.count())await readinessButton.click();
    await page.locator('[data-reconnect]').waitFor();
    assert.equal(await page.locator('.gr-auto-row').count(),0);await page.locator('[data-reconnect]').click();await idle();assert.equal(await page.locator('#gpo-login').count(),1);
    connectionExpired=false;await page.locator('#gpo-login [name="userName"]').fill('TEST/operator');await page.locator('#gpo-login [name="password"]').fill('fixture-only');await page.locator('#gpo-login button').click();await idle();
    await page.locator('[data-gpo-nav][href="#/benchmark"]').click();await page.locator('[data-rule="1.1.3"]').click();await page.locator('[data-tab="remediation"]').click();await page.waitForTimeout(450);await page.screenshot({path:path.resolve(__dirname,'../work/frontend-target.png'),fullPage:true});await page.locator('[data-gpo-toggle]').click();await page.locator('[data-gpo="gpo-1"]').click();
    await page.locator('[name="value"]').fill('2');await page.locator('[name="value"]').press('Tab');
    assert.equal(await page.locator('[name="value"]').inputValue(),'2');
    await page.locator('#gpo-selection .primary-action').click();await idle();assert.equal(previewBody.value,2);
    const beforeConnect=connectCount,beforePreview=previewCount;
    await page.locator('[data-enable-write]').click();await idle();
    assert.equal(writeGateRestarts,1,'Write authorization must restart exactly once');
    assert.equal(connectCount,beforeConnect+1,'Credential must reconnect once from tab memory');
    assert.equal(previewCount,beforePreview+1,'Restart must generate a fresh final preview');
    assert.equal(await page.locator('#gpo-apply').count(),0,'New preview must require renewed review');
    assert.equal(await page.evaluate(()=>[...Object.values(sessionStorage),...Object.values(localStorage)].some(x=>x.includes('fixture-only'))),false,'Password persisted in browser storage');
    await page.locator('#approval-ref').fill('CHG-1');await page.locator('#approval-by').fill('Reviewer');await page.locator('#approval-ok').check();
    await page.locator('#gpo-apply [name="impact"]').check();await page.locator('#gpo-apply [name="confirmation"]').fill('APPLY');await page.locator('#gpo-apply button').click();await idle();
    const downloadPromise=page.waitForEvent('download');await page.locator('[data-evidence]').click();const download=await downloadPromise;assert.match(download.suggestedFilename(),/gpo-evidence/);await idle();
    await page.locator('[data-gpo-nav][href="#/operations"]').click();await page.locator('[data-ops-filter="SUCCESS"]').click();assert.equal(await page.locator('.op-card').count(),1);
    await page.locator('[data-verify]').click();await idle();
    await page.locator('[data-rollback] input').fill('ROLLBACK');await page.locator('[data-rollback] button').click();await page.locator('[data-confirm-run]').click();await idle();
    await page.locator('[data-ops-filter="ROLLED_BACK"]').click();assert.equal(await page.locator('.op-card').count(),1);
    const fixed=mappings.find(m=>m.automation==='Automated'&&!m.allowValueOverride&&!m.requiresInput&&!m.domainPolicySensitive);
    await page.locator('[data-gpo-nav][href="#/benchmark"]').click();await page.locator('#catalog-search').fill(fixed.id);await page.locator(`[data-rule="${fixed.id}"]`).click();await page.locator('[data-tab="remediation"]').click();
    await page.locator('[data-gpo-toggle]').click();await page.locator('[data-gpo="gpo-1"]').click();await page.locator('#gpo-selection .primary-action').click();await idle();assert.equal(previewBody.value,0);
    await page.locator('[data-gpo-nav][href="#/benchmark"]').click();await page.locator('#catalog-search').fill('1.2.3');await page.locator('[data-rule="1.2.3"]').click();await page.locator('[data-tab="remediation"]').click();assert.equal(await page.locator('#gpo-selection .primary-action').isDisabled(),true);
    await page.locator('[data-gpo-nav][href="#/audit"]').click();await page.locator('.audit-event-row').waitFor();assert.equal(await page.locator('.integrity-card.ok').count(),1);await page.locator('#audit-search').fill('GPO_EXECUTION_RESULT');assert.equal(await page.locator('.audit-event-row').count(),1);
    // A delayed transport is exercised separately, without touching real AD.
    hangConnect=true;
    const timeoutMessage=await page.evaluate(async()=>{try{await GpoClient.request('/api/gpo/connect',{body:{},timeout:20});return '';}catch(e){return e.message;}});
    assert.match(timeoutMessage,/timed out/);hangConnect=false;
    mode='SETUP';requests=[];await page.reload();await idle();assert.equal(requests.some(p=>p.startsWith('/api/gpo/')),false);
    await page.locator('#windows-setup [name="domain"]').waitFor();
    await page.waitForFunction(()=>!document.querySelector('#windows-setup [name="domain"]').disabled);await page.waitForTimeout(500);
    await page.screenshot({path:path.resolve(__dirname,'../work/frontend-settings.png'),fullPage:true});
    await page.locator('#windows-setup button.primary').click();await page.waitForFunction(()=>!document.querySelector('#windows-setup [name="domain"]').disabled);assert.deepEqual(setupBody.allowedOperators,['TEST\\operator']);assert.deepEqual(setupBody.approvedGpoIds,['*']);assert.deepEqual(setupBody.authorizedOus,['DC=example,DC=test']);
    await page.locator('[data-close]').click();await idle();
    catalogFails=true;await page.reload();await page.locator('[data-close]').click();await page.locator('[data-refresh]').waitFor();
    await page.waitForFunction(()=>!document.querySelector('[data-refresh]')?.disabled);catalogFails=false;await page.locator('[data-refresh]').click();await idle();
    mode='WINDOWS';connected=true;readinessFails=false;await page.goto(origin+'/#/dashboard');await page.reload();await idle();await page.locator('[data-readiness]').first().click();await idle();await page.locator('[data-lang]').click();await page.locator('[data-settings]').click();await page.locator('.gr-auto-permission').waitFor();await page.waitForTimeout(500);await page.screenshot({path:path.resolve(__dirname,'../work/frontend-settings-windows.png'),fullPage:true});await page.locator('[data-write]').click();await page.waitForFunction(()=>!document.querySelector('[data-write]')?.disabled);assert.equal(writeModeBody.confirmation,'DISABLE WRITES');await page.locator('[data-close]').click();
    await page.waitForTimeout(250);
    await page.locator('[data-gpo-nav][href="#/dashboard"]').click();await idle();
    await page.screenshot({path:path.resolve(__dirname,'../work/frontend-fixed.png'),fullPage:true});
    await page.locator('[data-theme]').click();
    await page.screenshot({path:path.resolve(__dirname,'../work/frontend-dark.png'),fullPage:true});
    await page.locator('[data-theme]').click();
    await page.locator('[data-gpo-nav][href="#/benchmark"]').click();
    await page.locator('#catalog-search').fill('no-control-matches-this-query');
    await page.locator('.empty-state[role="status"]').waitFor();
    await page.locator('#catalog-search').fill('');
    await page.locator('[data-view="HIGH"]').click();
    await page.waitForTimeout(200);
    const highEn=await page.locator('.ent-domain').count();assert.ok(highEn>0);
    await page.locator('[data-lang]').click();
    assert.equal(await page.locator('.ent-domain').count(),highEn,'High impact filter must not depend on display language');
    await page.locator('[data-view="ALL"]').click();
    await page.screenshot({path:path.resolve(__dirname,'../work/frontend-library.png'),fullPage:true});
    for(const width of [390,768,1366]){
      await page.setViewportSize({width,height:900});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`Library overflow at ${width}px`);
    }
    await page.setViewportSize({width:1600,height:900});
    await page.locator('.skip-link').focus();await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(()=>document.activeElement.id),'main-content');
    assert.equal(new URL(page.url()).hash,'#/benchmark');
    assert.deepEqual(errors,[]);console.log('PASS: standalone shell, setup, legacy routes, corrupt storage, all control tabs, cancel, timeout, readiness failure, preview values, apply, verify, rollback, history filters, catalog retry.');
  }finally{await browser.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;server.closeAllConnections();server.close();});
