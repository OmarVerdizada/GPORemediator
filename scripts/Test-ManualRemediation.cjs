/* Generate every published manual procedure, then test the real scripts offline. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),cp=require('node:child_process');
const repo=path.resolve(__dirname,'..'),window={},sandbox=vm.createContext({window,Date,JSON,String,Number,Boolean});
for(const file of ['components.js','manual-engine.js','manual-remediation.js','ui-domain.js','studio-ui.js','remediation-guides.js','control-view.js'])vm.runInContext(fs.readFileSync(path.join(repo,'frontend/source',file),'utf8'),sandbox);
sandbox.GpoUiDomain=window.GpoUiDomain;
const catalog=JSON.parse(fs.readFileSync(path.join(repo,'frontend/source/benchmark-v4.json'),'utf8'));
const mappings=JSON.parse(fs.readFileSync(path.join(repo,'backend/data/gpo-production-mappings.json'),'utf8')).mappings;
assert.deepEqual(JSON.parse(JSON.stringify(window.GpoManualEngine.mappings)),mappings);
const api=window.GpoManualRemediation,rows=[],gpo='11111111-1111-1111-1111-111111111111';
for(const m of mappings){
 const r=catalog.rules.find(x=>x.id===m.id),selection={setting:m.id,gpoId:m.domainPolicySensitive?'31b2f340-016d-11d2-945f-00c04fb984f9':gpo,scopeDn:m.domainPolicySensitive?'DC=example,DC=test':m.scope==='User'?'OU=Users,DC=example,DC=test':'OU=Endpoints,DC=example,DC=test',value:m.suggested??0,customValue:m.requiresInput?'Policy test value':'',firstLink:false};
 const s={lang:'en',settings:mappings,selection,inventory:{domain:'example.test',domainController:'dc.example.test',gpos:[]}};
 for(const action of m.automation==='Automated'?['Preview','Apply']:['Review']){
  s.manualScriptAction=action;
  const generated=api.generate(s,r,action),html=api.render(s,r);
  assert(generated&&html.includes(`data-manual-procedure="${m.id}"`));
  if(generated.guide)assert(html.includes('data-guide-command="read"')&&html.includes('data-guide-command="apply"'));
  else assert(html.includes('Copy full script')&&html.includes('data-manual-download'));
  assert(!/<form|data-enable-write|data-confirm-run|data-verify=|onclick=|<script/.test(html));
  assert(!generated.script.includes('__GR_')&&!generated.script.includes('REPLACE_WITH_'));
  if(m.automation==='Automated'){
   assert(generated.script.includes(`$Action = '${action}'`));
   assert(generated.script.includes(window.GpoManualEngine.functions));
   assert(generated.script.indexOf('$backup=Backup-GPO')<generated.script.indexOf('$null=Write-Mapping $plan $map'));
   assert(generated.script.includes("Endpoint='NOT_TESTED'"));
  }else assert(!generated.script.includes('Write-Mapping')&&!generated.script.includes('Set-GP'));
  rows.push({id:m.id,action,script:generated.script});
 }
 const offline=api.generate({settings:[],selection:{},lang:'az'},r);
 if(offline.guide){assert.equal(offline.script,window.GpoRemediationGuides.get(r.id).read);assert(!api.render({settings:[],selection:{},lang:'az'},r).includes('REPLACE_WITH_GPO_GUID'));}
 else{assert(offline.script.includes('REPLACE_WITH_DOMAIN'));assert(api.render({settings:[],selection:{},lang:'az'},r).includes('Şablon görünür'));}
}
assert.equal(rows.length,799);
const r=catalog.rules.find(x=>x.id==='2.3.7.4'),evil="'; throw 'INJECTED' #\n</code><img src=x onerror=alert(1)>\n@'";
const state={lang:'en',settings:mappings,selection:{setting:r.id,gpoId:gpo,scopeDn:'OU=Endpoints,DC=example,DC=test',customValue:evil},inventory:{domain:'example.test',domainController:'dc.example.test',gpos:[]}};
const generated=api.generate(state,r,'Apply');
assert(generated.script.includes("$CustomValue = '''; throw ''INJECTED''"));
const html=api.render(state,r);assert(!html.includes('<img src=x'));assert(html.includes('&lt;/code&gt;'));
for(const rule of catalog.rules){
 const state={lang:'en',catalog,selectedRule:rule,settings:[],selection:{},history:[],approval:{reviewed:false},favorites:new Set(),tab:'overview'};
 const esc=window.GpoComponents.esc;
 const view=window.GpoControlView.create({state,esc,say:(az,en)=>en,tr:x=>x,riskFor:()=>({cls:'medium',name:'Medium'}),badges:()=>'',topDomainForRule:()=>null,sectionTitle:()=>'',renderConnection:()=>'',uiIcon:()=>'',stateClass:()=>'',statusText:x=>x});
 assert(view.controlView().includes(`data-manual-procedure="${rule.id}"`),'Actual overview lost the manual panel for '+rule.id);
}
rows.push({id:r.id,action:'Escaping',script:generated.script});
const dir=path.join(repo,'work/audit');fs.mkdirSync(dir,{recursive:true});
const fixture=path.join(dir,'manual-procedures.json');fs.writeFileSync(fixture,JSON.stringify(rows));
// Node can inherit PowerShell 7's module path; a 5.1 child must use Windows
// PowerShell's stock modules (not 7.x's incompatible Utility module).
const psEnv={...process.env,PSModulePath:[path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/Modules'),path.join(process.env.ProgramFiles,'WindowsPowerShell/Modules')].join(';')};
let result=cp.spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(repo,'scripts/Build-ManualEngine.ps1'),'-Check'],{encoding:'utf8',env:psEnv});
process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');assert.equal(result.status,0);
result=cp.spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(repo,'scripts/Test-ManualProcedures.ps1'),'-FixturePath',fixture],{encoding:'utf8',env:psEnv,maxBuffer:5*1024*1024});
process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');assert.equal(result.status,0);
console.log('PASS 405-control manual coverage: 394 standalone writers, 11 read-only reviews; 800 exact scripts parsed, shared-source parity, escaping and offline templates');
