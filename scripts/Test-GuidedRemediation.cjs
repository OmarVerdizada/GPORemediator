// Guides must remain usable offline and must never turn instructions into execution.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),cp=require('node:child_process');
const root=path.resolve(__dirname,'..'),window={};vm.runInNewContext(fs.readFileSync(path.join(root,'frontend/source/remediation-guides.js'),'utf8'),{window});
const guides=window.GpoRemediationGuides,ids=['1.2.3','2.3.11.6','18.10.43.10.1','18.10.43.10.2'];
assert.deepEqual(Array.from(guides.ids),ids);assert.equal(guides.get('__proto__'),null);assert.equal(guides.get('1.1.1'),null);
const esc=v=>String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
const mapping=JSON.parse(fs.readFileSync(path.join(root,'backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const commands=[];
for(const id of ids){
 const guide=guides.get(id),m=mapping.find(x=>x.id===id);assert.notEqual(m.automation,'Automated');
 for(const lang of ['az','en']){
  const html=guides.render(id,{state:{lang},esc,say:(az,en)=>lang==='az'?az:en});
  assert.ok(html.includes(`data-remediation-guide="${id}"`));assert.ok(!/<form|<script|data-verify=|data-enable-write|data-confirm-run|<[^>]*\son\w+=/.test(html));
  assert.ok(html.includes('data-guide-command="read"'));assert.ok(html.includes('data-guide-command="apply"'));
  assert.ok(html.includes(lang==='az'?'avtomatik Apply bağlıdır':'automatic Apply remains blocked'));
  assert.ok(html.includes('rel="noopener noreferrer"'));
 }
 for(const key of ['read','apply','restore'])if(guide[key])commands.push({id,key,text:guide[key]});
 if(guide.restore){assert.ok(guide.apply.includes('ConvertTo-Json'));assert.ok(guide.apply.indexOf('ConvertTo-Json')<guide.apply.indexOf('Set-MpPreference -'));
  for(const token of ['Unsupported Defender parameter','Tamper Protection','DomainRole','Previous value is unknown'])assert.ok(guide.apply.includes(token));
  for(const token of ['Backup does not match','Current value changed','Previous -isnot [bool]'])assert.ok(guide.restore.includes(token));
 }
}
assert.equal(mapping.find(x=>x.id==='1.2.3').recommended,'Enabled.');assert.equal(mapping.find(x=>x.id==='1.2.3').domainPolicySensitive,false);
const force=mapping.find(x=>x.id==='2.3.11.6');assert.equal(force.handler,'SecurityTemplate');assert.equal(force.items[0].key,'ForceLogoffWhenHourExpire');
// Parse the exact published PowerShell snippets as data; never run their contents.
if(process.platform==='win32'){
 const input=path.join(root,'work','guided-command-syntax.json');fs.mkdirSync(path.dirname(input),{recursive:true});fs.writeFileSync(input,JSON.stringify(commands));
 const script=`$ErrorActionPreference='Stop'; $commands=Get-Content -LiteralPath '${input.replaceAll("'","''")}' -Raw | ConvertFrom-Json; foreach($entry in $commands){$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseInput($entry.text,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($entry.id+':'+$entry.key+':'+($errors.Message -join '; '))}}; Write-Output 'PowerShell guide syntax: PASS'`;
 const result=cp.spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8'});assert.equal(result.status,0,result.stdout+result.stderr);process.stdout.write(result.stdout);
}
console.log('Guided remediation: PASS (four blocked controls, AZ/EN guides, backup-before-write, endpoint/drift/type guards, official links and corrected mapping).');
