/* Actual generated commands are parsed by Windows PowerShell 5.1, never run. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),cp=require('node:child_process');
const root=path.resolve(__dirname,'..');global.window={};
eval(fs.readFileSync(path.join(root,'frontend/source/components.js'),'utf8'));
const settings=JSON.parse(fs.readFileSync(path.join(root,'backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const dir=path.join(root,'work/audit');fs.mkdirSync(dir,{recursive:true});
const commands=settings.map(m=>({id:m.id,command:window.GpoComponents.manualCheck({settings},{plan:{selection:{setting:m.id,verificationUser:"EXAMPLE\\User'Name"}}},{hostname:'ws.example.test'})}));
for(const row of commands){assert(row.command.includes('ws.example.test'));assert(!row.command.includes('gpupdate'));}
assert(commands.find(x=>x.id==='19.5.1.1').command.includes('HKEY_USERS'));
assert(commands.find(x=>x.id==='19.5.1.1').command.includes("User''Name"));
assert(commands.find(x=>x.id==='9.1.5').command.includes('-PolicyStore ActiveStore'));
assert.equal((fs.readFileSync(path.join(root,'frontend/source/product.js'),'utf8').match(/function disconnectedControl\(/g)||[]).length,1,'Dead duplicate control implementation returned');
const json=path.join(dir,'manual-commands.json'),ps=path.join(dir,'parse-manual.ps1');fs.writeFileSync(json,JSON.stringify(commands));
fs.writeFileSync(ps,`$ErrorActionPreference='Stop'\n$rows=Get-Content -LiteralPath '${json.replaceAll("'","''")}' -Raw|ConvertFrom-Json\nforeach($row in $rows){$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($row.command,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($row.id+': '+($errors|Out-String))}}\nWrite-Output 'PASS 405 generated PowerShell commands parsed without execution'\n`);
const result=cp.spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',ps],{encoding:'utf8'});process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');assert.equal(result.status,0);
