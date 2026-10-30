/* Actual generated commands are parsed by Windows PowerShell 5.1, never run. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),cp=require('node:child_process');
const root=path.resolve(__dirname,'..');global.window={};
eval(fs.readFileSync(path.join(root,'frontend/source/components.js'),'utf8'));
eval(fs.readFileSync(path.join(root,'frontend/source/manual-engine.js'),'utf8'));
const settings=JSON.parse(fs.readFileSync(path.join(root,'backend/data/gpo-production-mappings.json'),'utf8')).mappings;
const dir=path.join(root,'work/audit');fs.mkdirSync(dir,{recursive:true});
const commands=settings.map(m=>({id:m.id,command:window.GpoComponents.manualCheck({settings},{plan:{selection:{setting:m.id,verificationUser:"EXAMPLE\\User'Name"}}},{hostname:'ws.example.test'})}));
for(const row of commands){assert(row.command.includes('ws.example.test'));assert(!row.command.includes('gpupdate'));assert(row.command.startsWith('& {'));assert(!row.command.includes('Write-Warning'));}
for(const hostname of ['<user-session>','<scope>',''])assert.equal(window.GpoComponents.manualCheck({settings},{plan:{selection:{setting:'19.7.5.2'}}},{hostname}),'','Placeholder hosts must never become executable commands');
assert(window.GpoComponents.manualCheck({settings},{plan:{selection:{setting:'19.7.5.2'}}},null).includes('HKEY_CURRENT_USER'),'Generic standalone manual procedures must remain available without a recorded endpoint');
const userCheck=window.GpoComponents.manualCheck({settings},{plan:{selection:{setting:'19.7.5.2'}}},{hostname:'ws.example.test'});
assert(userCheck.includes('HKEY_CURRENT_USER'));assert(userCheck.includes('Run in the intended user session'));assert(!userCheck.includes('Administrator'));
assert(commands.find(x=>x.id==='19.5.1.1').command.includes('HKEY_USERS'));
assert(commands.find(x=>x.id==='19.5.1.1').command.includes("User''Name"));
assert(commands.find(x=>x.id==='9.1.5').command.includes('-PolicyStore ActiveStore'));
assert(commands.find(x=>x.id==='2.2.16').command.includes('UserRightsV1]::Read'));
assert(commands.find(x=>x.id==='2.2.16').command.includes('SeCreateGlobalPrivilege'));
assert(commands.find(x=>x.id==='9.1.5').command.includes('Format-List Name, LogMaxSizeKilobytes'));
assert(!commands.find(x=>x.id==='9.1.5').command.includes('LogBlocked'));
assert(commands.find(x=>x.id==='9.1.6').command.includes('Format-List Name, LogBlocked'));
assert(commands.find(x=>x.id==='9.1.7').command.includes('Format-List Name, LogAllowed'));
assert(commands.find(x=>x.id==='9.2.4').command.includes("-Name 'Private'"));
for(const [id,rid] of [['2.3.1.2','501'],['2.3.1.4','500'],['2.3.1.5','501']]){const command=commands.find(x=>x.id===id).command;assert(command.includes('Get-LocalUser -ErrorAction Stop'));assert(command.includes(`-${rid}$`));assert(!command.includes('secedit.exe'));}
const auditCommand=commands.find(x=>x.id==='17.2.1').command;
assert.match(auditCommand,/auditpol\.exe \/get \/subcategory:"\{[a-f0-9-]+\}"/i);
assert(!auditCommand.includes(' /r'));
assert(auditCommand.includes('SCENoApplyLegacyAuditPolicy'));
assert.equal((fs.readFileSync(path.join(root,'frontend/source/product.js'),'utf8').match(/function disconnectedControl\(/g)||[]).length,1,'Dead duplicate control implementation returned');
const json=path.join(dir,'manual-commands.json'),ps=path.join(dir,'parse-manual.ps1');fs.writeFileSync(json,JSON.stringify(commands));
fs.writeFileSync(ps,`$ErrorActionPreference='Stop'\n$rows=Get-Content -LiteralPath '${json.replaceAll("'","''")}' -Raw|ConvertFrom-Json\nforeach($row in $rows){$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($row.command,[ref]$tokens,[ref]$errors);if($errors.Count){throw ($row.id+': '+($errors|Out-String))}}\nWrite-Output 'PASS 405 generated PowerShell commands parsed without execution'\n`);
const result=cp.spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',ps],{encoding:'utf8'});process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');assert.equal(result.status,0);
// Execute the actual generated security-policy check with a native-command
// double. The wrong-host branch must never reach the probe, even when pasted.
const guardTest=path.join(dir,'manual-host-guard.ps1');
fs.writeFileSync(guardTest,`$ErrorActionPreference='Stop'
$rows=Get-Content -LiteralPath '${json.replaceAll("'","''")}' -Raw|ConvertFrom-Json
$command=[scriptblock]::Create(($rows|Where-Object id -eq '1.1.4').command)
$script:probeCount=0
function secedit.exe {
  $script:probeCount++
  $file=$args[[array]::IndexOf($args,'/cfg')+1]
  [IO.File]::WriteAllText($file,"[System Access]\\nMinimumPasswordLength = 14".Replace('\\n',"\u0060n"))
  $global:LASTEXITCODE=0
}
$original=$env:COMPUTERNAME
try {
  $env:COMPUTERNAME='different-host'
  try { & $command; throw 'Wrong-host guard accepted a different computer' }
  catch { if($_.Exception.Message -notlike 'Wrong computer.*No policy value was read.') { throw } }
  if($script:probeCount -ne 0){throw 'Probe executed on wrong computer'}
  $env:COMPUTERNAME='WS'
  $value=& $command
  if($script:probeCount -ne 1 -or [string]$value -notmatch 'MinimumPasswordLength = 14'){throw 'Expected endpoint probe failed'}
  'PASS manual check stops before reading the wrong host and reads the expected host'
  function Get-LocalUser {
    param($ErrorAction)
    [pscustomobject]@{Name='renamed-guest';SID='S-1-5-21-100-200-300-501';Enabled=$false;PrincipalSource='Local'}
  }
  $guestCommand=[scriptblock]::Create(($rows|Where-Object id -eq '2.3.1.2').command)
  $guest=& $guestCommand
  if($guest.Name -ne 'renamed-guest' -or $guest.Enabled -ne $false -or $guest.EnableGuestAccount -ne 0 -or $script:probeCount -ne 1){throw 'Generated Guest check did not use live renamed account state'}
  'PASS generated Guest check reads renamed RID 501 status without secedit or an INF'
} finally { $env:COMPUTERNAME=$original }
`);
const guard=cp.spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',guardTest],{encoding:'utf8'});process.stdout.write(guard.stdout||'');process.stderr.write(guard.stderr||'');assert.equal(guard.status,0);
