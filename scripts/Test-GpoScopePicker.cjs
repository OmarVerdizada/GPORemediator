/* Run using node scripts/Test-GpoScopePicker.cjs: no browser, AD, or network needed. */
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const code=fs.readFileSync(path.resolve(__dirname,'../frontend/source/gpo-scope-picker.js'),'utf8');
const ctx={window:{}};vm.runInNewContext(code,ctx);
const p=ctx.window.GpoScopePicker;
const dir=[{kind:'Domain',dn:'DC=prosol,DC=local',name:'prosol.local'},
 {kind:'OU',dn:'OU=Office,DC=prosol,DC=local',name:'Office'},
 {kind:'OU',dn:'OU=Users,OU=Office,DC=prosol,DC=local',name:'Users'},
 {kind:'OU',dn:'OU=Servers,DC=prosol,DC=local',name:'Servers'},
 {kind:'OU',dn:'OU=Sales\\,East,OU=Office,DC=prosol,DC=local',name:'Sales,East'}];
assert.deepEqual([...p.splitDn('OU=Sales\\,East,OU=Office,DC=prosol,DC=local')],['OU=Sales\\,East','OU=Office','DC=prosol','DC=local']);
assert.equal(p.parentDn(dir[2].dn),dir[1].dn);
assert.equal(p.approved(dir,'OU').length,4);
assert.equal(p.approved(dir,'Domain').length,1);
const expanded=new Set([dir[0].dn.toLowerCase(),dir[1].dn.toLowerCase()]);
const list=p.model(dir,'OU','',expanded);
assert.equal(list.total,4);assert.equal(list.rows.length,5);
assert.equal(p.model(dir,'OU','Servers',new Set()).matches,1);
const a=p.field(dir,dir[2].dn,'scopeDn','OU','az');
assert.ok(a.includes('data-scope-open="scopeDn"'));assert.ok(a.includes('name="scopeDn"'));
assert.ok(!a.includes('type="text"'));assert.ok(a.includes('OU=Users'));
const ui=p.modal(dir,'scopeDn','',expanded,{scopeDn:dir[2].dn},'az');
assert.ok(ui.includes('data-scope-choose="OU=Users,OU=Office,DC=prosol,DC=local"'));
assert.ok(!ui.includes('data-scope-choose="DC=prosol,DC=local"'));
const domain=p.modal(dir,'scopeDn','',new Set(),{scopeDn:dir[0].dn},'az',true);
assert.ok(domain.includes('data-scope-choose="DC=prosol,DC=local"'));
assert.ok(!domain.includes('data-scope-choose="OU=Users'));
assert.ok(domain.includes('Only the domain is shown'));
assert.ok(!domain.includes('This tree contains only discovered AD OUs'));
const all=p.modal(dir,'scopeDn','',expanded,{scopeDn:dir[0].dn},'az',true,true);
assert.ok(all.includes('data-scope-choose="DC=prosol,DC=local"'));assert.ok(all.includes('OU=Users'));assert.ok(!all.includes('data-scope-choose="OU=Users'));assert.ok(all.includes('can select only the domain root'));
const unsafe=p.field([{kind:'OU',dn:'OU=<script>,DC=local',name:'<img src=x onerror=1>'}],'OU=<script>,DC=local','scopeDn','OU','az');
assert.ok(unsafe.includes('&lt;img'));assert.ok(!unsafe.includes('<img'));
console.log('PASS visual OU scope catalog: AD inventory, filtering, DN escaping, parent tree, selection, and HTML encoding');
