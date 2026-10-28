/* Static regression contract for the small, fast, truthful production UI.
   Run after patch, without starting AD/DC/WinRM or modifying policies. */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../frontend');
const read=(folder,file)=>fs.readFileSync(path.join(root,folder,file),'utf8');
const workspace=read('source','workspace.js');
const control=read('source','control-view.js');
const catalog=read('source','catalog-view.js');
const batch=read('source','workflow-center.js');
const index=read('source','index.html');
assert.equal((control.match(/function targetForm\(r\)\{/g)||[]).length,1,'Duplicate targetForm regression');
assert.equal((workspace.match(/function dashboardView\(\)\{/g)||[]).length,1,'Duplicate dashboardView regression');
for(const marker of ['ux-status-bar','ux-kpi-grid','ux-recent','ux-advanced-block','GpoRemediationGuides.dashboard','environmentHealth()','GpoPremium.heatmap'])
  assert.ok(workspace.includes(marker),'Dashboard lost '+marker);
for(const marker of ['ux-overview-layout','ux-more-tabs','data-control-start','function impactTab','function auditTab','GpoScopePicker.field'])
  assert.ok(control.includes(marker),'Control flow lost '+marker);
for(const marker of ['ux-catalog-strip','CIS sections are not AD domains','${state.favorites.size}'])
  assert.ok(catalog.includes(marker),'Catalog lost '+marker);
assert.ok(batch.includes('visibleControls=controls.slice(0,80)'),'Batch list must render no more than 80 controls initially');
assert.ok(batch.includes('noncomputer')||batch.includes('Scope')||batch.includes('mapping?.scope'),'Batch safety flow unexpectedly missing');
for(const file of ['workspace.js','control-view.js','product.js','catalog-view.js','workflow-center.js','index.html','ux-pro.css'])
  assert.equal(read('source',file),read('dist',file),'Frontend/dist stale: '+file);
for(const marker of ['/ux-pro.css?v=3.16.7','/gpo-scope-picker.js','/workspace.js?v='+(/buildLabel:'([^']+)'/.exec(workspace)||[])[1]])
  assert.ok(index.includes(marker),'Missing frontend asset '+marker);
assert.ok(!read('source','ux-pro.css').includes('!important'),'No !important allowed in UX overrides');
console.log('PASS professional UX regression: single control form, compact dashboard, 80-row batch, dist sync, retained policy analysis');
