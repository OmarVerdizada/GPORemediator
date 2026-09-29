const fs=require('node:fs');const path=require('node:path');const assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../frontend');const src=fs.readFileSync(path.join(root,'source/workspace.js'),'utf8');const dist=fs.readFileSync(path.join(root,'dist/workspace.js'),'utf8');
assert.equal(src,dist,'workspace source/dist mismatch');
for(const marker of ["data-replan","data-gpupdate","/replan","/gpo/session","statusText","assurance-grid","data-op-evidence"]){assert.ok(src.includes(marker),`missing UI marker: ${marker}`)}
const exec=fs.readFileSync(path.resolve(__dirname,'../backend/Infrastructure/WindowsPowerShellExecutor.cs'),'utf8');assert.ok(exec.includes('"gpoRefresh"'),'gpoRefresh is not allowlisted');
const service=fs.readFileSync(path.resolve(__dirname,'../backend/Services/GpoWorkflowService.cs'),'utf8');assert.ok(service.includes('ReplanAsync'),'fresh remediation replan endpoint missing');
console.log('PASS: dependency-free frontend/backend workflow smoke checks.');
