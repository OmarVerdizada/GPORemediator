"""Build an evidence-bounded audit inventory; never infer live AD success from mocks."""
import argparse, collections, csv, hashlib, json, re, subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--evidence',default='work/audit/validated');args=parser.parse_args()
evidence=ROOT/args.evidence;out=ROOT/'docs/audit';out.mkdir(parents=True,exist_ok=True)
def load(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(name,text):(out/name).write_text(text.strip()+'\n',encoding='utf-8')
def csvwrite(name,columns,rows):
 with (out/name).open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=columns);w.writeheader();w.writerows(rows)
maps=load(ROOT/'backend/data/gpo-production-mappings.json')['mappings'];catalog=load(ROOT/'frontend/source/benchmark-v4.json')
assert len(maps)==405 and len({m['id'] for m in maps})==405
assert {m['id'] for m in maps}=={r['id'] for r in catalog['rules']}
tests=load(evidence/'test-results.json');tests=tests if isinstance(tests,list) else [tests]
remediation={x['id']:x for x in load(evidence/'remediation-controls.json')};endpoints={x['id']:x for x in load(evidence/'endpoint-controls.json')}
admx=load(evidence/'admx-review.json');admx_ids=set(admx['matchedControls'])
base=subprocess.check_output(['git','show','b673998:backend/data/gpo-production-mappings.json'],cwd=ROOT,text=True,encoding='utf-8')
before={x['id']:x for x in json.loads(base)['mappings']}
changed=[m['id'] for m in maps if m!=before[m['id']]]
auto=[m for m in maps if m['automation']=='Automated' and m['handler']!='Manual']
blocked=[m['id'] for m in maps if m not in auto]
numeric={m['id'] for m in maps if not m['allowValueOverride'] and (m.get('comparator') in {'>=','<=','atMost'} or any(i.get('comparator') for i in m['items']))}
source=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=ROOT,text=True,encoding='utf-8').splitlines()
source=sorted(set(x for x in source if not x.startswith('docs/audit/') and (ROOT/x).is_file()))
text_extensions={'.cs','.csproj','.ps1','.psm1','.py','.cjs','.js','.json','.yml','.yaml','.html','.css','.md','.txt','.tsv','.cmd','.gitignore'}
inventory=[];routes=[];signatures=[]
for name in source:
 p=ROOT/name;istext=p.suffix.lower() in text_extensions or p.name.startswith('.')
 text=p.read_text(encoding='utf-8-sig',errors='replace') if istext else ''
 category='generated frontend' if name.startswith('frontend/dist/') else 'release package' if name.startswith('release/') else name.split('/')[0] if '/' in name else 'launcher/documentation'
 inventory.append(dict(Path=name,Category=category,Bytes=p.stat().st_size,SHA256=sha(p),Text_Lines=len(text.splitlines()) if istext else '',Inspection='whole-file text inventory and structural scan' if istext else 'binary hash inventory; package integrity test'))
 if name.startswith('backend/') and p.suffix=='.cs':
  for method,route in re.findall(r'\.Map(Get|Post|Put|Delete|Patch)\("([^"\n]+)"',text):routes.append(dict(File=name,Method=method.upper(),Route=route,Note='Dynamic loops expand GPO actions apply/rollback/verify/refresh; compiled frontend assets also create GET routes.'))
 if name.startswith(('backend/','frontend/source/')) and p.suffix in {'.cs','.js','.ps1','.psm1'}:
  for match in re.finditer(r'(?:\bfunction\s+([\w-]+)\s*\(|^\s*(?:public|private|internal|protected)\s+(?:(?:static|async)\s+)*[\w<>,?\[\].]+\s+(\w+)\s*\()',text,re.M):signatures.append(dict(File=name,Symbol=next(x for x in match.groups() if x),Line=text[:match.start()].count('\n')+1))
csvwrite('SOURCE_INVENTORY.csv',list(inventory[0]),inventory)
routes=[r for r in routes if r['Route']!='/api/workflows/']
for action in ['apply','rollback','verify','refresh']:
 routes.append(dict(File='backend/Infrastructure/WorkspaceEndpoints.cs',Method='POST',Route='/api/workflows/'+action,Note='Expanded from production action loop; Verify allows read roles, mutations require Administrator/Remediator; CSRF and server context guards apply.'))
csvwrite('API_INVENTORY.csv',['File','Method','Route','Note'],routes)
csvwrite('SYMBOL_INVENTORY.csv',['File','Symbol','Line'],signatures)
dependencies=[]
for name in source:
 if not name.endswith('.csproj'):continue
 project=ET.parse(ROOT/name).getroot();framework=project.findtext('.//TargetFramework')
 for package in project.findall('.//PackageReference'):
  dependencies.append(dict(Project=name,TargetFramework=framework,Package=package.get('Include'),Version=package.get('Version')))
csvwrite('DEPENDENCY_INVENTORY.csv',['Project','TargetFramework','Package','Version'],dependencies)

# Published logs are normalized for local paths; their own hashes remain verifiable.
published=out/'evidence';published.mkdir(exist_ok=True)
published_tests=[]
for test in tests:
 log=ROOT/test['log'];assert sha(log).upper()==test['logSha256'],test['name']+' evidence changed'
 raw=log.read_text(encoding='utf-8-sig',errors='replace')
 raw=raw.replace(str(ROOT),'<WORKSPACE>').replace(str(ROOT).replace('\\','/'),'<WORKSPACE>')
 raw=re.sub(r'C:\\Users\\[^\\\r\n]+\\Documents\\Codex\\[^\r\n]*?\\work\\dotnet','<SDK>',raw,flags=re.I)
 raw=re.sub(r'C:\\Users\\[^\\\r\n]+\\\.cache\\codex-runtimes\\[^\s\r\n]*','<BUNDLED_RUNTIME>',raw,flags=re.I)
 target=published/(test['name']+'.txt');target.write_text(raw,encoding='utf-8')
 published_tests.append({**test,'log':'evidence/'+target.name,'originalLogSha256':test['logSha256'],'logSha256':sha(target)})
for name in ['remediation-controls.json','endpoint-controls.json','admx-review.json']:(published/name).write_text(json.dumps(load(evidence/name),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
native=ROOT/'work/audit/native-read-probes.json'
if native.exists():(published/'native-read-probes.json').write_text(json.dumps(load(native),indent=2)+'\n',encoding='utf-8')
(published/'test-results.json').write_text(json.dumps(published_tests,indent=2)+'\n',encoding='utf-8')
pass_count=sum(x['status']=='PASS' for x in tests);fail_count=len(tests)-pass_count
endpoint_cases=sum(x.get('cases',0) for x in endpoints.values())

rows=[]
for m in maps:
 cid=m['id'];automatic=m in auto;r=remediation[cid];v=endpoints[cid]
 storage='; '.join((('['+i['section']+'] ') if i.get('section') else '')+(i.get('key') or i.get('guid') or 'manual procedure')+(' :: '+i['name'] if i.get('name') else '') for i in m['items'])
 method='selected DC Get-ADDefaultDomainPasswordPolicy' if m['scope']=='Domain' else 'Get-NetFirewallProfile ActiveStore' if cid.startswith('9.') else 'auditpol /get GUID /r numeric mask' if m['handler']=='AdvancedAudit' else 'secedit /export /mergedpolicy' if m['handler']=='SecurityTemplate' else 'selected SID HKEY_USERS values/types' if m['scope']=='User' else 'endpoint HKLM values/types; runtime prerequisites not proven'
 defects=[]
 if m['handler']=='AdvancedAudit':defects.append('D01 auditpol argument splitting/GUID attribution')
 if cid in numeric:defects.append('D02 numeric equality rejected stronger compliant policy')
 if cid.startswith('9.'):defects.append('D03 policy registry was not resultant active firewall evidence')
 if m['scope']=='User':defects.append('D08 manual HKCU could inspect the operator hive')
 if cid=='19.7.44.2.1':defects.append('D13 imported site chrome in description/recommendation')
 if automatic:defects.extend(['D04 version-only replication evidence','D05 stale evidence export','D09 independent assurance stages missing'])
 rows.append(dict(CIS_ID=cid,Control_Name=m['title'],OS='NOT_ESTABLISHED: imported catalog has no authoritative product/build binding',GPO_Mechanism=m['handler'],Remediation_Checked='SOURCE_AND_SYNTHETIC' if automatic else 'SAFETY_BLOCK_REVIEWED',Remediation_Result=r['state'],Verification_Checked='REAL_VERIFIER_WITH_MOCKED_NATIVE_APIS' if automatic else 'NOT_SUPPORTED',Verification_Result=v['status'],Rollback_Result='SHARED_OFFLINE_SNAPSHOT_TESTS_PASS; PER_CONTROL_LIVE_RESTORE_NOT_TESTED' if automatic else 'NO_AUTOMATIC_WRITE',Tests_Passed=v.get('cases',0)+r.get('testsPassed',0),Tests_Failed=int(r['state']=='FAIL')+int(v['status']=='FAIL'),Root_Cause='; '.join(defects) or 'No individual defect established; applicability/live behavior unverified',Fix='Shared engine fixes; mapping changed' if cid in changed else 'Shared engine/evidence fixes' if automatic else 'Automatic write remains blocked',Final_Status='NOT_SUPPORTED_AUTOMATIC' if not automatic else 'OFFLINE_PASS_LIVE_NOT_TESTED' if r['state']=='PASS' and v['status']=='PASS' else 'OFFLINE_FAILURE',Evidence='evidence/remediation-controls.json; evidence/endpoint-controls.json; evidence/admx-review.json',Benchmark_Version='operator-supplied CIS v4.0.0; exact licensed original unavailable',Expected_Configuration=json.dumps(m['items'],ensure_ascii=False,separators=(',',':')),Policy_Storage=storage,Verification_Method=method,AD_Permissions='GPO edit and SYSVOL write; gPLink write on selected target if linking; read policy/AD; host remoting/scheduling rights separately',ADMX_Address_Check='MATCHED_LOCAL_ADMX' if cid in admx_ids else 'NO_LOCAL_ADMX_MATCH_OR_NON_ADMX_HANDLER',Live_AD_Validation='NOT_TESTED',Runtime_Enforcement='NOT_TESTED'))
for row in rows:
 m=next(x for x in maps if x['id']==row['CIS_ID'])
 row['GPO_Storage_File']=('User/Registry.pol' if m['scope']=='User' else 'Machine/Registry.pol') if m['handler'] in {'Registry','RegistrySet'} else 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf' if m['handler']=='SecurityTemplate' else 'Machine/Microsoft/Windows NT/Audit/audit.csv' if m['handler']=='AdvancedAudit' else 'NOT_AUTOMATIC: guided procedure'
csvwrite('CIS_FULL_CONTROL_AUDIT.csv',list(rows[0]),rows)
affected=[dict(CIS_ID=m['id'],Mapping_Changed=m['id'] in changed,Shared_Engine_Affected=m in auto,Mechanism=m['handler'],Note='Complete affected-control list; no live GPO write implied') for m in maps if m in auto or m['id'] in changed]
csvwrite('AFFECTED_CONTROL_IDS.csv',list(affected[0]),affected)
write('ALL_DEFECTS_AND_FIXES.md',f'''
# Defects and repairs — 2026-10-15

15 defect groups were confirmed and repaired. A shared defect can affect many controls; it is not 15 independently validated production-policy failures. All {len(auto)} automatic controls traverse changed verification/evidence infrastructure. Exact mapping changes: {', '.join(changed)}.

| ID / subsystem | Original behavior / root cause | Corrected behavior | Regression evidence |
|---|---|---|---|
| D01 / all 27 AdvancedAudit controls | PowerShell split `/subcategory:` and the GUID into two native arguments; the verifier also accepted the first CSV row without matching its GUID. | Build one complete argument and require exactly one row for the requested GUID; native failure remains insufficient evidence. | Test-EndpointEvidence; Test-AllEndpointMappings |
| D02 / 18 numeric policies | Fixed recipes used equality, so valid stronger values were rejected or overwritten; a multi-item update recipe could not express an item-specific bound. | Explicit minimum/maximum comparators, an item comparator, and zero/nonzero distinction. CachedLogonsCount uses the declared ceiling 4; existing lower values are retained. Restart requirement recorded. | Test-GpoMappings; Test-ProductionMappings; 18 extra endpoint bound cases |
| D03 / all 23 firewall controls | Registry input could be reported verified without checking resultant firewall configuration. | Query ActiveStore and normalize native profile properties, booleans, inbound action and expanded log paths; failure cannot become VERIFIED. | Test-AllEndpointMappings |
| D04 / replication | Equal version numbers were sufficient for convergence; a truncated 50-DC list could still pass. | Also compare normalized SYSVOL file hashes and computer/user CSE metadata; unreachable/truncated sets remain pending. Legacy version-only evidence cannot be upgraded without a fresh probe. | Test-VerificationLifecycle: 7 replication cases |
| D05 / evidence exports | First export cached under operation ID was returned after later verification or rollback. | Export current recorded run; preserve earlier immutable snapshots under content-addressed keys. | WorkflowRegression before/after rollback export |
| D06 / standalone refresh workflow | A returned FAILED/empty scheduling result could finish the workflow as COMPLETED. | Stop as NEEDS_REVIEW while preserving publication/rollback records. | WorkspaceRegression failed-refresh case |
| D07 / scope membership | Endpoint samples used the preview host list; a moved/disabled user or host could be checked as if still in scope. | Recheck enabled computer OU membership and user SID/OU membership before probing. | Test-EndpointEvidence stale membership; all-control fixtures |
| D08 / manual commands | HKCU command under Administrator could query the wrong identity; security export reused one temp file. | Resolve selected user SID and read HKEY_USERS; unique temp file with exit checking/cleanup; explicit native audit argument and firewall ActiveStore command. | Test-ManualVerification: 405 parsed commands, SID/quoting checks |
| D09 / assurance claims | Mixed GPO/link/replication/sample indicators omitted a separate evidence claim for applicability and client processing. | Five independent stages plus evidence limits and diagnostic candidates in API/UI/HTML reports; RSoP and completion are not inferred. | WorkflowRegression; RecoveryUi five-stage presentation |
| D10 / read-only scan | Stored GPO match was named COMPLIANT; sample result label implied complete implementation verification. | GPO_MATCH and Sample configuration verified; legacy scan rows render with the scoped label. | WorkspaceRegression; Test-RecipeWorkspace |
| D11 / dead UI code | Duplicate disconnectedControl declaration silently shadowed the earlier implementation. | Keep one sign-in implementation. | Test-ManualVerification duplicate guard; recipe UI tests |
| D12 / UX version test | Asset version hardcoded to 3.11.0 caused the existing aggregate validation to stop after 3.11.1. | Compare the actual workspace build label with the loaded asset version. | Test-UX-Contract |
| D13 / 19.7.44.2.1 | Scraped site navigation/footer text polluted the description and recommendation. | Remove the site chrome and regenerate canonical mapping metadata. | Test-ProductionMappings |
| D14 / startup diagnosis | A recorded runtime exit after readiness was categorized UNKNOWN and described as a pre-readiness failure. | Preserve after-ready chronology in a distinct diagnosis category. | Test-VerificationLifecycle: 2 launcher diagnosis cases |
| D15 / isolation regression | PowerShell 5.1 String.Split selected a char-array overload; the source-contract count failed despite two correct calls. | Count escaped literal matches with Regex across Windows PowerShell versions. | domain-gpo-isolation check under Windows PowerShell 5.1 |

No production exception was suppressed and no permission was elevated. The recipe-label assertion changed because the product wording became narrower; the evidence, escaping and latest-record assertions remain enforced.
''')
write('UNVERIFIED_SCENARIOS.md','''
# Unverified and unsupported scenarios

The following are release gates, not passing mock tests:

1. **All 405 controls:** exact target Windows product, edition, build, role and authoritative benchmark applicability. The imported source says only CIS v4.0.0 and includes mixed role references. A complete original benchmark was not supplied/accessed. Local ADMX matches are not OS certification. The original benchmark's full control set therefore cannot be reconciled for omissions; only catalog-to-mapping completeness is established.
2. **All 394 automatic controls:** live apply, actual AD/SYSVOL CSE processing, effective policy, per-control restore, idempotence under GPMC, partial permission denial, crash and recovery in a disposable domain. Live test count is zero.
3. **Applicability:** target RSoP, effective Read/Apply token, nested OU, Enforced/Block Inheritance, WMI filters, site links, winning GPO, loopback and competing local/MDM sources. Direct-link equality is insufficient; the separate applicability stage says so.
4. **Refresh lifecycle:** Invoke-GPUpdate task scheduling is implemented. There is no trusted task-start/completion/exit-code telemetry. Repeated explicit schedules after the GPO lock releases and cross-GPO refreshes on the same host are not deduplicated by endpoint lifecycle. Scheduled remains scheduled; completing a workflow does not claim gpupdate completion.
5. **Runtime enforcement:** Defender tamper protection/engine state, service restart/startup, packet-level firewall behavior, SMB sessions, logon/reboot, hardware-dependent Device Guard and LAPS prerequisite/schema/processing remain separate from configuration evidence. No automatic service restart or credential/permission escalation was introduced.
6. **AD topologies:** live writable/RODC, multiple DC replication including same-version divergent bytes, DNS/WinRM/Kerberos timeout and double-hop access, trust and cross-domain behavior have not been demonstrated. The product pins one configured domain/DC at a time; simultaneous multi-domain and GPO creation are not implemented.
7. **Rollback:** full-GPO recovery plus selected-link restoration is tested with fixtures. Interrupted writes without a completed post-fingerprint require manual review by design; later external changes block restore. Actual Backup-GPO/Restore-GPO and security descriptor restoration require a live lab.
8. **Bounds:** sampling is at most five endpoints and replication at most 50 DCs. Evidence does not certify unsampled hosts or inaccessible DCs. Publication affects all existing links of the selected GPO, even though only one link is selected for adjustment.
9. **Deployment:** production-mode service start/restart/reconnect was not launched against the user's shared ProgramData state. Launcher parsing, packaged fingerprints, real compiled HTTP security helpers, DPAPI/ACL local fixtures and headless UI were tested. Clean-machine deployment, domain operator auth, requested shutdown markers and disconnected network startup need a lab.
10. **Release trust:** code-signing certificate/private key was unavailable; Authenticode signed-release execution was not performed. Embedded asset hashes and package SHA-256 are integrity checks, not independent publisher authentication. No new automatic update installer was created.
11. **Read-only environment probe:** this host is Windows 11 Pro, domain joined, but exposes no ActiveDirectory/GroupPolicy modules to this session. An auditpol read failed with 0x522 (privilege not held). A local Get-NetFirewallProfile ActiveStore read succeeded and returned the expected native property shapes. Profile values were omitted from the public report. Neither probe establishes that this application's selected GPO applied. Evidence is in evidence/native-read-probes.json with host/domain omitted. No disposable AD credentials/scope were supplied, and none were extracted from local state.

Intentionally blocked automatic controls: 1.2.3, 2.2.6, 2.2.16, 2.2.31, 2.2.33, 2.2.36, 2.2.39, 2.2.45, 2.3.11.6, 18.10.43.10.1, 18.10.43.10.2. Seven user-right controls require role-specific principal review; four additional controls have dedicated guides. Their blocking is not a failed automatic implementation.
''')
write('GPO_CHANGES.md',f'''
# GPO change tracking

## A. Actual Active Directory changes

**NO LIVE AD GPO OBJECTS WERE MODIFIED.**

No Backup-GPO, Restore-GPO, Set-GPRegistryValue, Set-ADObject, New/Set/Remove-GPLink, Invoke-GPUpdate, auditpol /set, secedit /configure, or production launcher was executed against a real AD/endpoint policy during this audit. Native command names in regression output are mocks operating on isolated fixtures. Separate native read-only probes were auditpol /get (insufficient privilege) and Get-NetFirewallProfile ActiveStore (local read succeeded; no selected-GPO attribution).

| Domain | GPO name/GUID | Target | CIS ID | Before/after | Time/operation/backup | Verification/rollback |
|---|---|---|---|---|---|---|
| None | None | None | None | None | None | Live testing not performed |

## B. Software implementation changes

Mapping metadata changed for exactly {len(changed)} controls: {', '.join(changed)}.

All {len(auto)} automatic controls use the repaired common verification/evidence path. A complete list is in AFFECTED_CONTROL_IDS.csv; no control is omitted because it is difficult or unsupported. The defect-to-file/test map is in ALL_DEFECTS_AND_FIXES.md and SOURCE_CHANGES.csv. Source edits are not actual AD GPO changes.

Snapshots from prior mapping hashes remain recoverable. Non-recovery operations with changed mappings require a fresh preview; existing GPOs are not changed by installing this code.
''')
changed_files=subprocess.check_output(['git','diff','--name-only'],cwd=ROOT,text=True,encoding='utf-8').splitlines()
changed_files+=subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=ROOT,text=True,encoding='utf-8').splitlines()
def file_change(p):
 table={
  'backend/PowerShell/GpoWorkflow.Worker.ps1':('Audit/native arguments, equality bounds, registry-only firewall evidence, stale scope and version-only replication','Shared item compliance, native ActiveStore/auditpol, current scope, file hashes and both CSE halves','all-control mapping/endpoint and verification-lifecycle fixtures'),
  'backend/Services/GpoWorkflowService.cs':('Evidence cache returned the first export after later changes','Current-run export with preserved content-addressed snapshots','WorkflowRegression'),
  'backend/Services/WorkspaceWorkflows.cs':('Failed standalone scheduling could finish COMPLETED; scan matched values called COMPLIANT','NEEDS_REVIEW on failed/empty refresh; scoped GPO_MATCH scan label','WorkspaceRegression'),
  'backend/Domain/GpoAssurance.cs':('No independent assurance claim model','Five stages and evidence-bounded diagnostic candidates','WorkflowRegression; RecoveryUi'),
  'backend/Domain/GpoWorkflow.cs':('Mixed result properties were the only assurance interface','Expose computed independent stages/diagnosis without changing persisted outcome fields','WorkflowRegression; API regressions'),
  'backend/Domain/ProductionGpoMappings.cs':('Multi-item mappings could not express an item-specific bound','Optional item comparator for backward-compatible typed serialization','all-control mapping/endpoint fixtures'),
  'backend/Infrastructure/WorkspaceEndpoints.cs':('HTML report omitted independent assurance claims','Escaped five-stage evidence table','WorkspaceRegression report checks'),
  'scripts/Build-ProductionMappings.py':('18 fixed numeric recipes rejected compliant bounds; cached-logon restart omitted','Explicit reviewed comparators and restart note; canonical ceiling for cached logons','Test-ProductionMappings; Test-GpoMappings'),
  'backend/data/gpo-production-mappings.json':('19 canonical records needed numeric/recommendation metadata repair','Deterministically regenerated reviewed mapping data','mapping-generation and all-control fixtures'),
  'frontend/source/components.js':('Manual checks could read wrong HKCU and reused a temporary export name','Selected SID hive, explicit native syntax, unique export/cleanup and ActiveStore command','Test-ManualVerification; RecoveryUi'),
  'frontend/source/product.js':('Duplicate disconnected implementation; broad verification wording; drawer lacked value/check command','One sign-in implementation, sample-only label and endpoint manual evidence','Test-RecipeWorkspace; Test-ManualVerification; RecoveryUi'),
  'frontend/source/control-view.js':('Verification page lacked five independent claims','Display computed assurance stages and diagnostic candidates','RecoveryUi'),
  'frontend/source/workflow-center.js':('Scan summary implied endpoint compliance','GPO_MATCH for current and legacy scan rows','WorkflowUi'),
  'frontend/source/benchmark-v4.json':('19.7.44.2.1 contained scraped footer/navigation chrome','Remove non-policy description/recommendation text','Test-ProductionMappings'),
  'GpoRemediator.ps1':('After-readiness exit described as startup-before-readiness; old package version','Distinct after-ready diagnosis and release 3.12.0','Test-VerificationLifecycle; built-source-match'),
  'scripts/Test-UX-Contract.cjs':('Hardcoded old asset version','Assert build-label/asset-version correspondence','Test-UX-Contract'),
  'security/Test-DomainGpoIsolation.ps1':('PowerShell 5.1 overload split into characters','Escaped literal Regex count','domain-gpo-isolation'),
 }
 if p in table:problem,fix,test=table[p]
 elif p.startswith(('frontend/dist/','release/')):problem,fix,test='Distributed artifacts must match corrected source','Regenerate compiled/distribution assets and hashes','built-source-match; Validate-ProductionPackage'
 elif p.startswith('scripts/'):problem,fix,test='Audit coverage or existing expectations needed regression evidence','Add/extend reproducible real-source synthetic tests and evidence generation','see evidence/test-results.json and individual tests'
 elif p.startswith('.github/'):problem,fix,test='New verifier matrix absent from CI','Register all-control/native/lifecycle/manual regressions','local equivalents pass; remote CI not claimed'
 else:problem,fix,test='Release version or audit documentation needed updating','3.12.0 version/cache identity and evidence-bounded documentation','build, syntax and package checks'
 return dict(File=p,Original_Problem=problem,Fix=fix,Test_Result=test)
csvwrite('SOURCE_CHANGES.csv',['File','Original_Problem','Fix','Test_Result'],[file_change(p) for p in sorted(set(changed_files)) if not p.startswith('docs/audit/')])
test_table='\n'.join(f"| {t['name']} | {t['kind']} | {t['status']} | {t['durationSeconds']} | [log]({t['log']}) |" for t in published_tests)
write('TEST_RESULTS.md',f'''
# Executed validation

Generated from individual subprocess exit codes and SHA-256-checked logs, not assumed coverage. Final command checks: **{len(tests)} executed / {pass_count} passed / {fail_count} failed**. No listed command was skipped. Eleven classes of live/unsupported validation were not run, as documented in UNVERIFIED_SCENARIOS.md. No remote CI completion is claimed.

Known parameterized coverage (distinct measurements, not a summed assertion count):

- {len(auto)} real mapping writer/read-back/idempotence/endpoint-recipe synthetic fixtures; 11 explicit manual blocks.
- {endpoint_cases} synthetic positive/negative/stronger-bound verifier cases across all 394 automatic controls.
- 1,592 backend control/refresh/priority combinations; invalid selections/value bounds and manual denial additionally checked.
- 405 generated manual PowerShell commands parsed by Windows PowerShell 5.1 without executing them.
- 9 replication/launcher regression scenarios; all final tests retain real source functions.
- {len(admx_ids)} registry control addresses matched installed ADMX; {len(admx['mismatches'])} detected simple Enabled/Disabled mismatches. Unmatched entries are not inferred correct or broken merely from absence in ADMX.
- Real local TestServer HTTP/RBAC/CSRF/idempotency, local DPAPI and private-file ACL fixtures, and Chrome desktop/mobile UI tests. These are actual Windows-local integration tests, not live AD tests.
- Actual Windows/AD end-to-end enforcement tests: **0**.

| Command check | Scope | Result | Seconds | Evidence |
|---|---|---|---:|---|
{test_table}

Earlier failures are not hidden: the baseline aggregate stopped on the obsolete 3.11.0 asset-version assertion; the first audit run had 32/34 passing checks, failing the changed sample-result label expectation and the PowerShell 5.1 String.Split isolation test. Both assertions were repaired for their intended semantics and the entire final run repeated. An intermediate packaging check also rejected audit transcripts saved with the forbidden runtime-log extension; published static transcripts now use .txt, while the package validator continues to reject runtime .log artifacts unchanged. Developing the new verifier matrix also exposed the auditpol argument error; final per-control results are preserved in evidence/endpoint-controls.json. Synthetic failure fixtures were corrected to use genuinely noncompliant values rather than values satisfying a minimum.

The published logs normalize workspace/runtime paths. Their original and normalized SHA-256 values are recorded in evidence/test-results.json. They contain synthetic example identities only. Runtime ZIP SHA-256: {sha(ROOT/'release/GpoRemediator-runtime-win-x64.zip')}.
''')
write('FULL_PROJECT_AUDIT.md',f'''
# Full GPO Remediator audit — 2026-10-15

Assessment: **NOT READY for an unrestricted production rollout.** The repaired source/package passes the available local checks; the authoritative benchmark/OS binding, target applicability, client processing and live AD enforcement gates below remain open. This is an end-to-end source/fixture audit, not a certification of an actual domain.

## Scope and counts

405 advertised and registered controls, all inventoried and source/fixture assessed. 394 automatic mappings, 11 intentional manual/review blocks. {len(changed)} mapping records changed; 15 confirmed defect groups repaired. {sum(r['Final_Status']=='OFFLINE_FAILURE' for r in rows)} automatic controls fail final synthetic checks. **0 controls were fully proved working in live AD; all 405 remain not fully tested for real applicability/enforcement.** The installed ADMX check covers {len(admx_ids)} addresses, with zero simple Boolean mismatches; it is not validation of every policy's OS applicability.

The repository inventory covers {len(inventory)} tracked/new source and distribution files; generated/dist copies are identified rather than counted as independent implementations. SOURCE_INVENTORY.csv records bytes, hashes and text scans; SYMBOL_INVENTORY.csv and API_INVENTORY.csv map entry points. A catalog-to-map set equality check found no missing or duplicate IDs relative to the supplied 405-entry catalog. Missing controls relative to an original authoritative CIS PDF cannot be determined from the supplied catalog alone.

## Architecture and dependencies

```mermaid
flowchart LR
  UI[Compiled offline frontend] --> HTTP[Loopback ASP.NET Core API]
  HTTP --> AUTH[Negotiate + startup proof + RBAC + CSRF]
  AUTH --> JOB[WorkspaceWorkflows durable queue]
  JOB --> GPO[GpoWorkflowService typed plans and context]
  GPO --> GATE[OperationGate GPO reservation]
  GPO --> DB[SQLite plans runs evidence HMAC audit]
  GPO --> EXEC[WindowsPowerShellExecutor private stdin]
  EXEC --> ISO[Verified per-domain/GPO launcher]
  ISO --> DC[Kerberos WinRM pinned writable DC]
  DC --> WORKER[Worker + SecurityTemplate module]
  WORKER --> GP[GroupPolicy and ActiveDirectory cmdlets]
  GP --> POLICY[AD GPC + SYSVOL GPT + links + Backup-GPO]
  WORKER --> END[Allowed endpoint native read probes]
```

| Component | Actual responsibility / dependency |
|---|---|
| backend/Program.cs | Composition, immutable config, protected state, loopback Kestrel, session/setup/service/GPO routes, startup integrity and recovery; no non-Windows fallback |
| Infrastructure/OperatorSecurity, OperatorConfirmation, RequestSecurity | Authenticated operator identity determines role; delegated AD execution identity is separate; exact-origin CSRF, role metadata and startup sign-in/rate limits |
| Infrastructure/Store, PrivateFiles | Microsoft.Data.Sqlite 10.0.13, durable WAL/FULL records, append-only audit/HMAC, DPAPI-protected keys, private ACLs, reparse-point rejection |
| Services/GpoWorkflowService, OperationGate | Ephemeral protected credentials, inventory, mapping/config hashes, allowlists, approvals, per-GPO reservations, operation/result/evidence storage |
| Services/WorkspaceWorkflows and Domain/WorkspaceWorkflow | Bounded server queue, reviewed/rebased batches, first-snapshot rollback anchors, read-only scans and delayed checks; interrupted writes become review, not replay |
| Infrastructure/WindowsPowerShellExecutor, GpoScriptWorkspaces, BundledAssets | Fixed bundled script integrity, private stdin credentials, bounded JSON/stage transport/deadlines; compiled UI and verified domain/GPO-specific launchers |
| PowerShell/Invoke-GpoWorkflow | One delegated Kerberos session to selected writable DC; trusted worker/module text; bounded product-owned error messages |
| PowerShell/GpoWorkflow.Worker | Discovery/preflight, policy conflict preview, Registry/RegistrySet, SecurityTemplate and AdvancedAudit writes, local/full GPO backups, version/CSE changes, links, replication/native probes and guarded restore |
| PowerShell/SecurityTemplate | Strict INI edits and duplicate rejection, CSE GUID pairs, low-16-bit computer version bump, normalized full-GPO content fingerprint |
| frontend/source | client/session/request handling; workspace state/router; catalog/control/operation/product views; workflow-center; automation/setup, enterprise read-only panels; scope picker; reusable components; preferences/AZ-EN/guides and styles |
| GpoRemediator.ps1 / scripts/ServiceControl / Start-ControlPanel | Verified ZIP install, source/runtime fingerprints, canonical protected config, readiness, restart/stop markers and bounded recovery; compatibility wrappers are documented |
| Build-Portable / Tooling | .NET 10 SDK plus Node only on developer build host; self-contained win-x64 runtime, compiled UI/script assets, package hash; no operator SDK download |
| security and CI | Pinned checkout/setup actions; .NET security/workflow fixtures, Python secret/mapping/scope checks, Windows PowerShell fixtures and Playwright Chrome/Edge UI; Authenticode builder requires supplied certificate |

One production project and four regression projects target net10.0. Production also depends on Negotiate 10.0.13 and ProtectedData 10.0.13; HTTP regressions use TestHost. Python and Playwright are test tooling, not runtime dependencies. Each csproj and all package versions are in SOURCE_INVENTORY.csv. Dependency advisory query result is in TEST_RESULTS.md/evidence; it is time-bounded, not a permanent guarantee.

## Exact operator paths

1. **Select CIS control:** benchmark-v4.json → catalog-view/product → workspace.selectRule → syncBackendMappings/ProductionGpoMappings.
2. **Choose domain:** Setup writes one pinned domain/DC config and controlled restart; explicit sign-in connects through GpoWorkflowService.ConnectAsync → gpoInventory. Simultaneous multi-domain browsing is not implemented.
3. **Select GPO:** discovered GUID/name/selectable flags → visual picker. Read-only inventory is not hidden by the production write allowlist.
4. **Select target:** live domain/OU catalog → GpoSelection; user policy separates user OU, endpoint OU and verification user; domain password/lockout accepts any selected active GPO and links it at the domain root with order 1.
5. **Preview:** /api/gpo/preview → typed mapping validation → DC Preview/Validate-Selection → current content/link fingerprint, authority warnings, inventory and conflicts. Readiness may create/delete a backup-directory probe; it does not change a GPO.
6. **Confirm:** change reference, APPLY/impact/protected confirmations → /api/workflows/apply or guarded direct endpoint → ValidateConsent, write gate, GUID/OU/host boundaries and current context.
7. **Apply:** server reservation + durable DC file lock → fresh preview/fingerprint check → full Backup-GPO/manifest → mechanism-specific write → selected link → read-back. Apply worker itself never forces endpoint refresh.
8. **Update:** an explicit approved workflow refresh choice or refresh action → live GPO/rollback preflight → allowed live-scope targets → Invoke-GPUpdate. A workflow with explicit refresh may chain it after Apply; this is not an automatic unapproved repeat.
9. **AD/SYSVOL:** Verification-Metadata → selected/local version + per-DC version/content/CSE checks; unreachable/truncated sets stay pending.
10. **Endpoint:** Verify-EffectiveSamples → current scope membership → at most five allowed endpoints → auditpol / secedit / ActiveStore / typed registry or selected user SID. Domain controls read the selected DC's account-policy properties; fine-grained per-user resultant password policy remains unproved.
11. **Report:** current run → content-addressed evidence snapshot or current workflow JSON/HTML report, explicit five assurance stages, endpoint results and diagnostic candidates. SHA-256 is integrity evidence, not a publisher signature.
12. **Rollback:** snapshot-aware consent/context → post-publication fingerprint and lock → Restore-GPO first snapshot → selected link restoration → content/extensions/link comparison. External changes or interrupted unknown writes require review; explicit refresh may follow the restored snapshot.

## Mechanism-by-mechanism findings

Registry/RegistrySet use GPMC Set-GPRegistryValue, including computer service startup registry settings and Administrative Template values; GPMC owns registry policy serialization/versioning. This is not presented as equivalent to changing service runtime state. Security Options/User Rights/Account Policies use INF templates where mapped and security CSE metadata/version updates. Advanced Audit uses its own audit.csv format and MS-GPAC CSE/tool pair; endpoint auditing uses numeric masks, preserving required include bits. Firewall writes policy inputs but verification now queries active resultant profiles. Defender/SMB/RDP/event logs and other registry-backed controls retain configuration-only runtime limits. All 405 records include the actual storage/method and tested/untested status in CIS_FULL_CONTROL_AUDIT.csv.

Scope enforcement exists in both typed backend rules and the DC worker. Cross-domain/RODC execution is rejected; remote mutation uses the delegated account, never auto-grants Domain Admin. GPO creation is absent. Other existing links are inspected and warned about, not silently removed. Link filtering/precedence analysis is advisory and is not token-accurate endpoint RSoP. WinRM's second-hop limitations are an explicit live-validation gate.

## Evidence and production gates

See ALL_DEFECTS_AND_FIXES.md for all 15 fixes; GPO_CHANGES.md distinguishes software changes from actual AD changes; TEST_RESULTS.md records {len(tests)} command checks and full logs; UNVERIFIED_SCENARIOS.md lists all remaining gates. Baseline/final test failures and fixture limitations are retained in the narrative. No simulated policy state is labelled actual AD evidence.

**NO LIVE AD GPO OBJECTS WERE MODIFIED.**

## Authoritative references and limits

- [Microsoft auditpol get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get): GUID subcategory queries and CSV reports. The local native read here failed for privilege; remote policy application remains untested.
- [MS-GPAC standard assignments](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/ac9c8234-d2e8-455d-be76-f84244dd1e58): Advanced Audit CSE/tool GUID pair was checked.
- [Microsoft Invoke-GPUpdate](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/invoke-gpupdate): remote refresh is scheduling; the implementation does not infer completion.
- [Microsoft Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile): ActiveStore is used for resultant profile configuration.
- [Microsoft secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export): merged policy export is used for security configuration.
- [Microsoft cached logon information](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/cached-domain-logon-information): CachedLogonsCount is REG_SZ, zero disables caching, and changing it requires restart.
- [CIS benchmark portal](https://www.cisecurity.org/cis-benchmarks): benchmark family/edition/version matters. The complete original v4.0.0 benchmark matching this imported catalog was unavailable; no official CIS conformance certification or complete independent 405-value proof is claimed.

## Git delivery

Intended branch: audit/full-project-20261015. Base main commit: b6739982525aeb4aeb4674a0e2e74ed9775cf768. Changes are committed/pushed on the audit branch only; no force-push or main overwrite. The actual commit and push result are reported in the delivery message (avoiding a self-referential commit hash inside its own committed content).
''')
summary=dict(controls=len(maps),audited=len(rows),automatic=len(auto),unsupported=len(blocked),live_verified=0,not_fully_tested=405,defect_groups_fixed=15,mapping_records_changed=len(changed),changed_control_ids=changed,final_checks=len(tests),passed=pass_count,failed=fail_count,endpoint_fixture_cases=endpoint_cases,admx_address_matches=len(admx_ids),live_ad_gpo_changes=0,readiness='NOT READY for unrestricted production',generatedAt=datetime.now(timezone.utc).isoformat())
(out/'AUDIT_SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps(summary,indent=2))
