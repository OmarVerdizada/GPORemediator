#!/usr/bin/env python3
"""Enumerate all 405 CIS controls and fail closed on structural GPO-scope mismatches.
This is a source audit, NOT an effective Windows/AD audit.
"""
import csv, json, collections
from pathlib import Path
root = Path(__file__).resolve().parents[1]
a = json.loads((root/'backend/data/gpo-production-mappings.json').read_text(encoding='utf-8'))
b = json.loads((root/'frontend/source/benchmark-v4.json').read_text(encoding='utf-8'))
rows=a['mappings']; benchmark=b['rules']
assert len(rows)==405 and len({x['id'] for x in rows})==405, 'Expected 405 unique mapping IDs'
assert {x['id'] for x in rows}=={x['id'] for x in benchmark}, 'Mapping/benchmark ID mismatch'
roles={'2.2.6','2.2.16','2.2.31','2.2.33','2.2.36','2.2.39','2.2.45'}
fixed={'1.2.3','2.3.11.6','18.10.43.10.1','18.10.43.10.2'}
errors=[]; result=[]
for r in rows:
    cid=r['id']; section=cid.split('.')[0]; scope=r['scope']; items=r['items']; handler=r['handler']; auto=r['automation']=='Automated' and handler!='Manual'
    hive={i.get('key','').split('\\')[0].upper() for i in items if i.get('key','').upper().startswith(('HKCU\\','HKLM\\'))}
    if hive & {'HKCU'} and scope!='User': errors.append(f'{cid}: HKCU with {scope}')
    if hive & {'HKLM'} and scope!='Computer': errors.append(f'{cid}: HKLM with {scope}')
    if section=='19' and scope!='User': errors.append(f'{cid}: section 19 must be User')
    if section in ('2','5','9','17','18') and scope!='Computer': errors.append(f'{cid}: section {section} must be Computer')
    if section=='1' and scope!=('Computer' if cid=='1.2.3' else 'Domain'): errors.append(f'{cid}: section 1 exception mismatch')
    if scope=='Domain' and not r['domainPolicySensitive']: errors.append(f'{cid}: Domain not marked domainPolicySensitive')
    if scope!='Domain' and r['domainPolicySensitive']: errors.append(f'{cid}: non-Domain marked domainPolicySensitive')
    if section=='2' and cid.startswith('2.2.') and (handler not in ('SecurityTemplate','Manual') or not items or any(i.get('section')!='Privilege Rights' or not i.get('key','').startswith('Se') for i in items)):
        errors.append(f'{cid}: User Rights Assignment must be a machine security template privilege entry')
    if handler in ('Registry','RegistrySet') and not items: errors.append(f'{cid}: empty registry recipe')
    if handler=='AdvancedAudit' and (scope!='Computer' or any(not i.get('guid') for i in items)):
        errors.append(f'{cid}: invalid advanced-audit scope/GUID')
    if cid in roles and auto: errors.append(f'{cid}: role-specific principals must be guided until role discovery')
    if cid in fixed and auto: errors.append(f'{cid}: existing guided safety boundary disabled')
    if auto and not items: errors.append(f'{cid}: automated mapping without items')
    target = 'Default Domain Policy (domain root)' if scope=='Domain' else 'User OU' if scope=='User' else 'Computer OU/domain (choose precisely)'
    addr='; '.join((('['+i['section']+'] ') if i.get('section') else '')+(i.get('key') or i.get('guid') or '?') + (('\\'+i['name']) if i.get('name') else '') for i in items)
    if not addr: addr='GUIDED — no automatic write'
    principal='; '.join(','.join(i.get('value') or []) for i in items if i.get('section')=='Privilege Rights')
    result.append([cid,section,r['title'],scope,'User Configuration' if scope=='User' else 'Computer Configuration',handler,target,addr,principal,'AUTO' if auto else 'GUIDED',
                   'Role exception requires per-host review' if cid in roles else ('Review custom guided procedure' if cid in fixed else '')])
if errors:
    raise SystemExit('Policy scope audit FAILED:\n'+'\n'.join(errors))
auto=sum(row[9]=='AUTO' for row in result)
assert auto==394 and len(result)-auto==11, f'Unexpected automation boundary: {auto}/405'
out=root/'work'; out.mkdir(parents=True,exist_ok=True)
with (out/'policy-scope-audit.csv').open('w',encoding='utf-8-sig',newline='') as fh:
    writer=csv.writer(fh);writer.writerow(['CIS ID','Top Section','Control Title','Target Scope','GPO Half','Handler','Link Target','Policy Address','Principal Values','Operation','Review Note']);writer.writerows(result)
bysection=collections.defaultdict(lambda:collections.Counter())
for row in result:bysection[row[1]][row[3]]+=1
summary=['# CIS v4.0.0 policy scope audit (static, not endpoint proof)','',f'- Mappings: {len(result)}; automated: {auto}; guided: {len(result)-auto}.','- Source: backend/data/gpo-production-mappings.json.','- Only a live Windows AD/GPResult/secedit/auditpol test can establish effective compliance.','','| CIS section | Computer | User | Domain | Total |','|---|---:|---:|---:|---:|']
for sec in sorted(bysection,key=int):
 c=bysection[sec];summary.append(f"| {sec} | {c['Computer']} | {c['User']} | {c['Domain']} | {sum(c.values())} |")
summary+=['','## Exception-sensitive guided controls','',', '.join(sorted(roles,key=lambda v:[int(i) for i in v.split('.')])),'','## Every control','', 'Full per-control details are in `work/policy-scope-audit.csv` (405 individual entries).','']
(out/'policy-scope-summary.md').write_text('\n'.join(summary),encoding='utf-8')
print(f'PASS: {len(result)} static mappings (394 AUTO + 11 GUIDED), 19 CIS top sections; generated {out/"policy-scope-audit.csv"}')
