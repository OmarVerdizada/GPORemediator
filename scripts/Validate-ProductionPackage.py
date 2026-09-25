#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'frontend' / 'source' / 'benchmark-v4.json'
MAPPINGS = ROOT / 'backend' / 'data' / 'gpo-production-mappings.json'

errors: list[str] = []
def check(ok: bool, msg: str):
    if not ok: errors.append(msg)

def load(path: Path):
    with path.open('r', encoding='utf-8-sig') as f: return json.load(f)

catalog_raw=load(CATALOG)
controls=(catalog_raw.get('controls') or catalog_raw.get('rules')) if isinstance(catalog_raw,dict) else catalog_raw
mapping_doc=load(MAPPINGS)
mappings=mapping_doc['mappings']

catalog_ids=[str(x['id']) for x in controls]
map_ids=[str(x['id']) for x in mappings]
check(len(catalog_ids)==405, f'catalog count {len(catalog_ids)} != 405')
check(len(set(catalog_ids))==405, 'catalog IDs are not unique')
check(len(map_ids)==405, f'mapping count {len(map_ids)} != 405')
check(len(set(map_ids))==405, 'mapping IDs are not unique')
check(set(catalog_ids)==set(map_ids), f'catalog/mapping ID mismatch: missing={sorted(set(catalog_ids)-set(map_ids))[:10]} extra={sorted(set(map_ids)-set(catalog_ids))[:10]}')

by_id={x['id']:x for x in mappings}
blocked={x['id'] for x in mappings if str(x.get('automation','')).lower()!='automated' or str(x.get('handler','')).lower()=='manual'}
expected_blocked={'1.2.3','2.3.11.6','18.10.43.10.1','18.10.43.10.2'}
check(blocked==expected_blocked, f'blocked control set changed: {sorted(blocked)}')
writable=[x for x in mappings if x['id'] not in blocked]
check(len(writable)==401, f'writable mappings {len(writable)} != 401')
check(mapping_doc['meta'].get('mapped')==401, 'mapping meta.mapped != 401')
check(mapping_doc['meta'].get('manualOrBlocked')==4, 'mapping meta.manualOrBlocked != 4')
check(mapping_doc['meta'].get('totalUnique')==405, 'mapping meta.totalUnique != 405')

handlers={'SecurityTemplate','Registry','RegistrySet','AdvancedAudit'}
check(all(x.get('handler') in handlers for x in mappings), 'unapproved handler found')
check(sum(x['handler']=='Registry' for x in mappings)==325, 'Registry count changed')
check(sum(x['handler']=='SecurityTemplate' for x in mappings)==48, 'SecurityTemplate count changed')
check(sum(x['handler']=='AdvancedAudit' for x in mappings)==27, 'AdvancedAudit count changed')
check(sum(x['handler']=='RegistrySet' for x in mappings)==5, 'RegistrySet count changed')

sid_guid=re.compile(r'^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$')
for m in mappings:
    mid=m['id']; h=m['handler']; scope=m.get('scope'); items=m.get('items') or []
    check(scope in {'Computer','User','Domain'}, f'{mid}: invalid scope {scope}')
    check(bool(items), f'{mid}: empty mapping items')
    check(len(items)<=32, f'{mid}: unreasonable item count')
    if m.get('requiresInput'):
        check(mid in {'2.3.1.4','2.3.1.5','2.3.7.4','2.3.7.5'}, f'{mid}: unexpected organization input')
    if m.get('allowValueOverride'):
        check(mid.startswith('1.'), f'{mid}: browser numeric override outside Account Policies')
        check(isinstance(m.get('minimum'),int) and isinstance(m.get('maximum'),int) and isinstance(m.get('suggested'),int), f'{mid}: override range incomplete')
        if all(isinstance(m.get(k),int) for k in ('minimum','maximum','suggested')):
            check(m['minimum']<=m['suggested']<=m['maximum'], f'{mid}: suggested outside range')
    if m.get('domainPolicySensitive'):
        check(mid.startswith('1.1.') or mid.startswith('1.2.'), f'{mid}: unexpected domain-sensitive flag')
        check(scope=='Domain', f'{mid}: domain-sensitive mapping not Domain scope')
    for item in items:
        if h=='SecurityTemplate':
            check(bool(item.get('section')) and bool(item.get('key')), f'{mid}: security-template section/key missing')
            check(item.get('type') in {'Integer','Principals','QuotedString','String'}, f"{mid}: unsupported security-template type {item.get('type')}")
        elif h in {'Registry','RegistrySet'}:
            key=str(item.get('key') or '')
            check(key.startswith(('HKLM\\','HKCU\\')), f'{mid}: registry key root invalid: {key}')
            check(bool(item.get('name')), f'{mid}: registry value name missing')
            check(item.get('type') in {'DWORD','QWORD','String','MultiString','ExpandString','Binary'}, f"{mid}: unsupported registry type {item.get('type')}")
            if scope=='User': check(key.startswith('HKCU\\'), f'{mid}: user mapping is not HKCU')
            else: check(key.startswith('HKLM\\'), f'{mid}: computer/domain mapping is not HKLM')
        elif h=='AdvancedAudit':
            check(sid_guid.match(str(item.get('guid') or '')) is not None, f'{mid}: invalid audit GUID')
            state=item.get('state'); mask=item.get('mask')
            expected={'Success':1,'Failure':2,'Success and Failure':3}
            check(state in expected and mask==expected.get(state), f'{mid}: audit state/mask mismatch')

# Explicit Account Policy safety contract.
account_ids={x['id'] for x in mappings if x.get('domainPolicySensitive')}
check(account_ids=={'1.1.1','1.1.3','1.1.4','1.1.5','1.1.6','1.2.1','1.2.2','1.2.3','1.2.4'}, f'domain policy control set changed: {sorted(account_ids)}')


# Production worker contracts that are easy to regress without a Windows lab.
worker=(ROOT/'backend'/'PowerShell'/'GpoWorkflow.Worker.ps1').read_text(encoding='utf-8-sig')
security=(ROOT/'backend'/'PowerShell'/'SecurityTemplate.psm1').read_text(encoding='utf-8-sig')
executor=(ROOT/'backend'/'Infrastructure'/'WindowsPowerShellExecutor.cs').read_text(encoding='utf-8-sig')
check('{F3CCC681-B74C-4060-9F26-CD84525DCA2A}' in security, 'Advanced Audit CSE GUID missing')
check('{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}' in security, 'Advanced Audit tool extension GUID missing')
check("if([string]$Map.handler -eq 'AdvancedAudit'){return [string]$Item.state}" in worker, 'Advanced Audit persisted-state comparison missing')
check("[string]$item.mask" in worker, 'Advanced Audit endpoint mask verification missing')
check("UnableToRetrievePolicyRegistryItem" in worker and "GPO_REGISTRY_READ_FAILED" in worker, 'Registry policy read must distinguish absent values from read failures')
check('Invoke-PasswordPilot.ps1' not in executor and 'Invoke-PolicyOperation.ps1' not in executor, 'Legacy Windows executor surface is still reachable')

# Frontend/dist must be byte-for-byte synchronized for operator UI assets we own.
for name in ('workspace.js','workspace.css','benchmark-v4.json','automation.js','automation.css'):
    a=ROOT/'frontend'/'source'/name; b=ROOT/'frontend'/'dist'/name
    if a.exists() or b.exists():
        check(a.exists() and b.exists(), f'{name}: source/dist missing')
        if a.exists() and b.exists(): check(a.read_bytes()==b.read_bytes(), f'{name}: source/dist mismatch')

# No development simulation database or known mock state should ship.
for bad in ('mock.db','mock.db-wal','mock.db-shm'):
    check(not any(ROOT.rglob(bad)), f'shipped development artifact: {bad}')

if errors:
    print('PRODUCTION PACKAGE VALIDATION: FAIL')
    for e in errors: print(' -',e)
    sys.exit(1)
print('PRODUCTION PACKAGE VALIDATION: PASS')
print(f' - catalog: {len(catalog_ids)} unique CIS v4 controls')
print(f' - server-writable: {len(writable)} automated controls')
print(f' - manual/read-only: {len(blocked)} controls')
print(' - handlers: SecurityTemplate / Registry / RegistrySet / AdvancedAudit')
print(' - source/dist synchronization: OK')
