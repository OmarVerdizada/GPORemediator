"""Independent policy-address regressions for defects found during the 405-control review."""
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
m = {x['id']: x for x in json.loads((root/'backend/data/gpo-production-mappings.json').read_text(encoding='utf-8'))['mappings']}
assert len(m) == 405
assert {x['id'] for x in m.values() if x['automation'] != 'Automated'} == {'1.2.3','2.3.11.6','18.10.43.10.1','18.10.43.10.2'}
for cid, key in [('2.3.1.2','EnableGuestAccount'),('2.3.10.1','LSAAnonymousNameLookup')]:
    assert m[cid]['handler'] == 'SecurityTemplate'
    assert m[cid]['items'] == [{'section':'System Access','key':key,'type':'Integer','value':['0']}]
for cid, name, value in [('2.3.17.8','EnableVirtualization','1'),('18.9.25.1','BackupDirectory','2'),('18.9.25.2','PasswordExpirationProtectionEnabled','1'),('18.6.21.2','fBlockNonDomain','1'),('18.6.9.1','EnableLLTDIO','0'),('18.6.9.2','EnableRspndr','0'),('18.10.43.17','DisableAntiSpyware','0')]:
    assert m[cid]['items'][0]['name'].lower() == name.lower(), cid
    assert m[cid]['items'][0]['value'] == [value], cid
assert m['18.6.19.2.1']['items'][0]['key'].lower() == r'hklm\system\currentcontrolset\services\tcpip6\parameters'
assert m['18.6.19.2.1']['requiresRestart']
assert {x['name'] for x in m['18.6.14.1']['items']} == {r'\\*\NETLOGON',r'\\*\SYSVOL'}
assert {x['name']:x['value'] for x in m['18.10.93.4.2']['items']} == {'DeferFeatureUpdates':['1'],'DeferFeatureUpdatesPeriodInDays':['180']}
assert {x['name']:x['value'] for x in m['18.9.23.1']['items']} == {'DevicePKInitEnabled':['1'],'DevicePKInitBehavior':['0']}
assert len(m['18.4.4']['items']) == 2 and 'Wow6432Node' in m['18.4.4']['items'][1]['key']
assert all(x['type'] == 'String' for x in m['18.4.4']['items']) and m['18.4.4']['requiresRestart']
for x in m.values():
    if 'include ' in x['title'].lower() and x['handler'] in ('SecurityTemplate','AdvancedAudit'):
        assert x['comparator'] == 'includes', x['id']
print('PASS independent mapping regressions, 405 unique controls and four guided boundaries')
