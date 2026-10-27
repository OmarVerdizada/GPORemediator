"""Regression tests for authored source drift and independent recipe identities; no AD."""
from pathlib import Path
import copy,importlib.util,json,shutil,tempfile,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mapping_source_audit',ROOT/'scripts/Audit-MappingSources.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
maps={m['id']:m for m in json.loads((ROOT/'backend/data/gpo-production-mappings.json').read_text(encoding='utf-8'))['mappings']}
bench={r['id']:r for r in json.loads((ROOT/'frontend/source/benchmark-v4.json').read_text(encoding='utf-8'))['rules']}
errors,_,_=audit.check_sources(maps,bench)
assert not errors,errors
assert len(maps)==405 and sum(m['automation']=='Automated' for m in maps.values())==394
with tempfile.TemporaryDirectory(prefix='gpr-source-test-') as tmp:
    sandbox=Path(tmp).resolve();assert sandbox.is_relative_to(Path(tempfile.gettempdir()).resolve())
    target=sandbox/'backend/data/mapping_sources';target.mkdir(parents=True)
    for source in (ROOT/'backend/data/mapping_sources').glob('*'):
        if source.is_file():shutil.copy2(source,target/source.name)
    audit.ROOT=sandbox
    original=(target/'section19-registry.tsv').read_text(encoding='utf-8')
    (sandbox/'scripts').mkdir();shutil.copy2(ROOT/'scripts/Build-ProductionMappings.py',sandbox/'scripts/Build-ProductionMappings.py')
    (sandbox/'frontend/source').mkdir(parents=True);shutil.copy2(ROOT/'frontend/source/benchmark-v4.json',sandbox/'frontend/source/benchmark-v4.json')
    shutil.copy2(ROOT/'backend/data/gpo-production-mappings.json',sandbox/'backend/data/gpo-production-mappings.json')
    checked=subprocess.run([sys.executable,str(sandbox/'scripts/Build-ProductionMappings.py'),'--check'],capture_output=True,text=True,encoding='utf-8')
    assert checked.returncode==0,checked.stderr
    (target/'section19-registry.tsv').write_text(original+'99.99\tHKCU\\SOFTWARE\\Example\tUnknown\tDWORD\t1\n',encoding='utf-8',newline='\n')
    rejected_generation=subprocess.run([sys.executable,str(sandbox/'scripts/Build-ProductionMappings.py')],capture_output=True,text=True,encoding='utf-8')
    assert rejected_generation.returncode!=0 and 'unknown catalog ID' in rejected_generation.stderr,rejected_generation.stderr
    (target/'section19-registry.tsv').write_text(original,encoding='utf-8',newline='\n')

    def rejected(text,expected):
        (target/'section19-registry.tsv').write_text(text,encoding='utf-8',newline='\n')
        result=audit.check_sources(maps,bench)[0]
        assert any(expected in e for e in result),result
    rejected(original.replace('19.5.1.1','99.99',1),'unknown control')
    rejected(original+original.splitlines()[0]+'\n','duplicate source')
    fields=original.splitlines()[0].split('\t');fields[4]='0'
    rejected('\t'.join(fields)+'\n'+'\n'.join(original.splitlines()[1:])+'\n','type/value differs')
    (target/'section19-registry.tsv').unlink()
    assert any('Required source missing' in e for e in audit.check_sources(maps,bench)[0])
    (target/'section19-registry.tsv').write_text(original,encoding='utf-8',newline='\n')
    for cid,mutate,expected in [
      ('18.10.43.6.1.2',lambda m:m['items'][5].update(name='00000000-0000-0000-0000-000000000000'),'ASR GUIDs differ'),
      ('18.10.43.11.1.1.2',lambda m:m['items'][0].update(name='BruteForceProtectionConfiguredState'),'source registry address/handler differs'),
      ('19.7.5.2',lambda m:m.update(scope='Computer'),'hive/scope mismatch'),
      ('2.3.10.1',lambda m:m.update(warnings=['No verified Windows GPO mapping is available.']),'unverified-placeholder warning'),
      ('9.1.1',lambda m:m['items'][0].update(value=['4294967296']),'invalid unsigned registry value'),
      ('17.3.1',lambda m:m['items'][0].update(mask=2),'audit state/mask mismatch')]:
        changed=copy.deepcopy(maps);mutate(changed[cid]);result=audit.check_sources(changed,bench)[0]
        assert any(expected in e for e in result),(cid,result)
    assert not audit.check_sources(maps,bench)[0]
print('PASS 405 source records: no orphan/duplicate/missing TSV, exact source/final recipe parity, ASR identity, feature identity, scope/type/value and audit-mask corruption rejected; no native execution')
