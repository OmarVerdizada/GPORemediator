"""Audit every imported control and its authored sources. Never contacts AD or writes policy.
Optional Microsoft SCT ZIP is read in memory; no downloaded script is executed.
"""
from pathlib import Path
import argparse,collections,csv,hashlib,io,json,os,re,sys,uuid,xml.etree.ElementTree as ET,zipfile
ROOT=Path(__file__).resolve().parents[1]
REGISTRY_TYPES={'DWORD','QWORD','STRING','MULTISTRING','EXPANDSTRING','BINARY'}
GUID_RE=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
def read_json(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def digest(raw):return hashlib.sha256(raw).hexdigest().upper()
def compact(value):return re.sub('[^a-z0-9]','',str(value or '').lower())
def address(key,name=''):
    text=str(key or '').replace('!','\\').strip().replace('\\\\','\\').lower()
    text=re.sub(r'^machine\\',lambda _: 'hklm\\',text)
    return text+('\\'+name.lower() if name else '')
def xml(raw):
    obj=ET.fromstring(raw.decode('utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'))
    for item in obj.iter():item.tag=item.tag.split('}')[-1]
    return obj
def check_sources(maps,bench):
    errors=[];origins=collections.defaultdict(list);snapshots=[]
    required={'section02-registry.tsv','section02-userrights.tsv','section09-registry.tsv','section17-audit.tsv','section18-registry.tsv','section19-registry.tsv','section18-asr.tsv'}
    missing=required-{p.name for p in (ROOT/'backend/data/mapping_sources').glob('*.tsv')}
    errors.extend('Required source missing: '+name for name in sorted(missing))
    for path in sorted((ROOT/'backend/data/mapping_sources').glob('*.tsv')):
        width=4 if path.name=='section18-asr.tsv' else 3 if 'userrights' in path.name else 5
        rows=list(csv.reader(path.read_text(encoding='utf-8-sig').splitlines(),delimiter='\t'));seen=set()
        for line,row in enumerate(rows,1):
            if not row:continue
            cid=row[0];tag=f'{path.name}:{line}';origins[cid].append(tag)
            if len(row)!=width:errors.append(f'{tag}: expected {width} columns');continue
            if cid not in maps:errors.append(f'{tag}: unknown control {cid}');continue
            unique=(cid,row[1].lower()) if path.name=='section18-asr.tsv' else cid
            if unique in seen:errors.append(f'{tag}: duplicate source record')
            seen.add(unique);m=maps[cid]
            if path.name.endswith('registry.tsv'):
                matches=[i for i in m['items'] if address(i.get('key'),i.get('name',''))==address(row[1],row[2])]
                if m['handler'] not in {'Registry','RegistrySet'} or len(matches)!=1:errors.append(f'{tag}: source registry address/handler differs from final mapping');continue
                it=matches[0];expected=[] if not row[4] and row[3]=='MultiString' else [row[4]]
                if it['type'].lower()!=row[3].lower() or it['value']!=expected:errors.append(f'{tag}: source type/value differs from final mapping')
            elif 'userrights' in path.name:
                expected=row[2].split('|') if row[2] else []
                if m['items']!=[{'section':'Privilege Rights','key':row[1],'type':'Principals','value':expected}]:errors.append(f'{tag}: privilege source differs from final mapping')
            elif path.name=='section17-audit.tsv':
                if len(m['items'])!=1:errors.append(f'{tag}: unexpected audit items');continue
                it=m['items'][0]
                if (it['guid'].lower(),it['name'],it['state'],it['mask'])!=(row[1].lower(),row[2],row[3],int(row[4])):errors.append(f'{tag}: audit source differs from final mapping')
            elif path.name=='section18-asr.tsv':
                matches=[i for i in m['items'] if i.get('name')==row[1].lower() and i.get('value')==[row[2]] and i.get('type')=='String']
                if len(matches)!=1:errors.append(f'{tag}: ASR rule state missing from final mapping')
        snapshots.append({'path':str(path.relative_to(ROOT)).replace('\\','/'),'sha256':digest(path.read_bytes()),'records':len(rows)})
    for cid in read_json(ROOT/'backend/data/mapping_sources/reviewed-overrides.json'):
        if cid not in maps:errors.append('Override has unknown ID '+cid)
        origins[cid].append('reviewed-overrides.json#'+cid)
    asr=maps['18.10.43.6.1.2'];required=set(re.findall(GUID_RE,bench['18.10.43.6.1.2']['recommended'],re.I));actual={i['name'].lower() for i in asr['items']}
    if actual!={g.lower() for g in required}:errors.append('18.10.43.6.1.2: ASR GUIDs differ from the imported recommendation')
    for cid,m in maps.items():
        if cid not in bench:errors.append('Mapping outside catalog '+cid)
        if m['title']!=bench[cid]['title']:errors.append(cid+': title mismatch')
        if m['automation']=='Automated' and (not m['items'] or m['handler']=='Manual'):errors.append(cid+': automatic control has no executable recipe')
        if m['automation']=='Automated' and any('No verified Windows GPO mapping' in warning for warning in m['warnings']):errors.append(cid+': executable recipe retains an unverified-placeholder warning')
        for it in m['items']:
            key=it.get('key','')
            if m['handler'] in {'Registry','RegistrySet'}:
                if it['type'].upper() not in REGISTRY_TYPES:errors.append(cid+': invalid registry type')
                if not re.match(r'^HK(LM|CU)\\[^\\]',key) or '\\\\' in key:errors.append(cid+': noncanonical registry key')
                if (key.startswith('HKCU\\')) != (m['scope']=='User'):errors.append(cid+': hive/scope mismatch')
                if it['type'] in ['DWORD','QWORD'] and any(not re.fullmatch(r'\d+',v) or not 0<=int(v)<2**(32 if it['type']=='DWORD' else 64) for v in it['value']):errors.append(cid+': invalid unsigned registry value')
            if m['handler']=='AdvancedAudit':
                try:uuid.UUID(it['guid'])
                except ValueError:errors.append(cid+': invalid audit GUID')
                mask=(1 if 'Success' in it['state'] else 0)|(2 if 'Failure' in it['state'] else 0)
                if mask!=it['mask']:errors.append(cid+': audit state/mask mismatch')
            if it.get('section')=='Privilege Rights' and not it.get('key','').startswith('Se'):errors.append(cid+': invalid privilege name')
        if m.get('allowValueOverride') and not m['minimum']<=m['suggested']<=m['maximum']:errors.append(cid+': desired value outside bounds')
    if set(maps)!=set(bench):errors.append('Catalog/mapping coverage differs')
    return errors,origins,snapshots

def references(admx_root,zip_path,extra):
    policies=collections.defaultdict(list);workbook=collections.defaultdict(list);titles=collections.defaultdict(list);native=collections.defaultdict(list);sources=[]
    templates=[(p.name,p.read_bytes(),'installed Windows PolicyDefinitions' if folder==admx_root else 'additional Microsoft ADMX reference') for folder in [admx_root,*extra] if folder.exists() for p in sorted(folder.glob('*.admx'))]
    if zip_path:
        with zipfile.ZipFile(zip_path) as z:
            sources.append({'source':'Microsoft SCT Windows Server 2019 ZIP','sha256':digest(zip_path.read_bytes()),'url':'https://www.microsoft.com/en-us/download/details.aspx?id=55319'})
            templates += [(n,z.read(n),'Microsoft SCT WS2019') for n in z.namelist() if n.endswith('.admx')]
            import openpyxl
            name='Documentation/MS Security Baseline Windows 10 v1809 and Server 2019.xlsx'
            wb=openpyxl.load_workbook(io.BytesIO(z.read(name)),read_only=True,data_only=True)
            for sheet in ['Computer','User','Security Template','WD Firewall','Adv Audit Config']:
                for line,row in enumerate(wb[sheet].values,1):
                    if line==1 or not row[1]:continue
                    item={'source':'Microsoft SCT WS2019 workbook','sheet':sheet,'row':line,'name':row[1],'supportedOn':row[6] if sheet in ['Computer','User'] else None}
                    titles[compact(row[1])].append(item)
                    raw=row[5] if sheet in ['Computer','User'] else row[6] if sheet=='Security Template' else ''
                    for addr in str(raw or '').splitlines():workbook[address(addr)].append(item)
            native_root=ET.fromstring(z.read('Documentation/MSFT-WS2019-MemberServer-FINAL.PolicyRules'))
            for item in native_root:
                if item.tag in ['ComputerConfig','UserConfig']:
                    key=('HKCU\\' if item.tag=='UserConfig' else 'HKLM\\')+item.findtext('Key','');native[address(key,item.findtext('Value',''))].append({'source':'Microsoft SCT WS2019 PolicyRules','type':item.findtext('RegType'),'baselineValue':item.findtext('RegData')})
                elif item.tag=='SecurityTemplate':
                    key=item.findtext('LineItem','').split('=')[0];native['security:'+item.get('Section','')+':'+key].append({'source':'Microsoft SCT WS2019 security template','line':item.findtext('LineItem')})
                elif item.tag=='AuditSubcategory':native['audit:'+item.findtext('GUID','').lower()].append({'source':'Microsoft SCT WS2019 audit table','name':item.findtext('Name'),'baselineMask':item.findtext('Setting')})
    for filename,raw,origin in templates:
        try:tree=xml(raw)
        except (ET.ParseError,UnicodeError,LookupError):continue
        sources.append({'source':filename,'origin':origin,'sha256':digest(raw)})
        for p in tree.findall('.//policy'):
            parentkey=p.get('key','');base={'template':filename,'policy':p.get('name'),'class':p.get('class'),'origin':origin,'supportedOn':p.find('supportedOn').get('ref') if p.find('supportedOn') is not None else ''}
            if p.get('valueName'):policies[address(parentkey,p.get('valueName'))].append((base,p,p))
            for el in p.findall('./elements/*'):
                if el.get('valueName'):policies[address(el.get('key',parentkey),el.get('valueName'))].append((base,p,el))
                elif el.tag=='list' and el.get('key'):policies['list:'+address(el.get('key'))].append((base,p,el))
    return policies,workbook,titles,native,sources

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--reference-zip',type=Path);ap.add_argument('--admx-root',type=Path,default=Path(os.environ.get('SystemRoot','C:/Windows'))/'PolicyDefinitions');ap.add_argument('--extra-admx',type=Path,action='append',default=[]);ap.add_argument('--audit-list',type=Path);ap.add_argument('--output',type=Path,default=ROOT/'work/mapping-source-audit');args=ap.parse_args()
    maps={m['id']:m for m in read_json(ROOT/'backend/data/gpo-production-mappings.json')['mappings']};bench={m['id']:m for m in read_json(ROOT/'frontend/source/benchmark-v4.json')['rules']}
    errors,origins,snapshots=check_sources(maps,bench);policies,book,titles,native,authority=references(args.admx_root,args.reference_zip,args.extra_admx)
    native_audit={}
    if args.audit_list:
        native_audit={r['GUID'].lower():r['Category/Subcategory'].strip() for r in csv.DictReader(args.audit_list.read_text(encoding='utf-8-sig').splitlines())}
        authority.append({'source':'Native auditpol subcategory listing','sha256':digest(args.audit_list.read_bytes())})
    documented=read_json(ROOT/'backend/data/mapping_sources/review-evidence.json')
    rows=[]
    for cid,m in maps.items():
        evidence=[];issues=[];dependency=[]
        name=re.search(r"(?:Ensure|Configure) '(.+?)'(?: is | to |$)",m['title']);base_title=name[1] if name else m['title']
        evidence+=titles.get(compact(base_title),[])
        for it in m['items']:
            key=it.get('key','');full=address(key,it.get('name',''));evidence+=book.get(full,[])+native.get(full,[])
            if it.get('section'):evidence+=native.get('security:'+it['section']+':'+key,[])
            if it.get('guid'):
                evidence+=native.get('audit:'+it['guid'].lower(),[])
                if native_audit:
                    actual=native_audit.get(it['guid'].lower(),'');expected=it['name'].removeprefix('Audit ')
                    if compact(expected)=='pnpactivity':expected='Plug and Play Events'
                    if compact(actual)!=compact(expected):issues.append('Native audit subcategory GUID/name mismatch')
                    else:evidence.append({'source':'Native auditpol subcategory listing','guid':it['guid'],'name':actual})
            if m['handler'] not in ['Registry','RegistrySet']:continue
            addr=address(key.split('\\',1)[1],it.get('name',''));candidates=policies.get(addr,[])
            if not candidates:candidates=policies.get('list:'+address(key.split('\\',1)[1]),[])
            for ref,p,node in candidates:
                if ref['class'] not in ['Both','User' if m['scope']=='User' else 'Machine']:continue
                evidence.append(ref)
                if node.tag=='policy':
                    boolean=re.search(r"is set to '(Enabled|Disabled)'$",m['title'])
                    value=p.find(('enabledValue' if boolean and boolean[1]=='Enabled' else 'disabledValue')+'/*') if boolean else None
                    if value is not None and it['value']!=[value.get('value',value.text or '')]:issues.append('ADMX boolean value differs: '+ref['template'])
                else:
                    types={'decimal':'String' if node.get('storeAsText')=='true' else 'DWORD','longDecimal':'QWORD','text':'ExpandString' if node.get('expandable')=='true' else 'String','multiText':'MultiString','list':'String'}
                    expected=types.get(node.tag)
                    if expected and expected.lower()!=it['type'].lower():issues.append('ADMX type differs: '+ref['template'])
                    if node.tag=='enum':
                        allowed=[v.get('value',v.text or '') for v in node.findall('./item/value/*')]
                        if allowed and any(v not in allowed for v in it['value']):issues.append('ADMX enum value absent: '+ref['template'])
                    if node.tag in ['decimal','longDecimal']:
                        for v in it['value']:
                            if not v.isdigit() or not int(node.get('minValue','0'))<=int(v)<=int(node.get('maxValue',str(2**64-1))):issues.append('ADMX numeric range mismatch: '+ref['template'])
                    if p.get('valueName') and p.find('enabledValue') is not None and not any(i.get('name','').lower()==p.get('valueName').lower() for i in m['items']):dependency.append(p.get('name')+' / '+p.get('valueName'))
        note=documented.get('controls',{}).get(cid,{})
        evidence+=note.get('references',[])
        if cid.startswith('9.'):evidence+=documented['families']['firewall']['references']
        if cid.startswith('2.2.'):evidence+=documented['families']['userRights']['references']
        if m['handler']=='AdvancedAudit':evidence+=documented['families']['audit']['references']
        evidence=list({json.dumps(ref,sort_keys=True):ref for ref in evidence}.values())
        if issues:errors += [cid+': '+i for i in sorted(set(issues))]
        status='GUIDED_REVIEW_REQUIRED' if m['automation']!='Automated' else 'SOURCE_ISSUE' if issues else 'CONFIGURATION_REFERENCE_REVIEWED' if evidence else 'ADDITIONAL_PRIMARY_REFERENCE_REQUIRED'
        rows.append({'id':cid,'section':int(cid.split('.')[0]),'title':m['title'],'scope':m['scope'],'handler':m['handler'],'automation':m['automation'],'comparator':m.get('comparator'),'minimum':m.get('minimum'),'maximum':m.get('maximum'),'requiresInput':m['requiresInput'],'requiresRestart':m['requiresRestart'],'items':m['items'],'sourceFiles':origins[cid] or ['Build-ProductionMappings.py: explicit account/special recipe'],'status':status,'evidence':evidence,'dependencies':sorted(set(dependency)),'reviewNote':note.get('note',''),'warnings':m['warnings'],'Server2019OriginalReference':any('WS2019' in str(ref.get('source','')) or ref.get('origin')=='Microsoft SCT WS2019' for ref in evidence),'CISOriginalDocumentBinding':'NOT_INDEPENDENTLY_BOUND','WindowsServer2019Enforcement':'NOT_LIVE_TESTED'})
    args.output.mkdir(parents=True,exist_ok=True)
    result={'target':'Windows Server 2019 (operator-confirmed)','controls':len(rows),'sourceErrors':errors,'sourceFiles':snapshots,'authoritySources':authority,'counts':dict(collections.Counter(r['status'] for r in rows)),'limitation':'Checks configuration addresses/types/value domains against Microsoft references and the operator-supplied catalog. Does not certify exact original CIS PDF binding, target-build applicability or live policy enforcement.','rows':rows}
    (args.output/'mapping-review.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8',newline='\n')
    with (args.output/'mapping-review.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['id','section','title','scope','handler','automation','comparator','minimum','maximum','requiresInput','requiresRestart','status','sourceFiles','items','dependencies','reviewNote','warnings','Server2019OriginalReference','CISOriginalDocumentBinding','WindowsServer2019Enforcement'];w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader()
        for row in rows:w.writerow({k:json.dumps(row[k],ensure_ascii=False) if isinstance(row[k],(list,dict)) else row[k] for k in fields})
    summary=['# Windows Server 2019 mapping-source review','','Every imported control is represented in the CSV and JSON. These are configuration-source checks, not live enforcement or full-benchmark certification.','','| Section | Controls | Reference reviewed | Guided | More reference required |','|---|---:|---:|---:|---:|']
    for section in range(1,20):
        group=[r for r in rows if r['section']==section];c=collections.Counter(r['status'] for r in group);summary.append(f"| {section} | {len(group)} | {c['CONFIGURATION_REFERENCE_REVIEWED']} | {c['GUIDED_REVIEW_REQUIRED']} | {c['ADDITIONAL_PRIMARY_REFERENCE_REQUIRED']} |")
    summary+=['','Sections with zero controls are empty headings in the supplied catalog; no remediation is invented for them.','',f'Source issues: {len(errors)}.','',*errors,'','Original CIS PDF/product-version binding remains unverified. Newer ADMX availability does not prove that Windows Server 2019 consumes every policy or has the required updates/components.','']
    (args.output/'mapping-review.md').write_text('\n'.join(summary),encoding='utf-8',newline='\n')
    print(json.dumps({'controls':len(rows),'errors':len(errors),'statuses':result['counts'],'output':str(args.output)}));
    if errors:raise SystemExit('\n'.join(errors))
if __name__=='__main__':main()
