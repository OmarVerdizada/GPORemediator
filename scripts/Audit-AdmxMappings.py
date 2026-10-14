from pathlib import Path
import xml.etree.ElementTree as ET,json,re,collections,argparse,hashlib,os
parser=argparse.ArgumentParser(description="Read-only installed ADMX address and simple boolean cross-check; not an OS applicability certification.")
parser.add_argument("--output",default="work/admx-review.json")
args=parser.parse_args()
os.chdir(Path(__file__).resolve().parents[1])
source_hashes={}
maps=json.loads(Path('backend/data/gpo-production-mappings.json').read_text(encoding='utf-8'))['mappings']; index=collections.defaultdict(list)
for f in (Path(os.environ.get('SystemRoot','C:/Windows'))/'PolicyDefinitions').glob('*.admx'):
 source_hashes[f.name]=hashlib.sha256(f.read_bytes()).hexdigest()
 try:
  raw=f.read_bytes();text=raw.decode('utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig');root=ET.fromstring(text)
 except (ET.ParseError,UnicodeError,LookupError):continue
 for el in root.iter():el.tag=el.tag.split('}')[-1]
 for p in root.findall('.//policy'):
  base=p.get('key','').lower();vn=p.get('valueName','').lower()
  if vn:index[(base,vn)].append((f.name,p))
  for el in p.findall('.//elements/*'):
   name=el.get('valueName','').lower();key=el.get('key',base).lower()
   if name:index[(key,name)].append((f.name,p))
found=[];missing=[];wrong=[]
for m in maps:
 if m['handler'] not in ('Registry','RegistrySet'):continue
 for item in m['items']:
  key=item['key'].split('\\',1)[1].lower();name=item['name'].lower();policies=index[(key,name)]
  if not policies:missing.append(m['id']+' '+item['name']);continue
  found.append(m['id'])
  desired=re.search(r"is set to '(Enabled|Disabled)'$",m['title'])
  if desired:
   for fn,p in policies:
    if p.get('valueName','').lower()!=name:continue
    v=p.find(('enabledValue' if desired[1]=='Enabled' else 'disabledValue')+'/*')
    if v is not None:
     expected=v.get('value',v.text or '')
     if item['value']!=[expected]:wrong.append((m['id'],m['title'],item['name'],item['value'],expected,fn,p.get('name')))
Path(args.output).parent.mkdir(parents=True,exist_ok=True)
Path(args.output).write_text(json.dumps({'sourceHashes':source_hashes,'limitation':'Registry-address and exact Enabled/Disabled cross-check only; no live domain or runtime enforcement verification.','matchedControls':sorted(set(found)),'missingItems':missing,'mismatches':wrong},indent=2),encoding='utf-8')
print('matched controls',len(set(found)));print('mismatches',json.dumps(wrong,indent=2));print('missing',missing)
