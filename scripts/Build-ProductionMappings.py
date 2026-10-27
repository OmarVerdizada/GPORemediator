import json, csv, glob, os, re, sys
root=os.path.dirname(os.path.dirname(__file__))
bench_path=os.path.join(root,'frontend','source','benchmark-v4.json')
bench=json.load(open(bench_path,encoding='utf-8'))
rules=bench['rules']
byid={r['id']:r for r in rules}

maps={}
def add(cid,handler,items=None,**kw):
    r=byid.get(cid)
    if not r: return
    maps[cid]={
      'id':cid,'controlId':cid,'title':r['title'],'category':r.get('sectionId',''),
      'level':r.get('level',''),'automation':r.get('automation',''),
      'handler':handler,'items':items or [],'recommended':r.get('recommended',''),
      'scope':'User' if cid.startswith('19.') else ('Domain' if cid.startswith('1.') else 'Computer'),
      'requiresInput':False,'inputType':None,'inputLabel':None,'inputDefault':None,
      'allowValueOverride':False,'minimum':None,'maximum':None,'suggested':None,'unit':None,'comparator':None,
      'domainPolicySensitive':cid.startswith('1.'),'requiresGpUpdate':True,'requiresRestart':False,
      'warnings':[], 'source':'operator CIS v4.0.0 + validated Windows policy mapping'
    }
    maps[cid].update(kw)

# Production Account Policy pack. Values are conservative benchmark recommended states.
account={
 '1.1.1':('PasswordHistorySize','24','>=','passwords'),
 '1.1.3':('MinimumPasswordAge','1','>=','days'),
 '1.1.4':('MinimumPasswordLength','14','>=','characters'),
 '1.1.5':('PasswordComplexity','1','==','enabled'),
 '1.1.6':('ClearTextPassword','0','==','disabled'),
 '1.2.1':('LockoutDuration','15','>=','minutes'),
 '1.2.2':('LockoutBadCount','5','<=','invalid attempts'),
 '1.2.3':('AllowAdministratorLockout','1','==','enabled'),
 '1.2.4':('ResetLockoutCount','15','>=','minutes'),
}
for cid,(key,val,cmp,unit) in account.items():
    add(cid,'SecurityTemplate',[{'section':'System Access','key':key,'type':'Integer','value':[val]}],
        comparator=cmp,unit=unit,scope='Domain',domainPolicySensitive=True,allowValueOverride=True,
        minimum={'1.1.1':24,'1.1.3':1,'1.1.4':14,'1.1.5':1,'1.1.6':0,'1.2.1':15,'1.2.2':1,'1.2.3':1,'1.2.4':15}[cid],
        maximum={'1.1.1':24,'1.1.3':998,'1.1.4':20,'1.1.5':1,'1.1.6':0,'1.2.1':99999,'1.2.2':5,'1.2.3':1,'1.2.4':99999}[cid],
        suggested=int(val),
        warnings=['Domain user password/lockout policy must use the domain root; the selected GPO is enabled at link order 1 so it becomes the effective domain account policy.'])

# TSV helpers.
def read_tsv(name):
    p=os.path.join(root,'backend','data','mapping_sources',name)
    if not os.path.exists(p): raise SystemExit(f'Required mapping source missing: {name}')
    expected_width=4 if name=='section18-asr.tsv' else 3 if 'userrights' in name else 5
    seen_rows=set()
    with open(p,encoding='utf-8') as f:
      for line,row in enumerate(csv.reader(f,delimiter='\t'),1):
        if row and row[0].strip():
            if len(row)!=expected_width: raise SystemExit(f'{name}:{line}: expected {expected_width} columns')
            if row[0] not in byid: raise SystemExit(f'{name}:{line}: unknown catalog ID {row[0]}')
            row_identity=(row[0],row[1].lower()) if name=='section18-asr.tsv' else row[0]
            if row_identity in seen_rows: raise SystemExit(f'{name}:{line}: duplicate source record')
            seen_rows.add(row_identity)
            if name=='section18-asr.tsv' and (row[0]!='18.10.43.6.1.2' or not re.fullmatch(r'[0-9a-fA-F-]{36}',row[1]) or row[2] not in ('0','1','2','6')): raise SystemExit(f'{name}:{line}: invalid ASR rule record')
            yield row

for row in read_tsv('section02-userrights.tsv'):
    cid,key,*rest=row; vals=(rest[0] if rest else '').split('|') if (rest and rest[0]) else []
    add(cid,'SecurityTemplate',[{'section':'Privilege Rights','key':key,'type':'Principals','value':vals}],scope='Computer')

for name in ['section02-registry.tsv','section09-registry.tsv','section18-registry.tsv','section19-registry.tsv']:
    for row in read_tsv(name):
        cid,key,vname,vtype,*value=row
        val=value[0] if value else ''
        vals=[] if vtype.lower()=='multistring' and val=='' else [val]
        add(cid,'Registry',[{'key':key,'name':vname,'type':vtype or 'DWORD','value':vals}],scope='User' if key.upper().startswith('HKCU') else 'Computer')

for row in read_tsv('section17-audit.tsv'):
    cid,guid,name,state,mask=row
    add(cid,'AdvancedAudit',[{'guid':guid,'name':name,'state':state,'mask':int(mask)}],scope='Computer')

# Correct user-catalog numbering and controls that differ from the reference task numbering.
add('2.3.1.1','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System','name':'NoConnectedUser','type':'DWORD','value':['3']}],scope='Computer')
add('2.3.1.2','SecurityTemplate',[{'section':'System Access','key':'EnableGuestAccount','type':'Integer','value':['0']}],scope='Computer')
add('2.3.1.3','Registry',[{'key':r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa','name':'LimitBlankPasswordUse','type':'DWORD','value':['1']}],scope='Computer')
add('2.3.1.4','SecurityTemplate',[{'section':'System Access','key':'NewAdministratorName','type':'QuotedString','value':[]}],scope='Computer',requiresInput=True,inputType='String',inputLabel='New built-in Administrator account name',warnings=['Choose a non-obvious name that does not reveal administrative purpose.'])
add('2.3.1.5','SecurityTemplate',[{'section':'System Access','key':'NewGuestName','type':'QuotedString','value':[]}],scope='Computer',requiresInput=True,inputType='String',inputLabel='New built-in Guest account name',warnings=['Choose a non-obvious name that does not reveal guest purpose.'])
add('2.3.7.4','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System','name':'LegalNoticeText','type':'String','value':[]}],scope='Computer',requiresInput=True,inputType='String',inputLabel='Logon legal notice text')
add('2.3.7.5','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System','name':'LegalNoticeCaption','type':'String','value':[]}],scope='Computer',requiresInput=True,inputType='String',inputLabel='Logon legal notice title')

# Security database settings have explicit base recipes; no registry placeholder is involved.
add('2.3.10.1','SecurityTemplate',[{'section':'System Access','key':'LSAAnonymousNameLookup','type':'Integer','value':['0']}],scope='Computer')
add('2.3.11.6','SecurityTemplate',[{'section':'System Access','key':'ForceLogoffWhenHourExpire','type':'Integer','value':['1']}],scope='Computer')

add('2.3.10.7','Registry',[{'key':r'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters','name':'NullSessionPipes','type':'MultiString','value':[]}],scope='Computer',warnings=['The benchmark permits BROWSER only when the legacy Computer Browser service is enabled. This mapping uses the safer blank list. RDS Licensing role exceptions must be reviewed.'])
add('2.3.10.8','Registry',[{'key':r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths','name':'Machine','type':'MultiString','value':[r'System\\CurrentControlSet\\Control\\ProductOptions',r'System\\CurrentControlSet\\Control\\Server Applications',r'Software\\Microsoft\\Windows NT\\CurrentVersion']}],scope='Computer')
add('2.3.10.9','Registry',[{'key':r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths','name':'Machine','type':'MultiString','value':[r'System\\CurrentControlSet\\Control\\Print\\Printers',r'System\\CurrentControlSet\\Services\\Eventlog',r'Software\\Microsoft\\OLAP Server',r'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print',r'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',r'System\\CurrentControlSet\\Control\\ContentIndex',r'System\\CurrentControlSet\\Control\\Terminal Server',r'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig',r'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration',r'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib',r'System\\CurrentControlSet\\Services\\SysmonLog']}],scope='Computer',warnings=['AD CS Certification Authority and WINS Server roles require documented additional paths. The base Member Server list is used unless role-specific mapping is added.'])

# Service control is represented by the service Start policy registry value in the GPO.
add('5.2','Registry',[{'key':r'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler','name':'Start','type':'DWORD','value':['4']}],scope='Computer',requiresRestart=True,warnings=['Disabling Print Spooler can break printing and print-dependent applications.'])

# Additional v4 controls present in the operator catalog but omitted from the first normalized extraction pass.
add('18.10.4.1','Registry',[{'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateManager','name':'AllowSharedLocalAppData','type':'DWORD','value':['0']}],scope='Computer')
add('18.10.6.1','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System','name':'MSAOptional','type':'DWORD','value':['1']}],scope='Computer')
add('18.10.8.1','Registry',[{'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer','name':'NoAutoplayfornonVolume','type':'DWORD','value':['1']}],scope='Computer')
add('18.10.8.2','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer','name':'NoAutorun','type':'DWORD','value':['1']}],scope='Computer')
add('18.10.8.3','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer','name':'NoDriveTypeAutoRun','type':'DWORD','value':['255']}],scope='Computer')
add('18.10.9.1.1','Registry',[{'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures','name':'EnhancedAntiSpoofing','type':'DWORD','value':['1']}],scope='Computer')

# Multi-value/special policies.
add('18.6.20.1','Registry',[
 {'key':r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Wcn\Registrars','name':'EnableRegistrars','type':'DWORD','value':['0']}
],scope='Computer')
add('18.9.5.2','Registry',[{'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard','name':'RequirePlatformSecurityFeatures','type':'DWORD','value':['3']}],scope='Computer',warnings=['Requires compatible UEFI/Secure Boot/DMA protection hardware. Validate virtualization platform support before deployment.'])
add('18.9.20.1.4','Registry',[{'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Internet Connection Wizard','name':'ExitOnMSICW','type':'DWORD','value':['1']}])
add('18.9.20.1.5','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer','name':'NoWebServices','type':'DWORD','value':['1']}])
add('18.9.20.1.7','Registry',[{'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Registration Wizard Control','name':'NoRegistration','type':'DWORD','value':['1']}])
add('18.9.20.1.10','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer','name':'NoPublishingWizard','type':'DWORD','value':['1']}])
add('18.9.25.1','Registry',[{'key':r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS','name':'BackupDirectory','type':'DWORD','value':['2']}],warnings=['This on-prem Active Directory workflow chooses Active Directory (2). Microsoft Entra backup (1) is also benchmark-compliant but is outside this product\'s current AD-only deployment model.'])

# Per-rule states are explicit source records, not a second handwritten GUID list.
asr_rows=list(read_tsv('section18-asr.tsv'))
if not asr_rows or len({row[1].lower() for row in asr_rows}) != len(asr_rows):
    raise SystemExit('ASR source must contain distinct rule GUIDs.')
add('18.10.43.6.1.2','RegistrySet',[
 {'key':r'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules','name':row[1].lower(),'type':'String','value':[row[2]]}
 for row in asr_rows
])
add('18.10.76.2.1','RegistrySet',[
 {'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System','name':'EnableSmartScreen','type':'DWORD','value':['1']},
 {'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System','name':'ShellSmartScreenLevel','type':'String','value':['Block']}
])
add('18.10.93.4.1','RegistrySet',[
 {'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate','name':'ManagePreviewBuilds','type':'DWORD','value':['1']},
 {'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate','name':'ManagePreviewBuildsPolicyValue','type':'DWORD','value':['1']}
])
add('18.10.93.4.3','RegistrySet',[
 {'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate','name':'DeferQualityUpdates','type':'DWORD','value':['1']},
 {'key':r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate','name':'DeferQualityUpdatesPeriodInDays','type':'DWORD','value':['0']}
])
# User catalog contains legacy numbering for these two controls; map by title/intent.
add('19.7.42.1','Registry',[{'key':r'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer','name':'AlwaysInstallElevated','type':'DWORD','value':['0']}],scope='User')
add('19.7.44.2.1','Registry',[{'key':r'HKCU\\SOFTWARE\\Policies\\Microsoft\\WindowsMediaPlayer','name':'PreventCodecDownload','type':'DWORD','value':['1']}],scope='User')

# Controls whose desired state is organization-specific but still safely supported through explicit input.
for cid in ['2.3.1.4','2.3.1.5','2.3.7.4','2.3.7.5']:
    maps[cid]['requiresInput']=True

# Any catalog rule without a verified mapping remains explicitly blocked rather than guessed.
for r in rules:
    if r['id'] not in maps:
        add(r['id'],'Manual',[],scope='User' if r['id'].startswith('19.') else 'Computer',
            warnings=['No verified Windows GPO mapping is available for this catalog entry. Automatic write is blocked.'],
            automation=r.get('automation',''),requiresGpUpdate=False)

# Normalize only registry key/path strings authored in special mappings. Some Python raw literals
# intentionally used doubled separators for readability; GroupPolicy cmdlets require canonical single separators.
for _m in maps.values():
    for _i in _m.get('items', []):
        if isinstance(_i.get('key'), str):
            while '\\\\' in _i['key']:
                _i['key']=_i['key'].replace('\\\\','\\')
        if _m['id'] in ('2.3.10.8','2.3.10.9') and isinstance(_i.get('value'), list):
            _i['value']=[_v.replace('\\\\','\\') if isinstance(_v,str) else _v for _v in _i['value']]

# Surface benchmark applicability/operational notes in the server-side plan without trying to
# guess role-specific exceptions. The full imported benchmark description remains visible in UI.
for _cid,_m in maps.items():
    _desc=(byid.get(_cid) or {}).get('description','')
    if re.search(r'(?i)\b(note|caution|important)\s*:',_desc):
        _w='This CIS recipe contains benchmark notes/cautions or environment-specific exceptions. Review the imported benchmark description and application dependencies before Apply.'
        if _w not in _m['warnings']:
            _m['warnings'].append(_w)

# Explicit operational convergence notes that cannot be solved by gpupdate alone.
if '2.3.10.4' in maps:
    maps['2.3.10.4']['warnings'].append('Windows restart is required before this Credential Manager policy becomes effective.')
if '18.7.1' in maps:
    maps['18.7.1']['warnings'].append('The Print Spooler service must be restarted before this policy becomes effective.')

# Reviewed corrections are explicit and reproducible; see docs/REMEDIATION-AUDIT.md.
with open(os.path.join(root, 'backend', 'data', 'mapping_sources', 'reviewed-overrides.json'), encoding='utf-8') as f:
    for cid, patch in json.load(f).items():
        maps[cid].update(patch)
# ROLE-SENSITIVE CONTROLS: SAFETY GATE. A single generic SID list must not
# overwrite service identities installed with IIS, SQL, ADFS or Exchange roles.
# Future auto-remediation requires per-endpoint role discovery and role-aware
# desired-set construction, followed by endpoint verification.
ROLE_SENSITIVE = {
    '2.2.6': 'IIS application pools require additional SeIncreaseQuotaPrivilege principals on relevant member servers.',
    '2.2.16': 'Microsoft SQL Server integration services can require additional SeCreateGlobalPrivilege principals.',
    '2.2.31': 'IIS and AD FS may require additional SeAuditPrivilege principals.',
    '2.2.33': 'IIS servers require IIS_IUSRS for SeImpersonatePrivilege.',
    '2.2.36': 'SQL Server memory configuration may require SQL service identities in SeLockMemoryPrivilege.',
    '2.2.39': 'Exchange servers may require the Exchange Servers principal in SeSecurityPrivilege on domain controllers.',
    '2.2.45': 'IIS application pools may require additional SeAssignPrimaryTokenPrivilege principals.',
}
for _cid, _reason in ROLE_SENSITIVE.items():
    _m = maps[_cid]
    _m['handler'] = 'Manual'
    _m['automation'] = 'Manual'
    _m['requiresGpUpdate'] = False
    _m['warnings'].append('ROLE-SENSITIVE / GUIDED ONLY: '+_reason+' Auto-write is disabled until role-specific target inventory and explicit principal approval are implemented.')

# "Include" is a minimum set, not permission to remove existing deny/audit entries.
for m in maps.values():
    if 'include ' in m['title'].lower() and m['handler'] in ('SecurityTemplate', 'AdvancedAudit'):
        m['comparator'] = 'includes'

# A control's processing half is derived from the reviewed policy address, then
# Preserve compliant stronger values for explicit numeric bounds in the imported
# control titles. atMost permits zero; <= retains the explicit nonzero contract.
NUMERIC_BOUNDS = {
    '2.3.6.5':'<=', '2.3.7.3':'<=', '2.3.7.6':'atMost', '2.3.9.1':'atMost',
    '9.1.5':'>=', '9.2.5':'>=', '9.3.7':'>=', '18.5.9':'atMost', '18.5.12':'atMost',
    '18.9.25.5':'>=', '18.9.25.6':'atMost', '18.9.25.7':'<=',
    '18.10.26.1.2':'>=', '18.10.26.2.2':'>=', '18.10.26.3.2':'>=', '18.10.26.4.2':'>=',
    '18.10.57.3.10.1':'atMost'
}
for cid, comparator in NUMERIC_BOUNDS.items():
    maps[cid]['comparator']=comparator
# Use the documented upper boundary; existing stricter values are now retained.
maps['2.3.7.6']['items'][0]['value']=['4']
maps['2.3.7.6']['requiresRestart']=True
maps['2.3.7.6']['warnings'].append('CachedLogonsCount configuration changes require a Windows restart; a matching registry value alone does not prove the cached-logon behavior changed.')
maps['18.10.93.4.2']['items'][1]['comparator']='>='

# A control's processing half is derived from the reviewed policy address, then
# checked against the declared scope. This prevents an HKCU recipe from being
# silently treated as a computer policy (or the inverse) during future imports.
for m in maps.values():
    registry_roots={i.get('key','').split('\\',1)[0].upper() for i in m.get('items',[]) if i.get('key','').upper().startswith(('HKCU\\','HKLM\\'))}
    expected='Domain' if m.get('domainPolicySensitive') else ('User' if 'HKCU' in registry_roots else 'Computer')
    if m['scope'] != expected:
        raise SystemExit(f"{m['id']}: declared scope {m['scope']} conflicts with reviewed policy address ({expected})")

# Remove accidental duplicates by ID; preserve user catalog order in output.
out=[];seen=set()
for r in rules:
    cid=r['id']
    if cid in seen: continue
    seen.add(cid);out.append(maps[cid])

meta={
 'schemaVersion':'2.0','benchmark':'CIS Benchmark v4.0.0','generatedFrom':'operator-supplied catalog',
 'mapped':sum(1 for x in out if x['handler']!='Manual' and x.get('automation')=='Automated'),
 'manualOrBlocked':sum(1 for x in out if x['handler']=='Manual' or x.get('automation')!='Automated'),
 'totalUnique':len(out),
 'reviewTargetOperatingSystem':'Windows Server 2019 (operator-confirmed)',
 'sourceCatalogBinding':'Imported 405-control subset; original CIS product/version document not independently bound. Not a full-benchmark or OS-enforcement certification.',
 'notes':'Mappings were cross-checked against Windows Group Policy semantics and the MIT-licensed ansible-lockdown Windows-2019-CIS GPO implementation where applicable.'
}
obj={'meta':meta,'mappings':out}
out_path=os.path.join(root,'backend','data','gpo-production-mappings.json')
serialized=json.dumps(obj,ensure_ascii=False,indent=2)+'\n'
if '--check' in sys.argv:
    with open(out_path,encoding='utf-8') as f:
        if f.read()!=serialized:
            raise SystemExit('Production mappings differ from reviewed generator output.')
else:
    with open(out_path,'w',encoding='utf-8',newline='\n') as f:
        f.write(serialized)
print(json.dumps(meta,indent=2))
print('read-only:',[x['id'] for x in out if x['handler']=='Manual' or x.get('automation')!='Automated'])
