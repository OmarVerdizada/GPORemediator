#!/usr/bin/env python3
"""Conservative high-confidence secret pattern gate. NOT a substitute for GitHub secret scanning/Gitleaks."""
import re, sys, subprocess
from pathlib import Path
RULES={
 'private key':re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
 'AWS access key':re.compile(rb'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
 'GitHub classic token':re.compile(rb'\bghp_[A-Za-z0-9]{36}\b'),
 'GitHub fine-grained token':re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{70,}\b'),
 'Slack bot token':re.compile(rb'\bxoxb-\d{8,}-\d{8,}-[a-zA-Z0-9]{20,}\b'),
}
SCAN_EXT={'.cs','.js','.ts','.ps1','.psm1','.json','.yml','.yaml','.xml','.txt','.md','.cmd','.py','.ini','.config'}
SKIP_DIRS={'node_modules','runtime','release','dist','.git','work','obj','bin'}

def scan_bytes(data:bytes):
    return [name for name,expression in RULES.items() if expression.search(data)]

def files(root:Path):
    p=subprocess.run(['git','ls-files','-z'],cwd=root,check=True,capture_output=True)
    for raw in p.stdout.split(b'\0'):
        if not raw:continue
        rel=Path(raw.decode('utf-8','surrogateescape'))
        if any(x in SKIP_DIRS for x in rel.parts) or rel.suffix.lower() not in SCAN_EXT:continue
        if rel.as_posix()=='security/Secret-Pattern-Guard.py':continue # own test fixtures
        item=root/rel
        if item.is_file() and not item.is_symlink():yield rel,item

def main():
    if '--self-test' in sys.argv:
        assert scan_bytes(b'-----BEGIN PRIVATE KEY-----\n...')==['private key']
        assert scan_bytes(b'password = "placeholder"')==[]
        assert 'AWS access key' in scan_bytes(b'AKIA1234567890ABCDEF')
        print('SECRET GUARD SELF TEST PASS');return 0
    root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path.cwd()
    issues=[]
    for rel,p in files(root):
        try:found=scan_bytes(p.read_bytes())
        except (OSError,ValueError):continue
        for kind in found:issues.append((str(rel),kind))
    for p,kind in issues:print(f'SECRET_PATTERN: {p}: {kind}')
    print(f'Secret pattern guard: {len(issues)} high-confidence finding(s).')
    return 1 if issues else 0
if __name__=='__main__':sys.exit(main())
