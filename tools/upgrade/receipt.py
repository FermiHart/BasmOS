#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""A hash-bound HOST build receipt. Not a digital signature or boot certificate."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import sys
from gate import ROOT, manifest

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def dump_atomic(path,data):
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,delete=False,prefix='.receipt-') as f:
        json.dump(data,f,indent=2); f.write('\n'); temp=Path(f.name)
    temp.replace(path)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--gate',type=Path,default=ROOT/'build/upgrade/gate/gate.json')
    ap.add_argument('--out',type=Path,default=ROOT/'build/upgrade/release')
    ap.add_argument('--verify',type=Path)
    a=ap.parse_args()
    if a.verify:
        p=a.verify.resolve(); receipt=json.loads(p.read_text())
        if receipt['inputs']!=manifest(): raise RuntimeError('source inputs changed')
        for row in receipt['artifacts']:
            # Only files immediately beneath the receipt directory are accepted.
            name=row['file']
            if Path(name).name!=name: raise RuntimeError('invalid artifact path')
            artifact=p.parent/name
            if sha(artifact)!=row['sha256'] or artifact.stat().st_size!=row['size']: raise RuntimeError('artifact changed: '+name)
            if sha(p.parent/(name+'.map'))!=row['map_sha256']: raise RuntimeError('symbol map changed: '+name)
        print('HOST receipt: hashes match (not authenticated)'); return
    gate=json.loads(a.gate.read_text()); inputs=manifest()
    if gate.get('status')!='PASS' or gate.get('inputs')!=inputs: raise RuntimeError('a fresh matching host gate is required')
    names={r['name'] for r in gate['variants']}
    if names!={'gcc','clang','gcc-asan','clang-asan'}: raise RuntimeError('full compiler/sanitizer matrix is required')
    assembler=a.gate.resolve().parent/'gcc/basm'
    gcc=next(r for r in gate['variants'] if r['name']=='gcc')
    if sha(assembler)!=gcc['assembler_sha256']: raise RuntimeError('assembler changed after gate')
    spec=importlib.util.spec_from_file_location('basm_contracts',ROOT/'tests/upgrade/test_assembler.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    out=a.out.resolve(); out.mkdir(parents=True,exist_ok=True); records=[]
    names=['basmos.bin','basmos-vm.bin','basmos-sh.bin','jash.bin','jash-pack.bin']
    for name,(source,flags,size,expected) in zip(names,module.ARTIFACTS):
        artifact=out/name; symbols=out/(name+'.map')
        p=subprocess.run([str(assembler),*flags,'-o',str(artifact),'--map',str(symbols),str(ROOT/source)],capture_output=True,timeout=10)
        if p.returncode: raise RuntimeError(p.stderr.decode())
        if sha(artifact)!=expected or artifact.stat().st_size!=size: raise RuntimeError('published artifact contract mismatch')
        records.append(dict(file=name,source=source,defines=flags,size=size,sha256=expected,
                            map_sha256=sha(symbols),symbols=[dict(offset=int(x.split()[0]),bytes=int(x.split()[1]),name=x.split()[2]) for x in symbols.read_text().splitlines()]))
    if inputs!=manifest(): raise RuntimeError('inputs changed during receipt build')
    receipt={'format':'basmos-host-receipt-v1','host_status':'PASS','release_status':'BLOCKED',
             'native_boot':'NOT_RUN','bear_compiler':'NOT_RUN','sacred_generator':'NOT_RUN',
             'authenticated':False,'gate_sha256':sha(a.gate), 'assembler_sha256':sha(assembler),
             'inputs':inputs,'artifacts':records}
    dump_atomic(out/'receipt.json',receipt)
    print('5/5 artifact identities verified; native release remains BLOCKED')
if __name__=='__main__':
    try: main()
    except (RuntimeError,OSError,ValueError,KeyError,subprocess.TimeoutExpired) as e:
        print('receipt:',e,file=sys.stderr); raise SystemExit(1)
