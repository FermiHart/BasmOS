#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Reproducible host gate. Explicitly NOT make proof / NASM / boot qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
INPUTS=['basm-nano/basm_nano.c','tests/upgrade/test_assembler.py',
        'tests/upgrade/ipc_byte_contract.c','tools/upgrade/gate.py',
        'basmos.basm','basmos-sh.basm','jash/jash.basm','jash/jash-pack.basm']
def manifest():
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS}


def command(args, log, env=None):
    p=subprocess.run([str(a) for a in args],cwd=ROOT,env=env,capture_output=True,timeout=90)
    log.write_text('$ '+' '.join(map(str,args))+'\n'+p.stdout.decode(errors='replace')+p.stderr.decode(errors='replace'))
    if p.returncode: raise RuntimeError(f'command failed ({p.returncode}); see {log}')
    return p.stdout

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,default=ROOT/'build/upgrade/gate')
    ap.add_argument('--quick',action='store_true',help='GCC only; not the full matrix')
    args=ap.parse_args(); out=args.out.resolve(); out.mkdir(parents=True,exist_ok=True)
    result={'status':'FAIL','scope':'host assembler and bounded IPC-byte model',
            'native_boot':'NOT_RUN','sacred_generated_source':'NOT_RUN','variants':[]}
    try:
        before=manifest()
        for tool in ['gcc','as','objcopy']+([] if args.quick else ['clang']):
            if not shutil.which(tool): raise RuntimeError(f'required tool missing: {tool}')
        matrix=[('gcc','gcc',[])]
        if not args.quick:
            matrix += [('clang','clang',[]),('gcc-asan','gcc',['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']),
                       ('clang-asan','clang',['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie'])]
        for name,cc,extra in matrix:
            dest=out/name; dest.mkdir(exist_ok=True)
            flags=['-std=c11','-O2','-g','-Wall','-Wextra','-Werror',*extra]
            basm=dest/'basm'; vm=dest/'ipc-byte-contract'
            command([cc,*flags,ROOT/'basm-nano/basm_nano.c','-o',basm],dest/'compile.log')
            command([cc,*flags,ROOT/'tests/upgrade/ipc_byte_contract.c','-o',vm],dest/'compile-ipc.log')
            env=dict(os.environ,BASM_UNDER_TEST=str(basm),BASM_TEST_REPORT=str(dest/'tests.json'),
                     ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
            command([sys.executable,ROOT/'tests/upgrade/test_assembler.py'],dest/'tests.log',env)
            contracts=[]
            for variant,defines in [('bios',[]),('bemu-contract',['-DBEMU_CONTRACT'])]:
                binary=dest/(variant+'.bin'); symbols=dest/(variant+'.map')
                command([basm,*defines,'-o',binary,'--map',symbols,ROOT/'basmos.basm'],dest/(variant+'-build.log'),env)
                offsets={row.split()[2]:int(row.split()[0]) for row in symbols.read_text().splitlines()}
                data=command([vm,binary,*[offsets[n] for n in ['sys_send','sys_recv','idtr','other_sp']]],dest/(variant+'-ipc.log'),env)
                contracts.append(dict(variant=variant,**json.loads(data)))
            entry=dict(name=name,compiler=command([cc,'--version'],dest/'compiler.log').decode().splitlines()[0],
                       tests=json.loads((dest/'tests.json').read_text()),contracts=contracts,
                       assembler_sha256=hashlib.sha256(basm.read_bytes()).hexdigest())
            result['variants'].append(entry)
            print(name,'PASS',flush=True)
        if before!=manifest(): raise RuntimeError('inputs changed during gate')
        result['inputs']=before
        result['status']='PASS'
        result['source_sha256']=hashlib.sha256((ROOT/'basm-nano/basm_nano.c').read_bytes()).hexdigest()
    except (RuntimeError,subprocess.TimeoutExpired,OSError) as e:
        result['error']=str(e); print(str(e),file=sys.stderr)
    finally:
        (out/'gate.json').write_text(json.dumps(result,indent=2)+'\n')
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__': raise SystemExit(main())
