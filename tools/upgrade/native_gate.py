#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Opt-in invocation of the existing full repository gate, never a host substitute."""
import json
import os
from pathlib import Path
import shutil
import subprocess
from gate import ROOT

def main():
    out=ROOT/'build/upgrade/native';out.mkdir(parents=True,exist_ok=True)
    missing=[p for p in ['nasm','qemu-system-i386','node','make'] if not shutil.which(p)]
    missing += [p for p in ['Makefile','tools/generate_sacred_basm.py','basm-nano/basm_sacred.c'] if not (ROOT/p).is_file()]
    if not os.access('/dev/kvm',os.R_OK|os.W_OK): missing.append('/dev/kvm (read/write)')
    report={'status':'BLOCKED','missing':missing,'executed':[],'bear_compiler':'NOT_RUN unless BEAR is explicitly supplied to make'}
    if not missing:
        # Refuse stale generated metadata; regeneration is a separate explicit step.
        for cmd in [['python3','tools/generate_sacred_basm.py','--check'],['make','verify-nasm'],['make','proof']]:
            try:
                p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=1200)
            except (subprocess.TimeoutExpired,OSError) as e:
                report['status']='FAIL'; report['error']=str(e); break
            report['executed'].append({'command':cmd,'returncode':p.returncode})
            (out/f"step-{len(report['executed'])}.log").write_text(p.stdout+p.stderr)
            if p.returncode: report['status']='FAIL';break
        else: report['status']='PASS'
    (out/'status.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__': raise SystemExit(main())
