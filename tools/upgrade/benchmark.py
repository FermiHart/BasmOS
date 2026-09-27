#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Paired CPU/wall measurements of assembly passes, not guest execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,default=ROOT/'build/upgrade/benchmark')
    ap.add_argument('--baseline',type=Path,default=ROOT/'tests/upgrade/reference/basm_nano.c',
                    help='source of the original assembler (default: package reference)')
    ap.add_argument('--min-sample-ms',type=float,default=10,
                    help='calibrate both variants to at least this CPU duration per sample')
    args=ap.parse_args(); out=args.out.resolve(); out.mkdir(parents=True,exist_ok=True)
    if not 1 <= args.min_sample_ms <= 100:
        ap.error('--min-sample-ms must be between 1 and 100')
    # Keep process placement identical; frequency and the shared host are not controlled.
    cpu=None
    if hasattr(os,'sched_getaffinity'):
        cpu=min(os.sched_getaffinity(0)); os.sched_setaffinity(0,{cpu})
    sources={'original':args.baseline.resolve(),'updated':ROOT/'basm-nano/basm_nano.c'}
    source_hashes={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in sources.items()}
    binaries={}
    for variant,source in sources.items():
        binary=out/('bench-'+variant); binaries[variant]=binary
        cmd=['gcc','-std=c11','-O2','-D_XOPEN_SOURCE=700',f'-DBASM_SOURCE="{source}"',
             str(ROOT/'tests/upgrade/bench_assembler.c'),'-o',str(binary)]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        (out/(variant+'-compile.log')).write_text('$ '+' '.join(cmd)+'\n'+p.stdout+p.stderr)
        if p.returncode: raise RuntimeError(p.stderr)
    def case(name,text,loops):
        file=out/(name+'.basm'); file.write_text(text); return (name,file,loops)
    workloads=[case('single_nop','BITS 32\norg 0\nnop\n',3000),
               case('padding_512','BITS 32\norg 0\ntimes 512 db 0\n',1500),
               case('padding_65536','BITS 32\norg 0\ntimes 65536 db 0\n',100),
               case('data_4096','BITS 32\norg 0\n'+'db 1,2,3,4\n'*1024,100)]
    labels=''.join(f's{i}:\n' for i in range(256))
    workloads.append(case('symbols_256_refs_5000','BITS 32\norg 0\n'+labels+''.join(f'dd s{i%256}\n' for i in range(5000)),12))
    workloads += [('record_source',ROOT/'basmos.basm',100),('shell_source',ROOT/'basmos-sh.basm',100),
                  ('jash_source',ROOT/'jash/jash.basm',100),('pack_source',ROOT/'jash/jash-pack.basm',100)]
    input_hashes={name:hashlib.sha256(file.read_bytes()).hexdigest() for name,file,_ in workloads}
    calibrated=[]
    for name,file,loops in workloads:
        count=loops
        for variant in sources:
            p=subprocess.run([str(binaries[variant]),str(loops),str(file)],capture_output=True,text=True,timeout=30)
            if p.returncode: raise RuntimeError(f'calibration {name}/{variant}: {p.stderr}')
            duration=json.loads(p.stdout)['cpu_ns']
            count=max(count,int(loops*args.min_sample_ms*1e6/max(1,duration))+1)
        calibrated.append((name,file,min(count,1000000)))
    workloads=calibrated
    raw=[]
    for round_no in range(3):
        for name,file,loops in workloads:
            for sample in range(5):
                order=['original','updated'] if (round_no+sample)%2==0 else ['updated','original']
                pair=[]
                for variant in order:
                    p=subprocess.run([str(binaries[variant]),str(loops),str(file)],capture_output=True,text=True,timeout=30)
                    if p.returncode: raise RuntimeError(f'{name}/{variant}: {p.stderr}')
                    row=dict(case=name,variant=variant,round=round_no,sample=sample,**json.loads(p.stdout))
                    row['wall_ns_op']=row['wall_ns']/loops; row['cpu_ns_op']=row['cpu_ns']/loops
                    raw.append(row); pair.append(row)
                if (pair[0]['bytes'],pair[0]['output_fnv32'])!=(pair[1]['bytes'],pair[1]['output_fnv32']):
                    raise RuntimeError(f'output mismatch: {name}')
    rows=[]
    for name,_,_ in workloads:
        row={'case':name}
        for variant in sources:
            subset=[r for r in raw if r['case']==name and r['variant']==variant]
            row[variant]={key:statistics.median(r[key] for r in subset) for key in ['wall_ns_op','cpu_ns_op']}
            row[variant]['cpu_ns_op_min']=min(r['cpu_ns_op'] for r in subset)
            row[variant]['cpu_ns_op_max']=max(r['cpu_ns_op'] for r in subset)
        row['speedup_wall']=row['original']['wall_ns_op']/row['updated']['wall_ns_op']
        row['speedup_cpu']=row['original']['cpu_ns_op']/row['updated']['cpu_ns_op']
        rows.append(row)
    if source_hashes!={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in sources.items()}:
        raise RuntimeError('assembler source changed during benchmark')
    if input_hashes!={name:hashlib.sha256(file.read_bytes()).hexdigest() for name,file,_ in workloads}:
        raise RuntimeError('workload changed during benchmark')
    result={'scope':'two assembly passes; excludes CLI, I/O, emulation and guest runtime',
            'status':'PASS','cpu_affinity':cpu,'host':platform.platform(),
            'compiler':subprocess.check_output(['gcc','--version'],text=True).splitlines()[0],
            'flags':['-std=c11','-O2','-D_XOPEN_SOURCE=700'],
            'clock':'CLOCK_MONOTONIC and CLOCK_THREAD_CPUTIME_ID',
            'exclusive_host':False,'frequency_controlled':False,'warmups_per_process':3,
            'sources':source_hashes,'workloads':input_hashes,
            'minimum_sample_target_ms':args.min_sample_ms,
            'loops':{name:loops for name,_,loops in workloads},
            'raw_samples':len(raw),'cases':rows}
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'raw.json').write_text(json.dumps(raw,indent=2)+'\n')
    for row in rows: print(row['case'],round(row['speedup_wall'],3),row['original']['wall_ns_op'],row['updated']['wall_ns_op'])
if __name__=='__main__': main()
