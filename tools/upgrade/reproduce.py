#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Before/after reproductions against the preserved BSD upstream reference."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
CASES=[
 ('signed_cmp','BITS 32\ncmp eax,200\n','3dc8000000'),
 ('operand_width','BITS 16\nmov eax,ebx\n','6689d8'),
 ('trailing_data','db 1 garbage\n',None),
 ('conditional_eof','%ifdef X\ndb 7\n',None),
 ('operand_ignored','cli 999\n',None),
 ('control_register','mov eax,cr9\n',None),
 ('duplicate_label','a:\na:\ndb 0\n',None),
 ('signed_overflow','db (-9223372036854775807-1)*-1\n',None),
 ('first_pass_budget','times 999999999999 db 0\n',None),
 ('push_width','BITS 16\npush 200\n','68c800'),
 ('counter_width','BITS 16\njecxz a\na: nop\n','67e30090'),
 ('embedded_nul','db 1\x00db 2\n',None),
]
def run(binary,text,d,extra=(),timeout=2):
    source=d/'input'; output=d/'output'; source.write_bytes(text.encode()); output.write_bytes(b'OLD')
    try:
        p=subprocess.run([str(binary),'-o',str(output),*extra,str(source)],capture_output=True,timeout=timeout)
        return dict(returncode=p.returncode,stderr=p.stderr.decode(errors='replace'),output=output.read_bytes().hex())
    except subprocess.TimeoutExpired:
        return dict(returncode='TIMEOUT',output=output.read_bytes().hex())
def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('--out',type=Path,default=ROOT/'build/upgrade/reproductions'); a=ap.parse_args()
    out=a.out.resolve(); out.mkdir(parents=True,exist_ok=True)
    binaries={}
    for name,source in [('original',ROOT/'tests/upgrade/reference/basm_nano.c'),('updated',ROOT/'basm-nano/basm_nano.c')]:
        binaries[name]=out/name
        cmd=['gcc','-std=c11','-O2',str(source),'-o',str(binaries[name])]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        (out/(name+'-build.log')).write_text('$ '+' '.join(cmd)+'\n'+p.stdout+p.stderr)
        if p.returncode: raise RuntimeError(p.stderr)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='basm-reproduce-') as t:
        d=Path(t)
        for name,text,expected in CASES:
            row={'name':name,'input':text,'expected_updated_hex':expected}
            for variant,binary in binaries.items(): row[variant]=run(binary,text,d,timeout=0.5 if name=='first_pass_budget' else 2)
            actual=row['updated']
            if expected is not None:
                assert actual['returncode']==0 and actual['output']==expected,row
            else:
                assert isinstance(actual['returncode'],int) and actual['returncode']!=0 and actual['output']==b'OLD'.hex(),row
            rows.append(row)
        if Path('/dev/full').exists():
            row={'name':'write_failure'}
            for variant,binary in binaries.items(): row[variant]=run(binary,'db 1\n',d,['-o','/dev/full'])
            assert row['original']['returncode']==0 and row['updated']['returncode']!=0,row
            rows.append(row)
        # Deliberately only a disposable input; never test alias writes in the repository.
        row={'name':'source_output_alias'}
        for variant,binary in binaries.items():
            result=run(binary,'db 1\n',d,['-o',str(d/'input')]); result['input_after']=(d/'input').read_bytes().hex();row[variant]=result
        assert row['original']['input_after']=='01' and row['updated']['input_after']==b'db 1\n'.hex(),row
        rows.append(row)
        ubsan=out/'original-ubsan'
        subprocess.run(['gcc','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=undefined',str(ROOT/'tests/upgrade/reference/basm_nano.c'),'-o',str(ubsan)],check=True,timeout=30)
        proof=run(ubsan,'db (-9223372036854775807-1)*-1\n',d)
        assert 'runtime error:' in proof['stderr'],proof
    result={'status':'PASS','cases':rows,'original_undefined_behavior':proof}
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(len(rows),'before/after reproductions PASS')
if __name__=='__main__': main()
