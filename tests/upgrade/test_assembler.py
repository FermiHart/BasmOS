#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Black-box contracts for BASM-NANO; no emulator or native boot claim.
Run with BASM_UNDER_TEST=/absolute/path ./test_assembler.py.
GNU as/objcopy are an independent encoding oracle, not a runtime oracle.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASM = Path(os.environ.get('BASM_UNDER_TEST', ROOT / 'build/upgrade/basm')).resolve()
ARTIFACTS = [
    ('basmos.basm', [], 512, '5b342405174202241bbc622d4fe1c94da367c8902f9a7a39cc9be211c79b74fe'),
    ('basmos.basm', ['-DBEMU_CONTRACT'], 232, 'd37945a20c188ecedc7102b62a2a0e21743c9eedab8be7f4ede5979d9d433fef'),
    ('basmos-sh.basm', [], 512, '4b92dfeebc951d718378b6b11ff97f6577be5d08a4239d1a5064297e638b76a7'),
    ('jash/jash.basm', [], 256, '3ed12f5d1d90d006522fab676e796441fb870e8b23083dfd6d1907f8693b536d'),
    ('jash/jash-pack.basm', [], 3584, '97789cb32d65251f9f748bd4efbb4e3c6a8c2a0aff6bc71abd31a9d72d61f3f0'),
]

class AssemblerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='basm-contract-')
        self.addCleanup(self.temp.cleanup)
        self.d = Path(self.temp.name)
        self.src, self.out = self.d/'in.basm', self.d/'out.bin'

    def run_basm(self, text, args=(), ok=True):
        self.src.write_bytes(text if isinstance(text, bytes) else text.encode())
        self.out.write_bytes(b'OLD-OUTPUT')
        p = subprocess.run([str(BASM), '-o', str(self.out), *args, str(self.src)],
                           capture_output=True, timeout=3)
        self.assertNotIn(b'runtime error:', p.stderr)
        self.assertNotIn(b'ERROR: AddressSanitizer', p.stderr)
        self.assertNotIn(b'ERROR: LeakSanitizer', p.stderr)
        self.assertGreaterEqual(p.returncode, 0, p.stderr.decode(errors='replace'))
        if ok:
            self.assertEqual(p.returncode, 0, p.stderr.decode(errors='replace'))
            return self.out.read_bytes()
        self.assertNotEqual(p.returncode, 0, repr(text))
        self.assertEqual(self.out.read_bytes(), b'OLD-OUTPUT')
        self.assertEqual(list(self.d.glob('*.tmp.*')), [])
        return p

    def test_instruction_regressions(self):
        cases = [
            ('BITS 32\ncmp eax,200\n', '3dc8000000'),
            ('BITS 32\ncmp ecx,200\n', '81f9c8000000'),
            ('BITS 32\ncmp eax,-56\n', '83f8c8'),
            ('BITS 32\ncmp eax,4294967295\n', '83f8ff'),
            ('BITS 16\nmov eax,ebx\n', '6689d8'),
            ('BITS 16\npushad\npopad\niretd\n', '6660666166cf'),
            ('BITS 16\ncall target\ntarget: ret\n', 'e80000c3'),
            ('BITS 16\njecxz target\ntarget: nop\n', '67e30090'),
            ('BITS 16\npush 200\n', '68c800'),
            ('BITS 32\nmov ecx,[eax+(2+3)*4]\n', '8b4814'),
            ('crc: mov eax,crc\n', 'b800000000'),
        ]
        for text, expected in cases:
            with self.subTest(text=text): self.assertEqual(self.run_basm(text).hex(), expected)

    def test_rejects_invalid_language(self):
        cases = [
            'db 1 garbage', '%ifdef X\ndb 7', 'cli 999', 'mov eax,cr9',
            'a:\na:\ndb 0', 'db (-9223372036854775807-1)*-1',
            'db 9223372036854775807+1', 'db -9223372036854775807-2',
            'db 9223372036854775808', 'db 3037000500*3037000500',
            'db -3037000500*3037000500', 'db -3037000500*-3037000500',
            'db 0x', 'BITS 32 junk', 'BITS 17', 'db 1,', 'db ,1', 'db 1,,2',
            'db "unterminated', 'db "ok"junk', 'db', 'mov eax,ebx,ecx',
            'mov ax,ebx', 'xor eax,al', 'test al,eax', 'cmp eax,ax',
            'mov cs,ax', 'mov ds,eax', 'mov ax,cr0', 'mov cr8,eax',
            'mov ecx,[eax]junk', 'mov eax,[ax]', 'mov eax,[eax*2]',
            'mov eax,[eax', 'mov eax,[]', 'mov eax,[eax+2147483648+2147483648]',
            'cmp eax,4294967296', 'BITS 16\npush 65536',
            '%else', '%endif', '%ifdef X\n%else\n%else\n%endif',
            '%ifdef X\n%endif junk', '%ifdef X\n%endifjunk', '%ifdef',
            '%ifdef X Y\n%endif', 'section .data', 'org -1',
            'org 0\norg 0', 'db 0\norg 1', 'a: org 0',
            'times 999999999999 db 0', 'times -1 db 0', 'times 65537 db 0',
            'times n db 0\nn: db 0', 'times 2 dw 0', 'times 2 db 0 junk',
            '.x: db 0', 'a-b: db 0', 'a'*128+': db 0',
            'db '+'('*70+'1'+')'*70, 'db '+'-'*70+'1',
            '%ifdef X\n'*17+'%endif\n'*17,
            'jmp missing', 'jmp faraway\ntimes 128 db 0\nfaraway: nop',
            'BITS 16\njmp 65536:0', 'BITS 16\njmp 0:65536',
        ]
        for text in cases:
            with self.subTest(text=text[:100]): self.run_basm(text+'\n', ok=False)

    def test_limits_and_two_pass_layout(self):
        self.assertEqual(len(self.run_basm('times 65536 db 7\n')), 65536)
        self.run_basm('times 65536 db 7\ndb 1\n', ok=False)
        text = ''.join(f'label{i}: db {i}\n' for i in range(256))
        self.assertEqual(len(self.run_basm(text)), 256)
        self.run_basm(text+'last: db 0\n', ok=False)
        text = 'cmp eax,target\nmov ecx,[eax+target]\npush target\ntarget: nop\n'
        data = self.run_basm(text)
        self.assertEqual(len(data), 17)
        self.assertEqual(data.hex(), '3d100000008b8810000000681000000090')
        # No BITS directive initially: both passes must start in 32-bit mode.
        self.assertEqual(self.run_basm('mov eax,ebx\nBITS 16\n').hex(), '89d8')
        self.run_basm(b'db 0\x00db 99\n', ok=False)
        self.run_basm(b';'+b' '*1024+b'\n', ok=False)
        self.run_basm(b';\n'*(524288+1), ok=False)
        # Accepted truncation is deliberate for data and low-byte immediates.
        self.assertEqual(self.run_basm('db 256,-1\ndw 65536\ndd -1\n').hex(), '00ff0000ffffffff')

    def test_preprocessor_and_strings(self):
        text = '%ifdef X\r\n db 1\r\n%else\r\n db 2\r\n%endif \r\n'
        self.assertEqual(self.run_basm(text), b'\x02')
        self.assertEqual(self.run_basm(text, ['-DX']), b'\x01')
        text='%ifdef X\n%ifdef Y\ndb 1\n%else\ndb 2\n%endif\n%else\ndb 3\n%endif\n'
        for defs, want in [([],3),(['-DY'],3),(['-DX'],2),(['-DX','-DY'],1)]:
            self.assertEqual(self.run_basm(text, defs), bytes([want]))
        self.assertEqual(self.run_basm('db "α;β", 0 ; outside comment\n'), 'α;β'.encode()+b'\0')
        self.assertEqual(self.run_basm('times\t3\tdb\t255\n'), b'\xff'*3)

    def test_optimized_lexer_boundaries(self):
        # Fast numeric paths must retain the same grammar and checked range.
        values = [0, 9, 10, 127, 128, 255, 256, 65535, 65536,
                  2147483647, 4294967295, 9223372036854775807]
        for value in values:
            for spelling in [str(value), hex(value), '0X'+format(value, 'X')]:
                with self.subTest(literal=spelling):
                    expected = (value & 0xffffffff).to_bytes(4, 'little')
                    self.assertEqual(self.run_basm('dd '+spelling), expected)
        self.assertEqual(self.run_basm('db 2+3*4, (2+3)*4, 20-2*3\n'), bytes([14,20,14]))
        self.assertEqual(self.run_basm('db '+'('*63+'1'+')'*63), b'\1')
        for text in ['db '+'('*64+'1'+')'*64, 'db 0x8000000000000000',
                     'db 0X', 'db 10x', 'db 1e2', 'db 0x1g',
                     'mov eal,al', 'mov eaxx,eax', 'mov e,eax',
                     'mov eax,e', 'mov eax,spx', 'mov eax,sx',
                     'n', 'nopx', 'pushadx', 'jecx', 'movx eax,ebx']:
            with self.subTest(rejected=text): self.run_basm(text, ok=False)
        # Exact line bound, semicolons inside strings, CRLF, multiple labels,
        # label-only lines and a last line with no newline exercise the lexer.
        self.assertEqual(self.run_basm('a: .b: db "a;b",39 ; outside\r\nc:\n ret'), b"a;b'\xc3")
        self.assertEqual(self.run_basm(';'+'x'*1022), b'')
        self.run_basm(';'+'x'*1023, ok=False)
        self.assertEqual(len(self.run_basm('db "'+'x'*1018+'"')), 1018)
        self.run_basm('db "'+'x'*1019+'"', ok=False)
        # Batched word/dword writes validate the entire remaining output span.
        for width, directive in [(2,'dw'),(4,'dd')]:
            with self.subTest(width=width):
                data=self.run_basm(f'times {65536-width} db 0\n{directive} 0x1234')
                self.assertEqual(len(data),65536)
                self.assertEqual(data[-width:],(0x1234).to_bytes(width,'little'))
                self.run_basm(f'times {65537-width} db 0\n{directive} 0x1234',ok=False)

    def test_cli_and_publication(self):
        for args in [['-D'], ['-D'+'A'*128], ['--unknown'], ['-f','elf'], [str(self.d/'other')]]:
            with self.subTest(args=args): self.run_basm('db 1\n', args, ok=False)
        self.run_basm('db 1\n', ['-o', str(self.src)], ok=False)
        self.assertEqual(self.src.read_bytes(), b'db 1\n')
        os.link(self.src, self.d/'alias')
        self.run_basm('db 1\n', ['--map', str(self.d/'alias')], ok=False)
        (self.d/'link').symlink_to(self.out)
        self.run_basm('db 1\n', ['--map',str(self.d/'link')], ok=False)
        self.run_basm('db 1\n', ['--map',str(self.d/'./out.bin')], ok=False)
        self.run_basm('db 1\n', ['--map',str(self.d/'absent'/'map')], ok=False)
        self.run_basm('db 1\n', ['--map',str(self.d)], ok=False)
        if Path('/dev/full').exists(): self.run_basm('db 1\n', ['--map','/dev/full'], ok=False)
        os.mkfifo(self.d/'fifo')
        p=subprocess.run([str(BASM),'-o',str(self.out),str(self.d/'fifo')],capture_output=True,timeout=3)
        self.assertNotEqual(p.returncode,0)
        # Map failure must never replace an existing binary.
        map_path=self.d/'map'
        data=self.run_basm('a: db 1\n.local: db 2\nb: db 3\n', ['--map',str(map_path)])
        self.assertEqual(data,b'\1\2\3')
        self.assertEqual(map_path.read_text(), '     0      2 a\n     2      1 b\n')
        self.assertEqual(list(self.d.glob('*.tmp.*')), [])

    def test_late_write_failure(self):
        # Force a real flush failure after a successful buffered fwrite.
        import resource
        import signal
        def limits():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64,64))
        self.src.write_text('times 256 db 0\n')
        self.out.write_bytes(b'OLD-OUTPUT')
        p=subprocess.run([str(BASM),'-o',str(self.out),str(self.src)],
                         preexec_fn=limits,capture_output=True,timeout=3)
        self.assertEqual(p.returncode,1,p.stderr.decode(errors='replace'))
        self.assertIn(b'cannot finish output',p.stderr)
        self.assertEqual(self.out.read_bytes(),b'OLD-OUTPUT')
        self.assertEqual(list(self.d.glob('*.tmp.*')),[])

    def test_artifact_identity(self):
        for name, flags, size, sha in ARTIFACTS:
            with self.subTest(artifact=name,flags=flags):
                data=self.run_basm((ROOT/name).read_bytes(), flags)
                self.assertEqual(len(data),size)
                self.assertEqual(hashlib.sha256(data).hexdigest(),sha)

    @unittest.skipUnless(shutil.which('as') and shutil.which('objcopy'), 'GNU binutils oracle unavailable')
    def test_independent_gnu_oracle(self):
        # Deliberately stay inside the documented no-index operand subset.
        r32=['eax','ecx','edx','ebx','esp','ebp','esi','edi']
        r16=['ax','cx','dx','bx','sp','bp','si','di']
        r8=['al','cl','dl','bl','ah','ch','dh','bh']
        segments = []
        for bits in [16,32]:
            nano, gas = [], []
            def add(line, equivalent=None):
                nano.append(line); gas.append(equivalent or line)
            for regs in [r8,r16,r32]:
                for i,a in enumerate(regs):
                    for b in regs:
                        for op in ['mov','xor','cmp','test']: add(f'{op} {a},{b}')
                    add(f'inc {a}'); add(f'dec {a}')
                    add(f'mov {a},17')
            for r in r32:
                for imm in [-2147483648,-129,-128,-1,0,127,128,200,2147483647,4294967295]:
                    add(f'cmp {r},{imm}')
                for base in r32:
                    for disp in [-129,-128,0,127,128,4096]:
                        add(f'mov {r},[{base}+({disp})]')
            for mem in ['[1234]','[eax]','[esp+127]','[ebp-128]']:
                for size in ['byte','word','dword']:
                    add(f'mov {size} {mem},17',f'mov {size} ptr {mem},17')
            for line in ['cli','cld','sti','hlt','nop','ret','lodsb','lodsw','pushad','popad','iretd']:
                add(line)
            for imm in [-129,-128,-1,0,127,128,200,32000]: add(f'push {imm}')
            add('call target'); add('jecxz target'); add('target: nop')
            segments.append((bits,nano,gas))
        for bits,nano,gas in segments:
            with self.subTest(bits=bits):
                actual=self.run_basm(f'BITS {bits}\n'+'\n'.join(nano)+'\n')
                s=self.d/'oracle.s'; obj=self.d/'oracle.o'; flat=self.d/'oracle.bin'
                s.write_text('.intel_syntax noprefix\n'+f'.code{bits}\n'+'\n'.join(gas)+'\n')
                p=subprocess.run(['as','--32','-o',str(obj),str(s)],capture_output=True,timeout=3)
                self.assertEqual(p.returncode,0,p.stderr.decode())
                subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(flat)],check=True,timeout=3)
                expected=flat.read_bytes()
                # Both orders of independent operand/address prefixes have the
                # same semantics; canonicalize this one difference explicitly.
                self.assertEqual(actual.replace(b'\x66\x67',b'\x67\x66'),expected)
        print('GNU encoding oracle:',sum(len(n) for _,n,_ in segments),'statements')

    def test_deterministic_input_mutations(self):
        rng=random.Random(20260926)
        seeds=['mov eax,[ebp+127]\n', 'cmp eax,200\n', '%ifdef X\ndb 1\n%endif\n',
               'times 10 db 0\n','a: db "hello",1\njmp a\n','db (2+3)*4\n']
        for case in range(400):
            text=bytearray(rng.choice(seeds).encode())
            for _ in range(rng.randint(1,4)):
                pos=rng.randrange(len(text)+1)
                if rng.randrange(2) and pos<len(text): text[pos]=rng.randrange(128)
                else: text[pos:pos]=bytes([rng.randrange(128)])
            self.src.write_bytes(text); self.out.write_bytes(b'unchanged')
            p=subprocess.run([str(BASM),'-o',str(self.out),str(self.src)],capture_output=True,timeout=3)
            with self.subTest(case=case):
                self.assertIn(p.returncode,[0,1],p.stderr.decode(errors='replace'))
                self.assertNotIn(b'runtime error:',p.stderr)
                self.assertNotIn(b'ERROR: AddressSanitizer',p.stderr)
                if p.returncode: self.assertEqual(self.out.read_bytes(),b'unchanged')
                else: self.assertLessEqual(self.out.stat().st_size,65536)

if __name__=='__main__':
    class Result(unittest.TextTestResult):
        subcases = 0
        def addSubTest(self, test, subtest, err):
            self.subcases += 1
            super().addSubTest(test, subtest, err)
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(AssemblerTests))
    report = {'status':'PASS' if result.wasSuccessful() and not result.skipped else 'FAIL',
              'test_methods':result.testsRun, 'subcases':result.subcases,
              'failures':len(result.failures), 'errors':len(result.errors),
              'skipped':len(result.skipped), 'encoding_statements':2676,
              'mutation_inputs':400, 'artifact_variants':5}
    if os.environ.get('BASM_TEST_REPORT'):
        Path(os.environ['BASM_TEST_REPORT']).write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if report['status']=='PASS' else 1)
