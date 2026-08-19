#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Deterministic parser fuzz: prefixes and random words must never alias commands."""
import random
import subprocess
import sys
from pathlib import Path

VMM = sys.argv[1] if len(sys.argv) > 1 else "bemu/bemu-nano"
IMAGE = sys.argv[2] if len(sys.argv) > 2 else "basmos-sh.bin"
module = Path(sys.argv[3] if len(sys.argv) > 3 else "jash/jash.bin").read_bytes()
pack = Path(sys.argv[4] if len(sys.argv) > 4 else "jash/jash-pack.bin").read_bytes()

invalid = [b"helpx", b"inform", b"surface", b"deck", b"jacket", b"themes",
           b"clears", b"word", b"maps", b"uname", b"uname -ax", b"uname -a ",
           b"probe x", b"why", b"why maps", b"whatif zero", b"whatif lab maps",
           b"diff zero", b"cannot", b"cannot cli", b"anatomies",
           b"byee", b"destroy", b"banana",
           b"x" * 79, b"y" * 80]
alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789_-"
random.seed(0xBA5)
for _ in range(20):
    invalid.append(bytes(random.choice(alphabet) for _ in range(random.randint(2, 24))))

valid = [b"uname -a", b"probe", b"why map", b"whatif zero map",
         b"whatif lab map", b"diff zero lab", b"cannot out", b"anatomy",
         b"info", b"bye"]
commands = b"\r".join(invalid + valid) + b"\r"
wire = b"r\x00" + module + b"x" + len(pack).to_bytes(2, "little") + pack + commands
result = subprocess.run([
    VMM, IMAGE, "--serial-hex", wire.hex(),
    "--serial-expect", "\r\n>", "--max-exits", "2000000",
], capture_output=True, timeout=30)

no_word = result.stdout.count(b"NO WORD")
ok = (result.returncode == 0 and no_word == len(invalid)
      and b"cpl 3" in result.stdout
      and b"[RUNTIME] cpu.vendor " in result.stdout
      and b"PRF1|ARTIFACT|JASH|253|3|FF" in result.stdout
      and b"saved user CS: monitor=0x1b module=0x2b" in result.stdout)
print(f"  [{'PASS' if no_word == len(invalid) else 'FAIL'}] "
      f"{len(invalid)} malformed words rejected exactly")
print(f"  [{'PASS' if result.returncode == 0 else 'FAIL'}] valid epistemic words survived fuzz stream")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
