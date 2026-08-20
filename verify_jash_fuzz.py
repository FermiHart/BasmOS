#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Deterministic JASH parser fuzz: only fourteen exact words may dispatch."""

import random
import subprocess
import sys
from pathlib import Path


VMM = sys.argv[1] if len(sys.argv) > 1 else "bemu/bemu-nano"
IMAGE = sys.argv[2] if len(sys.argv) > 2 else "basmos-sh.bin"
MODULE = sys.argv[3] if len(sys.argv) > 3 else "jash/jash.bin"
PACK = sys.argv[4] if len(sys.argv) > 4 else "jash/jash-pack.bin"
module = Path(MODULE).read_bytes()
pack = Path(PACK).read_bytes()

invalid = [
    b"h", b"probe", b"why map", b"whatif lab map", b"helpx", b"surface",
    b"deck", b"jacket", b"palettes", b"clears", b"maps", b"uname",
    b"uname -ax", b"uname -a ", b"layouts", b"attested", b"limits ",
    b"sigils", b"anatomies", b"byee", b"destroy", b"banana",
    b"help\x00junk", b"helpX\x00", b"helpX\x08", b"x" * 79, b"y" * 80,
]
alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789_-"
random.seed(0xBA5)
for _ in range(20):
    invalid.append(bytes(random.choice(alphabet)
                         for _ in range(random.randint(2, 24))))

valid = [b"map", b"help", b"uname -a", b"sigil", b"layout", b"surfaces",
         b"decks", b"attest", b"palette", b"anatomy", b"clear", b"limits",
         b"jack", b"bye"]
# The PTY transport canonicalizes LF to CR, so fuzz uses the native CR ABI.
# DEL edits the final X; C0 BS remains a no-op and is rejected above.
commands = (b"\r".join(invalid) + b"\rmap\rhelpX\x7f\r"
             + b"\r".join(valid[2:]) + b"\r")
result = subprocess.run([
    VMM, IMAGE, "--jash", MODULE, PACK, "--max-exits", "2000000",
], input=commands, capture_output=True, timeout=30)

no_word = result.stdout.count(b"NO WORD")
ok = (result.returncode == 0 and no_word == len(invalid)
      and b"JASH/2030" in result.stdout
      and b"[RUNTIME] cpu.vendor " in result.stdout
      and b"PRF1|ARTIFACT|JASH|255|1|FF" in result.stdout)
print(f"  [{'PASS' if no_word == len(invalid) else 'FAIL'}] "
      f"malformed/control-bearing words rejected: got={no_word} want={len(invalid)}")
print(f"  [{'PASS' if result.returncode == 0 else 'FAIL'}] "
      "DEL editing and all fourteen canonical words survived the native CR stream")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
