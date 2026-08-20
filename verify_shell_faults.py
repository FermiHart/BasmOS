#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Load hostile CPL3 modules and require a #GP fail-stop from module CS 0x2B."""
import re
import subprocess
import sys

VMM = sys.argv[1] if len(sys.argv) > 1 else "bemu/bemu-nano"
IMG = sys.argv[2] if len(sys.argv) > 2 else "basmos-sh.bin"
CASES = {
    "cli": bytes.fromhex("fa"),
    "out dx,al": bytes.fromhex("ee"),
    "mov ds,0x10": bytes.fromhex("66b810008ed8"),
}

ok = True
for name, module in CASES.items():
    stream = b"r" + bytes((len(module),)) + module + b"x"
    result = subprocess.run([
        VMM, IMG,
        "--serial-hex", stream.hex(),
        "--serial-expect", "NEVER",
        "--max-exits", "100000",
    ], capture_output=True, text=True, timeout=15)
    passed = (
        result.returncode == 1
        and "CRASH: guest halt with IF=0" in result.stderr
        and re.search(r"frame=[0-9a-f]{8}/[0-9a-f]{8}/0000002b/", result.stderr)
        and ">rx" in result.stdout
        and "triple fault" not in result.stderr
    )
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}: #GP fail-stop from module CS 0x2B")
    if not passed:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        ok = False

print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
