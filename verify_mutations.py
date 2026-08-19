#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Mutation gate: native proofctl must reject broken artifact invariants."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
PROOFCTL = str((ROOT / "tools/proofctl").resolve())
FILES = ["basmos.bin", "basmos-vm.bin", "basmos-sh.bin",
         "jash/jash.bin", "jash/jash-pack.bin"]


def rejected(name, mutate):
    with tempfile.TemporaryDirectory(prefix="basmos-mutation-") as directory:
        root = Path(directory)
        (root / "jash").mkdir()
        for relative in FILES:
            shutil.copy2(ROOT / relative, root / relative)
        mutate(root)
        result = subprocess.run([PROOFCTL], cwd=root, capture_output=True, timeout=10)
        passed = result.returncode != 0
        print(f"  [{'PASS' if passed else 'FAIL'}] mutation rejected: {name}")
        return passed


def flip(path, offset, value):
    data = bytearray(path.read_bytes())
    data[offset] = value
    path.write_bytes(data)


def mutate_sfc(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    at = data.rindex(b"SFC1")
    data[at + 6] ^= 1              # wire0 rights
    path.write_bytes(data)


def mutate_dck(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    at = data.rindex(b"DCK1")
    data[at + 12] ^= 8             # lab regains code.read
    path.write_bytes(data)


def mutate_identity(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    at = data.index(b"[RUNTIME] cpu.vendor")
    data[at + 1] = ord("X")
    path.write_bytes(data)


def mutate_capability_alias(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    data[132:136] = (0x230).to_bytes(4, "little")  # valid cap_help, wrong alias
    path.write_bytes(data)


def mutate_vm_opcode(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    data[44] = 4
    path.write_bytes(data)


def mutate_vm_manifest(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    at = data.rindex(b"EVM1")
    data[at + 4] = 2
    path.write_bytes(data)


def mutate_model_proof(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    at = data.index(b"PRF1|MODEL|MAP|08|17|DENY")
    data[at + 23] = ord("A")
    path.write_bytes(data)


checks = [
    rejected("boot signature", lambda root: flip(root / "basmos-sh.bin", 510, 0)),
    rejected("JASH native boundary", lambda root: flip(root / "jash/jash.bin", 255, 0x90)),
    rejected("Surface rights", mutate_sfc),
    rejected("Deck attenuation", mutate_dck),
    rejected("identity provenance", mutate_identity),
    rejected("shared capability alias", mutate_capability_alias),
    rejected("Evidence VM opcode", mutate_vm_opcode),
    rejected("Evidence VM manifest", mutate_vm_manifest),
    rejected("counterfactual proof", mutate_model_proof),
]
ok = all(checks)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
