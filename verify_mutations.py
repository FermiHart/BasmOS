#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Mutation gate: native proofctl must reject broken artifact invariants."""
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
PROOFCTL = str((ROOT / "tools/proofctl").resolve())
FILES = ["basmos.bin", "basmos-vm.bin", "basmos-sh.bin",
         "jash/jash.bin", "jash/jash-pack.bin"]


def refresh_manifest(root, relative):
    path = root / relative
    prefix = f"artifact={relative} bytes={path.stat().st_size} sha256="
    lines = (root / "ARTIFACTS.manifest").read_text(encoding="ascii").splitlines()
    replacement = prefix + hashlib.sha256(path.read_bytes()).hexdigest()
    lines = [replacement if line.startswith(prefix) else line for line in lines]
    (root / "ARTIFACTS.manifest").write_text("\n".join(lines) + "\n", encoding="ascii")


def rejected(name, relative, expected, mutate):
    with tempfile.TemporaryDirectory(prefix="basmos-mutation-") as directory:
        root = Path(directory)
        (root / "jash").mkdir()
        for artifact in FILES:
            shutil.copy2(ROOT / artifact, root / artifact)
        shutil.copy2(ROOT / "ARTIFACTS.manifest", root / "ARTIFACTS.manifest")
        mutate(root)
        refresh_manifest(root, relative)
        result = subprocess.run([PROOFCTL], cwd=root, capture_output=True, timeout=10)
        passed = result.returncode != 0 and expected.encode() in result.stderr
        print(f"  [{'PASS' if passed else 'FAIL'}] mutation rejected: {name}")
        if not passed:
            print(result.stderr.decode(errors="replace").strip(), file=sys.stderr)
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
    data[at + 12] ^= 8             # lab regains the visible map view
    path.write_bytes(data)


def mutate_identity(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    at = data.index(b"[RUNTIME] cpu.vendor")
    data[at + 1] = ord("X")
    path.write_bytes(data)


def mutate_command_target(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    data[108:112] = (0x230).to_bytes(4, "little")  # map points at cap_help
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


def mutate_sigil_root(root):
    path = root / "jash/jash-pack.bin"
    data = bytearray(path.read_bytes())
    at = data.rindex(b"SIG1")
    data[at + 6] ^= 1
    path.write_bytes(data)


checks = [
    rejected("boot signature", "basmos-sh.bin", "missing 55 aa",
             lambda root: flip(root / "basmos-sh.bin", 510, 0)),
    rejected("JASH native boundary", "jash/jash.bin", "JASH 255+1 boundary",
             lambda root: flip(root / "jash/jash.bin", 255, 0x90)),
    rejected("Surface rights", "jash/jash-pack.bin", "SFC1 entry", mutate_sfc),
    rejected("Deck composition", "jash/jash-pack.bin", "DCK1 entries", mutate_dck),
    rejected("identity provenance", "jash/jash-pack.bin", "identity provenance", mutate_identity),
    rejected("exact command target", "jash/jash-pack.bin", "word capability range", mutate_command_target),
    rejected("Evidence VM opcode", "jash/jash-pack.bin", "Evidence VM opcode", mutate_vm_opcode),
    rejected("Evidence VM manifest", "jash/jash-pack.bin", "EVM1 version/opcodes", mutate_vm_manifest),
    rejected("artifact-bound sigil root", "jash/jash-pack.bin", "SIG1 artifact root", mutate_sigil_root),
]
ok = all(checks)
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
