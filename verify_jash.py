#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Load JASH through the monitor and verify its complete visible contract."""

import hashlib
import os
import pty
import re
import select
import struct
import subprocess
import sys
import time
from pathlib import Path


VMM = sys.argv[1] if len(sys.argv) > 1 else "bemu/bemu-nano"
IMAGE = sys.argv[2] if len(sys.argv) > 2 else "basmos-sh.bin"
MODULE = sys.argv[3] if len(sys.argv) > 3 else "jash/jash.bin"
PACK = sys.argv[4] if len(sys.argv) > 4 else "jash/jash-pack.bin"

module = Path(MODULE).read_bytes()
pack = Path(PACK).read_bytes()
shell = Path(IMAGE).read_bytes()
if len(module) != 256:
    raise SystemExit(f"FAIL: JASH nucleus must be exactly 256 bytes, got {len(module)}")
if not 1 <= len(pack) <= 3584:
    raise SystemExit(f"FAIL: J-Pack must use 1..3584 bytes, got {len(pack)}")


def manifest(magic, shape):
    try:
        at = pack.rindex(magic)
        count = pack[at + 4]
        return [struct.unpack_from(shape, pack, at + 5 + i * struct.calcsize(shape))
                for i in range(count)]
    except (ValueError, IndexError, struct.error):
        return []


surfaces = manifest(b"SFC1", "<BBHH")
decks = manifest(b"DCK1", "<BBBB")
root = hashlib.sha256(shell + module).digest()
braille = ["".join(chr(0x2800 + byte) for byte in root[row:row + 8])
           for row in (0, 8)]
sig_at = pack.rindex(b"SIG1")
sigil_root = pack[sig_at + 6:sig_at + 22]

# Six removed aliases/legacy pseudo-computations must fail. Every canonical word
# then executes once; help arrives as CRLF to prove LF is ignored safely.
commands = (b"destroy\rbanana\rh\rprobe\rwhy map\rwhatif lab map\r"
            b"help\r\nuname -a\rattest\rsigil\rlayout\rsurfaces\rdecks\r"
            b"map\rjack\rmap\rlimits\rpalette\ranatomy\rclear\rjack\rbye\r")
wire = b"?r\x00" + module + b"x" + len(pack).to_bytes(2, "little") + pack + commands
result = subprocess.run([
    VMM, IMAGE, "--serial-hex", wire.hex(), "--serial-expect", "\r\n>",
    "--max-exits", "1000000",
], capture_output=True, timeout=30)


def live_pty_contract():
    """The sigil must appear before input; then bytes map one-for-one."""
    master, slave = pty.openpty()
    process = subprocess.Popen([VMM, IMAGE, "--jash", MODULE, PACK],
                               stdin=slave, stdout=slave, stderr=slave,
                               close_fds=True)
    os.close(slave)
    transcript = b""

    def wait_for(marker, seconds=5):
        nonlocal transcript
        deadline = time.monotonic() + seconds
        while marker not in transcript and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    transcript += os.read(master, 65536)
                except OSError:
                    break
            if process.poll() is not None:
                break
        return marker in transcript

    try:
        booted = wait_for("NK-SIGIL/1".encode()) and wait_for(b"@nanokernel.org")
        os.write(master, b"decks\r")
        exact = wait_for(b"DECKS / DCK1") and b"decks" in transcript
        os.write(master, b"bye\r")
        returned = wait_for(b"JASH:EOT")
        return booted, exact and returned
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        os.close(master)


pty_boot, pty_input = live_pty_contract()
stdout = result.stdout
first_nl = stdout.find(b"\n")
summary = stdout.rfind(b"\n[bemu-nano] serial rx=")
serial = stdout[first_nl + 1:summary] if first_nl >= 0 and summary > first_nl else b""
escapes = re.findall(rb"\x1b\[[0-9;]* ?[mJHq]", serial)
residue = re.sub(rb"\x1b\[[0-9;]* ?[mJHq]", b"", serial)
illegal_escape = b"\x1b" in residue
text = residue.replace(b"\r\n", b"\n").decode("utf-8", "strict")
prf = [line for line in text.splitlines() if line.startswith("PRF1|")]
root_hex = root.hex()

checks = [
    (result.returncode == 0, "VMM completed the JASH contract"),
    (pty_boot, "PTY Wire reaches the sigil and prompt without an extra key"),
    (pty_input, "PTY Wire preserves commands and returns to the monitor"),
    (len(escapes) >= 8 and not illegal_escape, "ANSI stream uses only the admitted grammar"),
    (serial.startswith(b">?3rx\x1b[2J\x1b[H"), "JASH clears and homes before rendering"),
    ("NK-SIGIL/1" in text and all(row in text for row in braille)
     and "artifact-bound" in text,
     "artifact-bound sacred geometry renders root bytes dot-for-bit"),
    (sigil_root == root[:16] and root_hex in text,
     "SIG1 manifest and visible root match SHA256(shell||nucleus)"),
    ("jash@nanokernel.org:/zero# " in text
     and "jash@nanokernel.org:/lab# " in text,
     "Deck-aware nanokernel.org prompts rendered"),
    (b"\x1b[3 q" in serial, "terminal cursor is a native blinking underline"),
    ("JASH/2030 i686 BasmOS capsule cpl3" in text,
     "uname reports the real capsule boundary"),
    (re.search(r"\[RUNTIME\] cpu\.vendor [ -~]{12}", text)
     and "[ARTIFACT] segments cs=000000ff ds=00000fff iopl=0" in text,
     "attest measures CPU and segment state in CPL3"),
    (("[HASH] shell " + hashlib.sha256(shell).hexdigest()) in text
     and ("[HASH] jash " + hashlib.sha256(module).hexdigest()) in text,
     "attest binds the sibling kernel and nucleus to exact bytes"),
    ("PRF1|VIEW|MAP|ZERO|VISIBLE" in text
     and "PRF1|VIEW|MAP|LAB|MASKED" in text,
     "map SELECT follows the live Deck composition"),
    ("[ARTIFACT] nucleus=255 reserve=1" in text
     and "PRF1|ARTIFACT|JASH|255|1|FF" in text,
     "anatomy reports the complete native byte map"),
    (len(prf) == 4 and all(re.fullmatch(r"PRF1(?:\|[A-Z0-9=]+)+", line)
                            for line in prf),
     "every evidence frame is strictly bounded ASCII PRF1"),
    ("code     CS:RX / DS:RW-alias" in text
     and "facts    ConventionStable  physical=RW" in text,
     "Surface text states the real hardware aliases"),
    (surfaces == [(1, 3, 0, 1), (2, 2, 0, 1), (3, 3, 0, 4096),
                  (3, 7, 0, 256), (4, 3, 0, 1), (5, 0, 0, 0)],
     "binary Surface manifest matches rights/base/extent"),
    (decks == [(0, 1, 0, 0x1F), (1, 2, 1, 0x17)],
     "binary Deck manifest matches both live views"),
    ("JACKED lab" in text and "JACKED zero" in text,
     "Deck transitions are reversible state changes"),
    (text.count("NO WORD") == 6,
     "removed aliases and legacy canned commands are rejected exactly"),
    ("help      uname -a   attest     sigil" in text
     and "palette   anatomy    clear      jack       bye" in text,
     "all fourteen canonical commands are discoverable"),
    ("JASH:EOT\n>" in text, "bye returned from module CS to monitor CS"),
    (b"saved user CS: monitor=0x1b module=0x2b" in stdout,
     "KVM observed both user code selectors"),
]

ok = True
for passed, description in checks:
    print(f"  [{'PASS' if passed else 'FAIL'}] {description}")
    ok = ok and bool(passed)
if not ok:
    print("\n--- normalized serial ---")
    print(text)
    print("--- raw stdout ---")
    print(repr(stdout))
    if result.stderr:
        print(result.stderr.decode("utf-8", "replace"), file=sys.stderr)

print(f"JASH: nucleus={len(module)}B pack={len(pack)}B rx={len(wire)}B ansi={len(escapes)}")
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
