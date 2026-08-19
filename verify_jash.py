#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Load JASH through the immutable monitor and verify its visible contract."""
import re
import hashlib
import struct
import subprocess
import sys
import os
import pty
import select
import time
from pathlib import Path

VMM = sys.argv[1] if len(sys.argv) > 1 else "bemu/bemu-nano"
IMAGE = sys.argv[2] if len(sys.argv) > 2 else "basmos-sh.bin"
MODULE = sys.argv[3] if len(sys.argv) > 3 else "jash/jash.bin"
PACK = sys.argv[4] if len(sys.argv) > 4 else "jash/jash-pack.bin"

try:
    module = Path(MODULE).read_bytes()
    pack = Path(PACK).read_bytes()
except OSError as error:
    print(f"FAIL: {error}", file=sys.stderr)
    sys.exit(1)

if len(module) != 256:
    print(f"FAIL: JASH nucleus must be exactly 256 bytes, got {len(module)}", file=sys.stderr)
    sys.exit(1)
if not 1 <= len(pack) <= 3072:
    print(f"FAIL: J-Pack must use 1..3072 bytes, got {len(pack)}", file=sys.stderr)
    sys.exit(1)

try:
    surface_at = pack.rindex(b"SFC1")
    surface_count = pack[surface_at + 4]
    surfaces = [struct.unpack_from("<BBHH", pack, surface_at + 5 + i * 6)
                for i in range(surface_count)]
    deck_at = pack.rindex(b"DCK1")
    deck_count = pack[deck_at + 4]
    decks = [struct.unpack_from("<BBBB", pack, deck_at + 5 + i * 4)
             for i in range(deck_count)]
except (ValueError, IndexError, struct.error):
    surfaces, decks = [], []

commands = (b"destroy\rbanana\runame -a\rprobe\rwhy map\rwhatif zero map\r"
            b"whatif lab map\rdiff zero lab\rcannot out\ranatomy\rinfo\r"
            b"surfaces\rdecks\rjack\rinfo\rwhy map\rmap\rjack\rmap\r"
            b"theme\rclear\rhelp\rbye\r")
wire = b"?r\x00" + module + b"x" + len(pack).to_bytes(2, "little") + pack + commands
expect = "\r\n>"              # reset ANSI may sit between JASH:EOT and CRLF
result = subprocess.run([
    VMM, IMAGE,
    "--serial-hex", wire.hex(),
    "--serial-expect", expect,
    "--max-exits", "1000000",
], capture_output=True, timeout=30)


def live_pty_contract():
    """The banner must appear before input; then bytes must map one-for-one."""
    master, slave = pty.openpty()
    process = subprocess.Popen([
        VMM, IMAGE, "--jash", MODULE, PACK,
    ], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
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
        booted_without_input = wait_for(b"kernel SEALED") and wait_for(b"jash")
        os.write(master, b"decks\r")
        input_exact = wait_for(b"DECKS") and b"decks" in transcript
        os.write(master, b"bye\r")
        returned = wait_for(b"JASH:EOT")
        return booted_without_input, input_exact and returned
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
        os.close(master)


pty_boot, pty_input = live_pty_contract()

stdout = result.stdout
first_nl = stdout.find(b"\n")
summary = stdout.rfind(b"\n[bemu-nano] serial rx=")
serial = stdout[first_nl + 1:summary] if first_nl >= 0 and summary > first_nl else b""

# JASH deliberately uses only SGR colors plus clear/home. Anything else is a
# protocol change, not decoration that the verifier may silently discard.
escapes = re.findall(rb"\x1b\[[0-9;]* ?[mJHq]", serial)
residue = re.sub(rb"\x1b\[[0-9;]* ?[mJHq]", b"", serial)
illegal_escape = b"\x1b" in residue
text = residue.replace(b"\r\n", b"\n").decode("ascii", "strict")
prf = [line for line in text.splitlines() if line.startswith("PRF1|")]

checks = [
    (result.returncode == 0, "VMM completed the JASH contract"),
    (pty_boot, "PTY Wire reaches the prompt without an extra key"),
    (pty_input, "PTY Wire preserves keys and responds without polling lag"),
    (len(escapes) >= 8 and not illegal_escape, "ANSI color/clear stream is valid"),
    (serial.startswith(b">?3rx\x1b[2J\x1b[H"), "JASH clears and homes before rendering"),
    ("CAPSULE LINK" in text and "6 TYPED SURFACES" in text
     and "DECK ZERO" in text and "WIRE COM1/INT80" in text,
     "cinematic boot frame names every live boundary"),
    ("jash@basmos.org:/# " in text, "exact spaced JASH prompt rendered"),
    (b"\x1b[3 q" in serial, "terminal cursor is a native blinking underline"),
    ("cpl 3" in text and "cs 002b" in text and "kernel sealed" in text,
     "info reports the real capsule boundary"),
    (re.search(r"\[RUNTIME\] cpu\.vendor [ -~]{12}", text)
     and "[RUNTIME] privilege cpl=3 cs=002b" in text
     and "[ARTIFACT] iopl=0 limits cs=000000ff ds=00000fff" in text,
     "uname -a measures CPU and capsule boundaries in CPL3"),
    ("[ARTIFACT] kernel basmos-sh.bin 512B SEALED" in text
     and "[ARTIFACT] nucleus jash.bin 256B RX; pack DATA/NX" in text
     and "[PROOF] required BASM+QEMU+KVM+PTY+browser" in text,
     "uname -a separates runtime, artifact and proof provenance"),
    (("[PROOF] shell.sha256 " + hashlib.sha256(Path(IMAGE).read_bytes()).hexdigest()) in text
     and ("[PROOF] jash.sha256 " + hashlib.sha256(module).hexdigest()) in text,
     "uname -a binds its kernel and nucleus claims to exact bytes"),
    (text.count("[RUNTIME] cpu.vendor ") == 2,
     "probe and uname -a share the same measured identity capability"),
    (text.count("PRF1|POLICY|MAP|08|1F|ALLOW") == 2
     and text.count("PRF1|POLICY|MAP|08|17|DENY") == 2,
     "why map and map consume one immutable SELECT capability"),
    ("PRF1|MODEL|MAP|08|1F|ALLOW" in text
     and "PRF1|MODEL|MAP|08|17|DENY" in text
     and text.count("state.changed=no") == 2,
     "whatif proves both Deck outcomes without changing state"),
    ("PRF1|MODEL|DECKDIFF|1F|17|08" in text
     and "affected map,why map" in text,
     "diff derives the exact authority delta and affected words"),
    ("[DERIVED] cannot out" in text
     and "[EXTERNAL] hostile/out PASS" in text
     and "PRF1|EXTERNAL|OUT|3|0|GP13" in text,
     "cannot distinguishes derivation from the external fault oracle"),
    ("[ARTIFACT] anatomy" in text
     and "PRF1|ARTIFACT|JASH|253|3|FF" in text,
     "anatomy reports the measured native byte budget"),
    (len(prf) == 9 and all(re.fullmatch(r"PRF1(?:\|[A-Z0-9=]+)+", line)
                           for line in prf),
     "every epistemic frame is strictly bounded ASCII PRF1"),
    ("wire0 Duplex<Byte>" in text and "glyph0 Sink<Glyph>" in text
     and "arena Region<RW,4096>" in text, "typed Surfaces are visible"),
    (surfaces == [(1, 3, 0, 1), (2, 2, 0, 1), (3, 3, 0, 4096),
                  (3, 5, 0, 256), (4, 1, 0, 1), (5, 0, 0, 0)],
     "binary Surface manifest matches kind/rights/base/extent"),
    ("* zero LIVE" in text and "lab READY" in text, "Deck inventory rendered"),
    (decks == [(0, 1, 0, 0x1F), (1, 2, 1, 0x17)],
     "binary Deck manifest carries state/theme/Surface masks"),
    ("JACKED lab" in text and "deck lab" in text, "Deck transition changes state"),
    ("DENIED requires code.read deck lab" in text
     and text.count("000..0ff nucleus RX") == 2,
     "Deck Surface mask denies map in lab and restores it in zero"),
    (text.count("NO WORD") == 2 and "destroy\nDECKS" not in text,
     "dispatch requires complete words, never first-letter aliases by accident"),
    ("why map" in text and "whatif zero map" in text and "cannot out" in text,
     "discoverable command vocabulary rendered"),
    ("JASH:EOT\n>" in text, "bye returned from module CS to monitor CS"),
    (b"saved user CS: monitor=0x1b module=0x2b" in stdout,
     "KVM observed both user code selectors"),
]

ok = True
for passed, description in checks:
    print(f"  [{'PASS' if passed else 'FAIL'}] {description}")
    ok = ok and passed
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
