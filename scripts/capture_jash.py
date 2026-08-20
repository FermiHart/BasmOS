#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Capture, normalize and render the real JASH KVM session."""

import argparse
import hashlib
import html
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
COMMANDS = EVIDENCE / "jash-session.commands"
RAW = EVIDENCE / "jash-session.ansi"
TEXT = EVIDENCE / "jash-session.txt"
MANIFEST = EVIDENCE / "jash-session.manifest"
SVG = ROOT / "website" / "jash-live.svg"
SHELL = ROOT / "basmos-sh.bin"
MODULE = ROOT / "jash" / "jash.bin"
PACK = ROOT / "jash" / "jash-pack.bin"
VMM = ROOT / "bemu" / "bemu-nano"
ANSI = re.compile(rb"\x1b\[[0-9;]* ?[mJHq]")

COMMAND_BYTES = (
    b"uname -a\r"
    b"attest\r"
    b"map\r"
    b"jack\r"
    b"map\r"
    b"surfaces\r"
    b"anatomy\r"
    b"bye\r"
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize(raw):
    if not raw.startswith(b"\x1b[2J\x1b[H"):
        raise RuntimeError("capture did not begin with clear/home")
    residue = ANSI.sub(b"", raw)
    if b"\x1b" in residue:
        raise RuntimeError("capture contains unsupported ANSI")
    residue = residue.replace(b"\r\n", b"\n")
    residue, count = re.subn(
        rb"(?m)^(\[RUNTIME\] cpu\.vendor )[ -~]{12}$",
        rb"\1<CPUID-VENDOR>", residue)
    if count != 1:
        raise RuntimeError("capture has no unique CPUID vendor field")
    return residue.decode("utf-8", "strict")


def validate(text):
    root = hashlib.sha256(SHELL.read_bytes() + MODULE.read_bytes()).hexdigest()
    root_bytes = bytes.fromhex(root)
    braille = ["".join(chr(0x2800 + byte) for byte in root_bytes[row:row + 8])
               for row in (0, 8)]
    required = [
        "NK-SIGIL/1", *braille,
        "jash@nanokernel.org:/zero# uname -a",
        "jash@nanokernel.org:/zero# attest",
        "[ROOT] sha256(shell||nucleus) " + root,
        "[HASH] shell " + sha(SHELL),
        "[HASH] jash " + sha(MODULE),
        "PRF1|VIEW|MAP|ZERO|VISIBLE",
        "jash@nanokernel.org:/zero# jack",
        "jash@nanokernel.org:/lab# map",
        "PRF1|VIEW|MAP|LAB|MASKED",
        "code     CS:RX / DS:RW-alias extent=256",
        "PRF1|ARTIFACT|JASH|255|1|FF",
        "JASH:EOT\n>",
    ]
    missing = [item for item in required if item not in text]
    if missing:
        raise RuntimeError("capture contract missing: " + repr(missing))


def capture():
    result = subprocess.run(
        [str(VMM), str(SHELL), "--jash", str(MODULE), str(PACK)],
        input=COMMAND_BYTES, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace"))
    text = normalize(result.stdout)
    validate(text)
    return result.stdout, text


def render_svg(text):
    lines = text.rstrip("\n").splitlines()
    width = 1320
    line_height = 20
    height = 76 + line_height * len(lines)

    def color(line):
        if "NK-SIGIL" in line or any("\u2800" <= ch <= "\u28ff" for ch in line) \
                or any(ch in line for ch in "∞◈◇"):
            return "#cf7dff"
        if "jash@nanokernel.org" in line or line.startswith("[READY]"):
            return "#46ff7d"
        if line.startswith(("[RUNTIME]", "[ROOT]")):
            return "#38d9ff"
        if line.startswith(("[ARTIFACT]", "[HASH]", "PRF1|")):
            return "#ffe45c"
        if line.startswith(("MASKED", "NO WORD")):
            return "#ff6262"
        return "#b8d8b8"

    body = []
    for index, line in enumerate(lines):
        body.append(
            f'<text x="34" y="{58 + index * line_height}" '
            f'fill="{color(line)}">{html.escape(line)}</text>')
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="1320" '
        f'height="{height}" viewBox="0 0 {width} {height}" role="img" '
        'aria-labelledby="title desc">\n'
        '<title id="title">Verified JASH live session</title>\n'
        '<desc id="desc">A KVM transcript showing the artifact-bound sigil, '
        'attestation, Deck transition, surfaces and return to the monitor.</desc>\n'
        '<rect width="100%" height="100%" rx="12" fill="#020402"/>\n'
        '<rect x="1" y="1" width="1318" height="34" rx="11" fill="#0b100b" '
        'stroke="#263426"/>\n'
        '<circle cx="20" cy="18" r="5" fill="#46ff7d"/>\n'
        '<text x="34" y="23" fill="#789578">JASH LIVE / KVM / CPL3 / VERIFIED TRANSCRIPT</text>\n'
        '<g font-family="ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace" '
        'font-size="14" xml:space="preserve">\n'
        + "\n".join(body) +
        '\n</g>\n</svg>\n')


def manifest_text():
    paths = [SHELL, MODULE, PACK, COMMANDS, RAW, TEXT, SVG]
    return "".join(f"{sha(path)}  {path.relative_to(ROOT)}\n" for path in paths)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true",
                        help="replace the committed capture evidence")
    args = parser.parse_args()
    raw, text = capture()
    svg = render_svg(text)

    if args.update:
        COMMANDS.write_bytes(COMMAND_BYTES.replace(b"\r", b"\n"))
        RAW.write_bytes(raw)
        TEXT.write_text(text, encoding="utf-8")
        SVG.write_text(svg, encoding="utf-8")
        MANIFEST.write_text(manifest_text(), encoding="ascii")
        print("updated JASH ANSI/text/SVG capture and manifest")
        return 0

    expected = {
        COMMANDS: COMMAND_BYTES.replace(b"\r", b"\n"),
        TEXT: text.encode("utf-8"),
        SVG: svg.encode("utf-8"),
    }
    for path, value in expected.items():
        if not path.exists() or path.read_bytes() != value:
            print(f"FAIL: stale JASH capture derivative: {path.relative_to(ROOT)}",
                  file=sys.stderr)
            return 1
    normalized = normalize(RAW.read_bytes())
    if normalized != text:
        print("FAIL: committed ANSI capture does not normalize to the transcript",
              file=sys.stderr)
        return 1
    validate(normalized)
    if MANIFEST.read_text(encoding="ascii") != manifest_text():
        print("FAIL: stale JASH capture manifest", file=sys.stderr)
        return 1
    print("RESULT: PASS - live JASH capture, artifacts, transcript and SVG agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
