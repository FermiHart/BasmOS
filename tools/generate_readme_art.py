#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate artifact-bound SVGs used by the GitHub README."""

import argparse
import hashlib
import math
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "readme"
MANIFEST = ROOT / "ARTIFACTS.manifest"
PALETTE = ["#65fbd2", "#ffcc66", "#ff6b8a", "#8ea1ff", "#d58cff"]
BANNED_SVG = {"script", "foreignObject", "animate", "animateMotion", "animateTransform", "set"}
CANONICAL_ARTIFACTS = [
    "basmos.bin", "basmos-vm.bin", "basmos-sh.bin",
    "jash/jash.bin", "jash/jash-pack.bin",
]


def artifacts():
    result = []
    pattern = re.compile(r"artifact=(\S+) bytes=(\d+) sha256=([0-9a-f]{64})")
    for line in MANIFEST.read_text(encoding="ascii").splitlines():
        match = pattern.fullmatch(line)
        if match:
            result.append((match.group(1), int(match.group(2)), match.group(3)))
    paths = [path for path, _, _ in result]
    if paths != CANONICAL_ARTIFACTS:
        raise RuntimeError("ARTIFACTS.manifest has a non-canonical artifact set or order")
    for path, size, digest in result:
        data = (ROOT / path).read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f"manifest identity does not match {path}")
    return result


def artifact_set_fingerprint(items):
    digest = hashlib.sha256(b"BASMOS-README-ART-V1\0")
    for path, _, _ in items:
        data = (ROOT / path).read_bytes()
        digest.update(path.encode("ascii") + b"\0")
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def svg_start(title, description, width, height, extra_defs=""):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
<title id="title">{title}</title>
<desc id="desc">{description}</desc>
<defs>
  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#070a12"/><stop offset="0.52" stop-color="#111426"/><stop offset="1" stop-color="#071715"/>
  </linearGradient>
  <radialGradient id="jade"><stop stop-color="#c8fff0"/><stop offset="0.35" stop-color="#65fbd2"/><stop offset="1" stop-color="#158a78"/></radialGradient>
  <radialGradient id="sun"><stop stop-color="#fff2c2"/><stop offset="0.4" stop-color="#ffcc66"/><stop offset="1" stop-color="#b56722"/></radialGradient>
  <filter id="soft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="9"/></filter>
  <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#8ea1ff" stroke-opacity=".07"/></pattern>
{extra_defs}
</defs>
<rect width="{width}" height="{height}" rx="24" fill="url(#bg)"/>
<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="23" fill="none" stroke="#8ea1ff" stroke-opacity=".28"/>
<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="23" fill="url(#grid)"/>
'''


def text(x, y, value, size, fill="#edf3ff", weight=500, anchor="start", spacing=0):
    family = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    return (f'<text x="{x}" y="{y}" fill="{fill}" font-family="{family}" '
            f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
            f'letter-spacing="{spacing}">{value}</text>\n')


def hero(items, set_fingerprint):
    width, height = 1200, 620
    cx, cy = 920, 280
    record_size = items[0][1]
    digest = bytes.fromhex(set_fingerprint)
    out = [svg_start(
        "BasmOS proof geometry",
        "Geometric fingerprint derived from all five committed BasmOS artifact streams.",
        width, height,
        '<linearGradient id="signal" x1="0" y1="0" x2="1" y2="0"><stop stop-color="#65fbd2"/><stop offset=".5" stop-color="#ffcc66"/><stop offset="1" stop-color="#ff6b8a"/></linearGradient>'
    )]
    out.append('<circle cx="920" cy="280" r="224" fill="#0b1320" stroke="#65fbd2" stroke-opacity=".42"/>\n')
    out.append('<circle cx="920" cy="280" r="176" fill="none" stroke="#d58cff" stroke-opacity=".22" stroke-dasharray="3 12"/>\n')
    out.append('<circle cx="920" cy="280" r="104" fill="none" stroke="#ffcc66" stroke-opacity=".36"/>\n')

    points = [(cx, cy)]
    for radius in (92, 188):
        for index in range(6):
            angle = math.radians(-90 + index * 60)
            points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
    for left in range(len(points)):
        for right in range(left + 1, len(points)):
            byte = digest[(left * 13 + right) % len(digest)]
            if (byte >> ((left + right) % 8)) & 1:
                x1, y1 = points[left]
                x2, y2 = points[right]
                color = PALETTE[(left + right + byte) % len(PALETTE)]
                out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-opacity=".24"/>\n')
    for index, (x, y) in enumerate(points):
        radius = 14 if index else 30
        fill = "url(#sun)" if index == 0 else "url(#jade)"
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius + 8}" fill="none" stroke="#65fbd2" stroke-opacity=".16"/>\n')
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{fill}" stroke="#f5f1df" stroke-opacity=".7"/>\n')

    out.append(text(70, 82, "NANOKERNEL / PROOF SYSTEM", 18, "#65fbd2", 700, spacing=3))
    out.append(text(72, 194, "BasmOS", 86, "#f4f0dd", 800))
    out.append(text(72, 244, "512-BYTE IA-32 NANOKERNEL", 26, "#ffcc66", 700, spacing=2))
    out.append(text(72, 292, "PM32  /  PAGING  /  PREEMPTION  /  IPC", 17, "#aebbe8", 600, spacing=1))
    out.append('<rect x="72" y="326" width="520" height="3" rx="2" fill="url(#signal)"/>\n')
    out.append(text(72, 376, "THE ARTIFACT IS THE ARGUMENT.", 23, "#edf3ff", 700, spacing=1))
    out.append(text(72, 410, "Every runtime claim terminates in bytes, state or readback.", 16, "#9da9c9", 400))
    out.append(text(cx, cy + 12, str(record_size), 36, "#f4f0dd", 900, "middle"))
    out.append(text(cx, cy + 58, "3 · 6 · 9", 18, "#ffcc66", 800, "middle", 2))

    stats = [(f"{record_size} B", "COMPLETE"), ("399 B", "PAYLOAD"), ("3", "EXECUTORS"), ("65,536", "IPC STATES")]
    for index, (number, label) in enumerate(stats):
        x = 72 + index * 152
        out.append(text(x, 505, number, 25, PALETTE[index], 800))
        out.append(text(x, 530, label, 12, "#8794b8", 600, spacing=1.5))
    out.append(text(72, 580, "ARTIFACT SET / " + set_fingerprint[:16].upper(), 14, "#d58cff", 700, spacing=1.5))
    out.append(text(1128, 580, "JASH / 2030", 14, "#65fbd2", 700, "end", 1.5))

    for index, byte in enumerate(digest[:16]):
        x = 744 + index * 24
        height_byte = 8 + (byte / 255) * 38
        color = PALETTE[byte % len(PALETTE)]
        out.append(f'<rect x="{x}" y="{570 - height_byte:.1f}" width="14" height="{height_byte:.1f}" rx="7" fill="{color}" fill-opacity=".88"/>\n')
    out.append('</svg>\n')
    return "".join(out)


def hero_mobile(items, set_fingerprint):
    width, height = 720, 1020
    record_size = items[0][1]
    digest = bytes.fromhex(set_fingerprint)
    cx, cy = 360, 680
    out = [svg_start(
        "BasmOS mobile proof geometry",
        "Mobile geometric fingerprint derived from all five committed BasmOS artifact streams.",
        width, height
    )]
    out.append(text(360, 62, "NANOKERNEL / PROOF SYSTEM", 24, "#65fbd2", 700, "middle"))
    out.append(text(360, 150, "BasmOS", 96, "#f4f0dd", 800, "middle"))
    out.append(text(360, 202, f"{record_size}-BYTE IA-32 NANOKERNEL", 32, "#ffcc66", 700, "middle", 1))
    out.append(text(360, 252, "PM32 / PAGING / PREEMPTION / IPC", 26, "#aebbe8", 600, "middle"))
    stats = [(f"{record_size} B", "COMPLETE"), ("399 B", "PAYLOAD"), ("3", "EXECUTORS"), ("65,536", "IPC STATES")]
    for index, (number, label) in enumerate(stats):
        x = 140 + (index % 2) * 340
        y = 320 + (index // 2) * 92
        out.append(text(x, y, number, 38, PALETTE[index], 800, "middle"))
        out.append(text(x, y + 31, label, 26, "#8794b8", 600, "middle", 1.2))
    out.append(f'<circle cx="{cx}" cy="{cy}" r="218" fill="#0b1320" stroke="#65fbd2" stroke-opacity=".55"/>\n')
    out.append(f'<circle cx="{cx}" cy="{cy}" r="164" fill="none" stroke="#d58cff" stroke-opacity=".5" stroke-dasharray="4 12"/>\n')
    points = [(cx, cy)]
    for radius in (82, 176):
        for index in range(6):
            angle = math.radians(-90 + index * 60)
            points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
    for left in range(len(points)):
        for right in range(left + 1, len(points)):
            byte = digest[(left * 13 + right) % len(digest)]
            if (byte >> ((left + right) % 8)) & 1:
                x1, y1 = points[left]
                x2, y2 = points[right]
                color = PALETTE[(left + right + byte) % len(PALETTE)]
                out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-opacity=".45" stroke-width="2"/>\n')
    for index, (x, y) in enumerate(points):
        radius = 28 if index == 0 else 13
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius + 7}" fill="#0a0f1d" stroke="#65fbd2" stroke-opacity=".7"/>\n')
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="#11182c" stroke="#ffcc66"/>\n')
    out.append(text(cx, cy + 10, str(record_size), 32, "#f4f0dd", 900, "middle"))
    out.append(text(cx, cy + 54, "3 · 6 · 9", 28, "#ffcc66", 800, "middle", 2))
    out.append(text(360, 960, "ARTIFACT SET / " + set_fingerprint[:16].upper(), 25, "#d58cff", 700, "middle", 1.2))
    out.append(text(360, 996, "JASH / 2030", 24, "#65fbd2", 700, "middle", 1.5))
    out.append('</svg>\n')
    return "".join(out)


def constellation(items):
    width, height = 1200, 500
    labels = ["RECORD", "VM CONTRACT", "CPL3 SECTOR", "JASH", "J-PACK"]
    positions = [(130, 275), (360, 220), (590, 292), (820, 205), (1060, 278)]
    out = [svg_start(
        "BasmOS artifact constellation",
        "Five committed BasmOS artifacts arranged by their verified relationships and byte sizes.",
        width, height
    )]
    out.append(text(56, 70, "ARTIFACT CONSTELLATION", 25, "#f4f0dd", 800, spacing=2))
    out.append(text(1144, 70, "FIVE IMAGES / ONE VERIFICATION FIELD", 14, "#8ea1ff", 600, "end", 1.2))

    edges = [(0, 1, "SAME SOURCE"), (2, 3, "LOADS"), (3, 4, "READS"), (0, 2, "SIBLING")]
    for left, right, label in edges:
        x1, y1 = positions[left]
        x2, y2 = positions[right]
        out.append(f'<path d="M{x1} {y1} C{(x1+x2)/2:.1f} {y1-70} {(x1+x2)/2:.1f} {y2+70} {x2} {y2}" fill="none" stroke="#8ea1ff" stroke-opacity=".34" stroke-width="2"/>\n')
        out.append(text((x1 + x2) / 2, min(y1, y2) - 30, label, 14, "#9aa7cc", 600, "middle", 1))

    for index, ((path, size, digest), label, (x, y)) in enumerate(zip(items, labels, positions)):
        radius = round(42 + 18 * math.log2(size / 232 + 1), 1)
        color = PALETTE[index]
        out.append(f'<circle cx="{x}" cy="{y}" r="{radius + 16:.1f}" fill="{color}" fill-opacity=".06" stroke="{color}" stroke-opacity=".12"/>\n')
        out.append(f'<circle cx="{x}" cy="{y}" r="{radius:.1f}" fill="#0b1020" stroke="{color}" stroke-width="3"/>\n')
        out.append(f'<circle cx="{x}" cy="{y}" r="{radius - 12:.1f}" fill="none" stroke="{color}" stroke-opacity=".45" stroke-dasharray="2 8"/>\n')
        out.append(text(x, y - 12, str(size) + " B", 27, color, 800, "middle"))
        out.append(text(x, y + 18, label, 16, "#f1f4ff", 700, "middle", 1))
    out.append(text(56, 464, "Every size is read from and checked against ARTIFACTS.manifest.", 15, "#8794b8", 500))
    out.append('</svg>\n')
    return "".join(out)


def constellation_mobile(items):
    width, height = 720, 1240
    labels = ["RECORD", "VM", "CPL3", "JASH", "J-PACK"]
    positions = [(250, 250), (470, 440), (250, 640), (470, 840), (250, 1050)]
    out = [svg_start(
        "BasmOS mobile artifact constellation",
        "Mobile constellation of five committed BasmOS artifacts and their exact byte sizes.",
        width, height
    )]
    out.append(text(360, 54, "ARTIFACT", 38, "#f4f0dd", 800, "middle", 1.5))
    out.append(text(360, 96, "CONSTELLATION", 38, "#f4f0dd", 800, "middle", 1.5))
    out.append(text(360, 136, "FIVE COMMITTED IMAGES", 24, "#8ea1ff", 600, "middle"))
    for left, right in ((0, 1), (0, 2), (2, 3), (3, 4)):
        x1, y1 = positions[left]
        x2, y2 = positions[right]
        out.append(f'<path d="M{x1} {y1} C360 {y1 + 70} 360 {y2 - 70} {x2} {y2}" fill="none" stroke="#8ea1ff" stroke-opacity=".46" stroke-width="3"/>\n')
    for index, ((_, size, _), label, (x, y)) in enumerate(zip(items, labels, positions)):
        color = PALETTE[index]
        radius = 78 if index != 4 else 96
        out.append(f'<circle cx="{x}" cy="{y}" r="{radius + 10}" fill="#0a0f1d" stroke="{color}" stroke-opacity=".35"/>\n')
        out.append(f'<circle cx="{x}" cy="{y}" r="{radius}" fill="#11182c" stroke="{color}" stroke-width="4"/>\n')
        out.append(text(x, y - 8, f"{size} B", 38, color, 800, "middle"))
        out.append(text(x, y + 32, label, 28, "#f1f4ff", 700, "middle", 1))
    out.append('</svg>\n')
    return "".join(out)


def proof_lattice(set_fingerprint):
    width, height = 1200, 560
    cx, cy = 600, 292
    nodes = [
        (600, 92, "BASM / NASM", "BYTE IDENTITY"),
        (870, 135, "SHA-256", "FIVE SEALED IMAGES"),
        (1050, 292, "proofctl", "NATIVE CONTRACTS"),
        (870, 448, "FUZZ / MUTATE", "FAIL CLOSED"),
        (600, 486, "65,536", "IPC CURSOR STATES"),
        (330, 448, "JS MODEL", "BOUNDED EXECUTION"),
        (150, 292, "KVM", "HARDWARE EXECUTION"),
        (330, 135, "QEMU", "SYSTEM READBACK"),
    ]
    out = [svg_start(
        "BasmOS proof lattice",
        "Eight verification surfaces orbit the committed BasmOS artifact set.",
        width, height
    )]
    out.append(text(52, 60, "PROOF LATTICE", 25, "#f4f0dd", 800, spacing=2))
    out.append(text(1148, 60, "NO SINGLE EXECUTOR OWNS THE RESULT", 14, "#ffcc66", 600, "end", 1.2))
    out.append('<circle cx="600" cy="292" r="142" fill="#11182c" stroke="#8ea1ff" stroke-opacity=".42"/>\n')
    out.append('<circle cx="600" cy="292" r="94" fill="#102f2b" stroke="#65fbd2" stroke-opacity=".72"/>\n')
    for index, (x, y, title_node, detail) in enumerate(nodes):
        color = PALETTE[index % len(PALETTE)]
        out.append(f'<line x1="{cx}" y1="{cy}" x2="{x}" y2="{y}" stroke="{color}" stroke-opacity=".28" stroke-width="2"/>\n')
        out.append(f'<circle cx="{x}" cy="{y}" r="62" fill="#0a0f1d" stroke="{color}" stroke-width="2"/>\n')
        out.append(f'<circle cx="{x}" cy="{y}" r="70" fill="none" stroke="{color}" stroke-opacity=".15"/>\n')
        out.append(text(x, y + 7, title_node, 19, color, 800, "middle"))
    out.append(text(cx, cy - 8, "ONE", 18, "#65fbd2", 800, "middle", 3))
    out.append(text(cx, cy + 22, "ARTIFACT SET", 23, "#f4f0dd", 800, "middle", 1))
    out.append(text(cx, cy + 50, set_fingerprint[:16].upper(), 10, "#d58cff", 600, "middle", 1.2))
    out.append('</svg>\n')
    return "".join(out)


def proof_lattice_mobile(set_fingerprint):
    width, height = 720, 1280
    nodes = [
        ("BASM / NASM", "assembly identity"),
        ("SHA-256", "committed images"),
        ("proofctl", "native contracts"),
        ("FUZZ / MUTATE", "fails closed"),
        ("65,536 STATES", "IPC cursors"),
        ("JS MODEL", "bounded execution"),
        ("KVM", "hardware execution"),
        ("QEMU", "system readback"),
    ]
    out = [svg_start(
        "BasmOS mobile proof lattice",
        "Mobile list of eight verification surfaces around the committed artifact set.",
        width, height
    )]
    out.append(text(360, 60, "PROOF LATTICE", 38, "#f4f0dd", 800, "middle", 2))
    out.append(text(360, 100, "NO SINGLE EXECUTOR", 24, "#ffcc66", 600, "middle", 1))
    out.append(text(360, 130, "OWNS THE RESULT", 24, "#ffcc66", 600, "middle", 1))
    out.append('<line x1="360" y1="130" x2="360" y2="1130" stroke="#8ea1ff" stroke-opacity=".42" stroke-width="3"/>\n')
    for index, (title_node, detail) in enumerate(nodes):
        y = 155 + index * 126
        color = PALETTE[index % len(PALETTE)]
        out.append(f'<rect x="90" y="{y}" width="540" height="98" rx="49" fill="#0a0f1d" stroke="{color}" stroke-width="3"/>\n')
        out.append(f'<circle cx="132" cy="{y + 49}" r="12" fill="{color}"/>\n')
        out.append(text(174, y + 43, title_node, 30, color, 800))
        out.append(text(174, y + 75, detail.upper(), 24, "#aeb9d6", 600, spacing=.5))
    out.append(text(360, 1216, "ARTIFACT SET / " + set_fingerprint[:16].upper(), 25, "#d58cff", 700, "middle", 1.2))
    out.append('</svg>\n')
    return "".join(out)


def validate_svg(path, encoded):
    try:
        root = ET.fromstring(encoded)
    except ET.ParseError as error:
        print(f"FAIL: invalid SVG XML in {path.relative_to(ROOT)}: {error}", file=sys.stderr)
        return False
    if root.tag.rsplit("}", 1)[-1] != "svg":
        print(f"FAIL: generated art is not SVG: {path.relative_to(ROOT)}", file=sys.stderr)
        return False
    labels = {node.tag.rsplit("}", 1)[-1] for node in root}
    if not {"title", "desc"}.issubset(labels):
        print(f"FAIL: generated SVG lacks title/desc: {path.relative_to(ROOT)}", file=sys.stderr)
        return False
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1]
        if tag in BANNED_SVG or tag == "style" or any(name.lower().startswith("on") for name in node.attrib):
            print(f"FAIL: unsafe SVG element or event in {path.relative_to(ROOT)}", file=sys.stderr)
            return False
        for value in node.attrib.values():
            if "http://" in value or "https://" in value or value.startswith(("data:", "javascript:")):
                print(f"FAIL: external SVG dependency in {path.relative_to(ROOT)}", file=sys.stderr)
                return False
    return True


def emit(path, content, check):
    encoded = content.encode("utf-8")
    if not validate_svg(path, encoded):
        return False
    if check:
        if not path.exists() or path.read_bytes() != encoded:
            print(f"FAIL: stale README art: {path.relative_to(ROOT)}", file=sys.stderr)
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    print(f"updated {path.relative_to(ROOT)}")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated SVGs are stale")
    args = parser.parse_args()
    items = artifacts()
    set_fingerprint = artifact_set_fingerprint(items)
    shell = (ROOT / "basmos-sh.bin").read_bytes()
    jash = (ROOT / "jash/jash.bin").read_bytes()
    jash_root = hashlib.sha256(shell + jash).digest()
    braille = ["".join(chr(0x2800 + byte) for byte in jash_root[row:row + 8])
               for row in (0, 8)]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required = [f"root {jash_root.hex()[:16]}", *braille]
    if any(value not in readme for value in required):
        raise RuntimeError("README JASH sigil does not match SHA256(shell||jash)")
    outputs = {
        OUT / "hero-proof-geometry.svg": hero(items, set_fingerprint),
        OUT / "hero-proof-geometry-mobile.svg": hero_mobile(items, set_fingerprint),
        OUT / "artifact-constellation.svg": constellation(items),
        OUT / "artifact-constellation-mobile.svg": constellation_mobile(items),
        OUT / "proof-lattice.svg": proof_lattice(set_fingerprint),
        OUT / "proof-lattice-mobile.svg": proof_lattice_mobile(set_fingerprint),
    }
    ok = all(emit(path, value, args.check) for path, value in outputs.items())
    if ok and args.check:
        print("RESULT: PASS - README proof geometry is deterministic and current")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
