#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Verify the staged nanokernel.org artifact before Pages upload."""

import hashlib
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


SITE = Path(sys.argv[1] if len(sys.argv) > 1 else "_site").resolve()
EXPECTED = {
    ".nojekyll", "AUTHORS.md", "ARTIFACTS.manifest", "CNAME", "DOMAINS.md",
    "LICENSE", "Makefile", "OPTIMIZATIONS.md", "README.md", "RELEASING.md",
    "RESEARCH.md", "RING3.md", "SECURITY.md", "SHA256SUMS", "WAVES.md",
    "THIRD_PARTY_NOTICES.md", "THREAT_MODEL.md", "TRADEMARKS.md",
    "basmos-sh.basm", "basmos-sh.bin", "basmos-vm.bin", "basmos.basm",
    "basmos.bin", "index.html", "jash-live.svg", "test_interpreter.js",
    "verify_domains.py", "verify_ipc_model.py", "verify_jash.py",
    "verify_jash_fuzz.py", "verify_jash_qemu.py", "verify_qemu.py",
    "basm-nano/basm_nano.c", "basm-nano/basm_sacred.c", "bemu/bemu_nano.c",
    "evidence/jash-session.ansi", "evidence/jash-session.commands",
    "evidence/jash-session.manifest", "evidence/jash-session.txt",
    "jash/jash-pack.basm", "jash/jash-pack.bin", "jash/jash.basm",
    "jash/jash.bin", "scripts/capture_jash.py", "scripts/verify_site.py",
    "website/jash-live.svg", "readme/hero-proof-geometry.svg",
    "readme/hero-proof-geometry-mobile.svg", "readme/artifact-constellation.svg",
    "readme/artifact-constellation-mobile.svg", "readme/proof-lattice.svg",
    "readme/proof-lattice-mobile.svg",
}


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for name in ("href", "src", "srcset"):
            if name in values:
                self.values.append(values[name])


def local_target(source, value):
    if not value or value.startswith(("#", "mailto:", "data:", "http://", "https://")):
        return None
    path = unquote(urlsplit(value).path)
    return (SITE / path.lstrip("/")) if path.startswith("/") else (source.parent / path)


def without_fenced_code(markdown):
    visible = []
    fence = None
    for line in markdown.splitlines():
        marker = re.match(r"^( {0,3})(`{3,}|~{3,})(.*)$", line)
        if marker:
            token = marker.group(2)
            if fence is None:
                fence = (token[0], len(token))
            elif (token[0] == fence[0] and len(token) >= fence[1]
                  and not marker.group(3).strip()):
                fence = None
            visible.append("")
        elif fence is None and not line.startswith(("    ", "\t")):
            visible.append(line)
        else:
            visible.append("")
    return "\n".join(visible)


def main():
    if not SITE.is_dir():
        raise SystemExit(f"FAIL: staged site not found: {SITE}")
    excluded = sorted(path for path in EXPECTED if path.startswith((".git/", ".github/")))
    if excluded:
        raise SystemExit(f"FAIL: Pages upload action would exclude: {excluded}")
    actual = {str(path.relative_to(SITE)) for path in SITE.rglob("*") if path.is_file()}
    if actual != EXPECTED:
        extra = sorted(actual - EXPECTED)
        absent = sorted(EXPECTED - actual)
        raise SystemExit(f"FAIL: staging allowlist mismatch; extra={extra} missing={absent}")
    missing = []
    parser = Links()
    index = SITE / "index.html"
    parser.feed(index.read_text(encoding="utf-8"))
    for value in parser.values:
        target = local_target(index, value)
        if target is not None and not target.exists():
            missing.append((index.relative_to(SITE), value))

    markdown_link = re.compile(r"\[[^]]*\]\(([^)]+)\)")
    reference_definition = re.compile(r"(?m)^\s*\[([^]]+)\]:\s*(?:<([^>]+)>|(\S+))")
    reference_use = re.compile(r"!?\[([^]]+)\]\[([^]]*)\]")
    for source in SITE.glob("*.md"):
        markdown = source.read_text(encoding="utf-8")
        visible = without_fenced_code(markdown)
        for value in markdown_link.findall(visible):
            target = local_target(source, value)
            if target is not None and not target.exists():
                missing.append((source.relative_to(SITE), value))
        definitions = {}
        for label, angle, plain in reference_definition.findall(visible):
            definitions[label.casefold()] = angle or plain
        for value in definitions.values():
            target = local_target(source, value)
            if target is not None and not target.exists():
                missing.append((source.relative_to(SITE), value))
        for label, identifier in reference_use.findall(visible):
            key = (identifier or label).casefold()
            value = definitions.get(key)
            if value is None:
                missing.append((source.relative_to(SITE), f"undefined reference [{key}]"))
                continue
            target = local_target(source, value)
            if target is not None and not target.exists():
                missing.append((source.relative_to(SITE), value))
        embedded = Links()
        embedded.feed(visible)
        for value in embedded.values:
            target = local_target(source, value)
            if target is not None and not target.exists():
                missing.append((source.relative_to(SITE), value))

    required = [
        "basmos.bin", "basmos-vm.bin", "basmos-sh.bin", "jash/jash.bin",
        "jash/jash-pack.bin", "ARTIFACTS.manifest", "SHA256SUMS",
        "basm-nano/basm_nano.c", "basm-nano/basm_sacred.c",
        "evidence/jash-session.txt", "evidence/jash-session.manifest",
        "jash-live.svg", "readme/hero-proof-geometry.svg", "CNAME",
    ]
    for value in required:
        if not (SITE / value).exists():
            missing.append((Path("<required>"), value))

    html = index.read_text(encoding="utf-8")
    stale = [token for token in ("@basmos.org", "3055 B", "253+3", "why map",
                                 "whatif lab map", "code.read") if token in html]
    if stale:
        raise SystemExit("FAIL: stale public JASH claims: " + ", ".join(stale))
    if (SITE / "CNAME").read_text(encoding="ascii").strip() != "nanokernel.org":
        raise SystemExit("FAIL: incorrect Pages CNAME")
    for line in (SITE / "evidence/jash-session.manifest").read_text(encoding="ascii").splitlines():
        digest, name = line.split(maxsplit=1)
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"FAIL: unsafe evidence path: {name}")
        target = SITE / relative
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise SystemExit(f"FAIL: evidence hash mismatch: {name}")
    if missing:
        for source, value in missing:
            print(f"  missing: {source}: {value}", file=sys.stderr)
        raise SystemExit("FAIL: staged site has missing local resources")
    print(f"RESULT: PASS - exact {len(EXPECTED)}-file allowlist, links and evidence agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
