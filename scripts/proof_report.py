#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Report the existing full Makefile proof gate without replacing its verifiers.

The single source of truth is Makefile:proof-core. This wrapper streams the
complete output and records a report even if the child gate returns nonzero.
A report is diagnostic evidence, not a cryptographic signature or attestation.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
IMAGES = (
    ("basmos.bin", 512),
    ("basmos-vm.bin", 232),
    ("basmos-sh.bin", 512),
    ("jash/jash.bin", 256),
    ("jash/jash-pack.bin", 3584),
)


def command_output(args):
    if shutil.which(args[0]) is None:
        return None
    try:
        result = subprocess.run(
            args, cwd=ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=5, check=False,
        )
        return (result.stdout or result.stderr).splitlines()[0]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def expected_hashes():
    try:
        lines = (ROOT / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    except OSError:
        return {}
    hashes = {}
    for line in lines:
        fields = line.split(maxsplit=1)
        if len(fields) == 2 and len(fields[0]) == 64:
            hashes[fields[1].lstrip("*").strip()] = fields[0].lower()
    return hashes


def observed_images():
    expected = expected_hashes()
    results = []
    for name, wanted_size in IMAGES:
        path = ROOT / name
        try:
            data = path.read_bytes()
            actual_size = len(data)
            digest = hashlib.sha256(data).hexdigest()
        except OSError:
            actual_size, digest = None, None
        results.append({
            "path": name,
            "expected_bytes": wanted_size,
            "observed_bytes": actual_size,
            "size_ok": actual_size == wanted_size,
            "observed_sha256": digest,
            "sha256_matches_manifest": (
                digest is not None and expected.get(name) == digest
            ),
        })
    return results


def commit_sha():
    return command_output(["git", "rev-parse", "HEAD"]) or "unknown"


def write_reports(out, report):
    json_path = out / "PROOF-REPORT.json"
    markdown_path = out / "PROOF-REPORT.md"
    lines = [
        "# BasmOS full proof report",
        "",
        f"- Status: **{report['status']}** (exit {report['exit_code']})",
        f"- Commit: `{report['commit']}`",
        f"- UTC: {report['utc']}",
        f"- Duration: {report['duration_seconds']:.2f}s",
        "- Source: `Makefile:proof-core` (unmodified underlying checks)",
        "- Full log: `evidence/PROOF-REPORT.log`",
        "",
        "| Artifact | Bytes | Size | SHA-256 manifest |",
        "| --- | ---: | --- | --- |",
    ]
    for artifact in report["artifacts"]:
        lines.append(
            f"| `{artifact['path']}` | {artifact['observed_bytes']} | "
            f"{'PASS' if artifact['size_ok'] else 'FAIL'} | "
            f"{'PASS' if artifact['sha256_matches_manifest'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        "This is a record of execution, **not** a signature, formal proof,",
        "or proof of tests not invoked by `Makefile:proof-core`.",
        "See `readme/PROOF.md` for scope and limitations.",
        "",
    ])
    for path, data in (
        (json_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n"),
        (markdown_path, "\n".join(lines)),
    ):
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(data, encoding="utf-8")
        temporary.replace(path)


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        print("usage: scripts/proof_report.py -- make proof-core", file=sys.stderr)
        return 2
    command = sys.argv[2:]
    out = ROOT / os.environ.get("PROOF_DIR", "evidence")
    out.mkdir(parents=True, exist_ok=True)
    log_path = out / "PROOF-REPORT.log"
    start = time.monotonic()
    code = 127
    child = None
    try:
        with log_path.open("w", encoding="utf-8", errors="replace") as log:
            try:
                child = subprocess.Popen(
                    command, cwd=ROOT, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                    errors="replace", bufsize=1,
                )
                assert child.stdout is not None
                for line in child.stdout:
                    print(line, end="", flush=True)
                    log.write(line)
                    log.flush()
                code = child.wait()
            except KeyboardInterrupt:
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                code = 130
                print("PROOF FAIL: interrupted", file=sys.stderr)
                log.write("PROOF FAIL: interrupted\n")
            except OSError as error:
                print(f"PROOF FAIL: {error}", file=sys.stderr)
                log.write(f"PROOF FAIL: {error}\n")
    finally:
        artifacts = observed_images()
        if code == 0 and not all(
            item["size_ok"] and item["sha256_matches_manifest"]
            for item in artifacts
        ):
            code = 1
            print("PROOF FAIL: artifact size or SHA256SUMS changed", file=sys.stderr)
        report = {
            "schema": "basmos-proof-report-v1",
            "status": "PASS" if code == 0 else "FAIL",
            "exit_code": code,
            "commit": commit_sha(),
            "utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": round(time.monotonic() - start, 3),
            "command": command,
            "gate": "Makefile:proof-core",
            "artifacts": artifacts,
            "tools": {
                "python": platform.python_version(),
                "make": command_output(["make", "--version"]),
                "qemu": command_output(["qemu-system-i386", "--version"]),
                "nasm": command_output(["nasm", "-v"]),
                "node": command_output(["node", "--version"]),
                "kvm_accessible": (
                    Path("/dev/kvm").exists()
                    and os.access("/dev/kvm", os.R_OK | os.W_OK)
                ),
            },
            "log": str(log_path.relative_to(ROOT)) if log_path.is_relative_to(ROOT) else str(log_path),
            "disclaimer": "Exit status of the existing Makefile gate; not independently certified.",
        }
        write_reports(out, report)
        print(
            f"Proof report: {out / 'PROOF-REPORT.json'} "
            f"(status={report['status']})",
            flush=True,
        )
    return code


if __name__ == "__main__":
    sys.exit(main())
