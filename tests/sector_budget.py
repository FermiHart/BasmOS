#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
"""Enforce the complete 512-byte kernel budget, including the boot signature.

Besides inspecting the actual artifact, rebuild its source and attempt a
one-byte-over-budget source. The assembler must reject that source without
replacing an existing valid sector or publishing a new oversized image.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.qemu_lab import parse_map

SECTOR_BYTES = 512
SIGNATURE_BYTES = 2


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect(assembler, source, kernel, map_path):
    image = kernel.read_bytes()
    symbols = parse_map(map_path)
    payload = symbols.get("payload_end", -1)
    ceiling = SECTOR_BYTES - SIGNATURE_BYTES
    checks = {
        "complete_kernel_exactly_512_bytes": len(image) == SECTOR_BYTES,
        "boot_signature_included": image[-2:] == b"\x55\xaa",
        "payload_within_510_bytes": 0 < payload <= ceiling,
        "padding_is_zero": 0 < payload <= ceiling and image[payload:ceiling] == bytes(ceiling - payload),
    }
    with tempfile.TemporaryDirectory(prefix="basmos-sector-budget-") as directory:
        temporary = Path(directory)
        rebuilt, rebuilt_map = temporary / "kernel.bin", temporary / "kernel.map"
        subprocess.run([str(assembler), "-f", "bin", "--map", str(rebuilt_map),
                        "-o", str(rebuilt), str(source)], check=True, capture_output=True)
        checks["source_rebuild_matches_kernel"] = rebuilt.read_bytes() == image
        checks["source_rebuild_matches_map"] = rebuilt_map.read_bytes() == map_path.read_bytes()

        # The negative source requests 511 payload bytes. It is never emitted
        # as a binary: the mandatory signature leaves only 510 payload bytes.
        negative = temporary / "over-budget.basm"
        negative.write_text("BITS 16\norg 0x7C00\nsection .text\n"
                            "times 511 db 0\npayload_end:\n"
                            "times 510 - ($ - $$) db 0\ndw 0xAA55\n")
        command = [str(assembler), "-f", "bin", "-o", str(rebuilt), str(negative)]
        failure = subprocess.run(command, capture_output=True)
        checks["511_byte_payload_rejected"] = (
            failure.returncode != 0 and b"times count is negative" in failure.stderr)
        checks["failed_build_preserves_previous_sector"] = rebuilt.read_bytes() == image
        absent = temporary / "must-not-exist.bin"
        command[-2] = str(absent)
        failure_new = subprocess.run(command, capture_output=True)
        checks["failed_build_publishes_no_new_image"] = failure_new.returncode != 0 and not absent.exists()

    return {"pass": all(checks.values()), "limit_bytes": SECTOR_BYTES,
            "kernel_bytes": len(image), "payload_bytes": payload,
            "padding_bytes": ceiling - payload, "signature_bytes": SIGNATURE_BYTES,
            "kernel_sha256": sha(image), "source_sha256": sha(source.read_bytes()),
            "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assembler", type=Path, default=ROOT / "basm-nano/basm-nano")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inspect(args.assembler.resolve(), args.source.resolve(),
                         args.kernel.resolve(), args.map.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        report = {"pass": False, "limit_bytes": SECTOR_BYTES, "error": str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
