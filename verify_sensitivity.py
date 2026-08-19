#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Byte-sensitivity map for the record artifact.
#
# For every byte offset of basmos.bin, flip all bits (XOR 0xFF), boot the
# mutated image in QEMU under the same flags as verify_qemu.py, and classify
# the observable effect on the demonstrated contract:
#
#   INTACT          full 3/6/9, guest running, heartbeat still advancing
#   ALTERED-VISIBLE guest alive, heartbeat alive, but the VGA contract differs
#   ALTERED-TIMER   3/6/9 shown and guest running, but the heartbeat is frozen
#   DEAD            contract never completes, or the guest is not running
#
# Classification is single-run with fixed timeouts; borderline mutants that
# merely slow the boot may vary between runs. The map documents the
# observability of each byte, not a formal proof of dead code.

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

IMG = sys.argv[1] if len(sys.argv) > 1 else "basmos.bin"
EXPECTED = bytes([0x33, 0x0F, 0x36, 0x0F, 0x39, 0x0A])
POLL_SECONDS = 3.0
DWELL_SECONDS = 0.5
HEARTBEAT_GAP = 0.3
WORKERS = 4
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")


def symbol_map():
    """Parse `basm-nano --map` so each byte is reported with its symbol."""
    out = subprocess.run(
        ["basm-nano/basm-nano", "-f", "bin", "-o", os.devnull,
         "basmos.basm", "--map", "-"],
        capture_output=True, text=True, check=True).stdout
    spans = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].isdigit():
            spans.append((int(parts[0]), int(parts[1]), parts[2]))
    spans.sort()
    return spans


def symbol_of(spans, offset):
    for start, size, name in spans:
        if start <= offset < start + size:
            return name
    if offset >= 510:
        return "signature"
    return "padding"


def classify(offset, spans):
    original = open(IMG, "rb").read()
    if len(original) != 512:
        sys.exit(f"{IMG} must be exactly 512 bytes")
    mutated = bytearray(original)
    mutated[offset] ^= 0xFF

    tmp = tempfile.TemporaryDirectory(prefix=f"basmos-sens-{offset}-")
    path = os.path.join(tmp.name, "mutant.bin")
    with open(path, "wb") as f:
        f.write(mutated)
    sock_path = os.path.join(tmp.name, "qmp.sock")

    qemu = subprocess.Popen([
        "qemu-system-i386",
        "-drive", f"format=raw,if=floppy,readonly=on,file={path}",
        "-nic", "none",
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,"
                    "spawn=deny,resourcecontrol=deny",
        "-display", "none",
        "-no-reboot", "-no-shutdown",
        "-qmp", f"unix:{sock_path},server,nowait",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        s = None
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(sock_path)
                break
            except OSError:
                time.sleep(0.1)
        if s is None:
            return "DEAD"
        buf = b""

        def qmp(frame):
            nonlocal buf
            s.sendall((json.dumps(frame) + "\n").encode())
            while True:
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        raise ConnectionError("qmp closed")
                    buf += chunk
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                msg = json.loads(line)
                if "return" in msg or "error" in msg:
                    return msg

        qmp({"execute": "qmp_capabilities"})

        def read_phys(address, count):
            r = qmp({"execute": "human-monitor-command",
                     "arguments": {"command-line":
                                   f"xp /{count}bx {address:#x}"}})
            dump = r.get("return", "")
            hexbytes = []
            for tok in dump.replace(":", " ").split():
                if tok.startswith("0x") and len(tok) <= 4:
                    try:
                        hexbytes.append(int(tok, 16))
                    except ValueError:
                        pass
            return hexbytes[-count:] if len(hexbytes) >= count else hexbytes

        def try_read(address, count):
            for _ in range(3):
                try:
                    return read_phys(address, count)
                except (OSError, ConnectionError, json.JSONDecodeError):
                    time.sleep(0.2)
            return []

        def status_running():
            try:
                status = qmp({"execute": "query-status"}) \
                    .get("return", {}).get("status")
                return qemu.poll() is None and status == "running"
            except (OSError, ConnectionError, json.JSONDecodeError):
                return False

        vga = b""
        deadline = time.time() + POLL_SECONDS
        while time.time() < deadline:
            vga = bytes(try_read(0xB8000, 6))
            if vga == EXPECTED:
                break
            time.sleep(0.15)

        if vga != EXPECTED:
            # Either the boot died or the visible contract changed.
            if not status_running():
                return "DEAD"
            # Alive but wrong pixels: altered visible behavior.
            b1 = try_read(0x6FC, 1)
            time.sleep(HEARTBEAT_GAP)
            b2 = try_read(0x6FC, 1)
            if b1 and b2 and (b2[0] - b1[0]) & 0xFF:
                return "ALTERED-VISIBLE"
            return "DEAD"

        # Contract pixels are intact: check liveness and the heartbeat.
        time.sleep(DWELL_SECONDS)
        alive = status_running()
        vga2 = bytes(try_read(0xB8000, 6))
        b1 = try_read(0x6FC, 1)
        time.sleep(HEARTBEAT_GAP)
        b2 = try_read(0x6FC, 1)
        beating = b1 and b2 and (b2[0] - b1[0]) & 0xFF
        if not alive or vga2 != EXPECTED:
            return "DEAD"
        if not beating:
            return "ALTERED-TIMER"
        return "INTACT"
    except (OSError, ConnectionError, json.JSONDecodeError):
        return "DEAD"
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=3)
        except subprocess.TimeoutExpired:
            qemu.kill()
        tmp.cleanup()


def main():
    import hashlib
    spans = symbol_map()
    data = open(IMG, "rb").read()
    digest = hashlib.sha256(data).hexdigest()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(lambda i: classify(i, spans), range(512)))

    order = ["INTACT", "ALTERED-VISIBLE", "ALTERED-TIMER", "DEAD"]
    counts = {c: results.count(c) for c in order}

    os.makedirs(OUT_DIR, exist_ok=True)
    payload_end = next(start for start, size, name in spans
                       if name == "payload_end")
    rows = [{"offset": i, "class": results[i],
             "symbol": symbol_of(spans, i)} for i in range(512)]
    payload_counts = {}
    for r in rows[:payload_end]:
        payload_counts.setdefault(r["symbol"], {}) \
            .setdefault(r["class"], 0)
        payload_counts[r["symbol"]][r["class"]] += 1

    doc = {
        "artifact": IMG,
        "sha256": digest,
        "method": "single-byte XOR 0xFF, QEMU boot, observable contract "
                  "(3/6/9 + running + heartbeat), single run",
        "payload_bytes": payload_end,
        "counts": counts,
        "payload_by_symbol": payload_counts,
        "bytes": rows,
    }
    json_path = os.path.join(OUT_DIR, "byte-sensitivity.json")
    with open(json_path, "w") as f:
        json.dump(doc, f, indent=1)

    glyphs = {"DEAD": "#", "ALTERED-VISIBLE": "~", "ALTERED-TIMER": "%",
              "INTACT": "."}
    md = ["# Byte-Sensitivity Map", "",
          f"Artifact: `{IMG}` (sha256 `{digest}`).",
          "Method: each byte flipped (XOR 0xFF), booted in QEMU, classified by",
          "the observable contract. Single run; fixed timeouts.", "",
          "| Class | Glyph | Bytes | Meaning |",
          "|---|---|---:|---|",
          f"| DEAD | `#` | {counts['DEAD']} | contract never completes or guest not running |",
          f"| ALTERED-VISIBLE | `~` | {counts['ALTERED-VISIBLE']} | alive, but VGA bytes differ |",
          f"| ALTERED-TIMER | `%` | {counts['ALTERED-TIMER']} | 3/6/9 intact but heartbeat frozen |",
          f"| INTACT | `.` | {counts['INTACT']} | no observable effect |",
          "", "```", f"payload: {payload_end} bytes   "
          f"(# dead  ~ altered  % timer-dead  . intact)", ""]
    for row in range(0, 512, 32):
        md.append(f"{row:03d} " + "".join(glyphs[results[i]]
                                          for i in range(row, row + 32)))
    md += ["```", ""]
    md_path = os.path.join(OUT_DIR, "byte-sensitivity.md")
    with open(md_path, "w") as f:
        f.write("\n".join(md))

    for c in order:
        print(f"  {c:16s} {counts[c]:4d}")
    dead_in_payload = sum(1 for r in rows[:payload_end]
                          if r["class"] == "INTACT")
    print(f"payload: {payload_end} bytes; "
          f"{dead_in_payload} of them observably dead under the "
          f"demonstrated contract")
    print(f"RESULT: INFO — evidence written to {json_path} and {md_path}")


if __name__ == "__main__":
    main()
