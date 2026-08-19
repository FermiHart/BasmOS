#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Prove JASH under QEMU while IRQ0 dots race its serial stream."""
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IMAGE = Path(sys.argv[1] if len(sys.argv) > 1 else "basmos-sh.bin")
MODULE = Path(sys.argv[2] if len(sys.argv) > 2 else "jash/jash.bin")
PACK = Path(sys.argv[3] if len(sys.argv) > 3 else "jash/jash-pack.bin")
image, module, pack = IMAGE.read_bytes(), MODULE.read_bytes(), PACK.read_bytes()
if len(image) != 512 or image[510:] != b"\x55\xaa" or len(module) != 256:
    raise SystemExit("FAIL: invalid shell sector or JASH nucleus")

commands = b"uname -a\rwhy map\rwhatif lab map\rinfo\rsurfaces\rjack\rwhy map\rbye\r"
wire = b"r\x00" + module + b"x" + len(pack).to_bytes(2, "little") + pack + commands


def connect(path):
    for _ in range(100):
        try:
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stream.settimeout(1)
            stream.connect(path)
            return stream
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"could not connect to {path}")


def qmp(stream, request):
    stream.sendall((json.dumps(request) + "\n").encode())
    buffer = b""
    while True:
        buffer += stream.recv(65536)
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if line.strip():
                message = json.loads(line)
                if "return" in message or "error" in message:
                    return message


def read_phys(stream, address, count):
    reply = qmp(stream, {
        "execute": "human-monitor-command",
        "arguments": {"command-line": f"xp /{count}bx {address:#x}"},
    }).get("return", "")
    values = []
    for token in reply.replace(":", " ").split():
        if token.startswith("0x") and len(token) <= 4:
            try:
                values.append(int(token, 16))
            except ValueError:
                pass
    return bytes(values[-count:]) if len(values) >= count else bytes(values)


tmp = tempfile.TemporaryDirectory(prefix="jash-qemu-")
serial_path = str(Path(tmp.name) / "wire.sock")
qmp_path = str(Path(tmp.name) / "qmp.sock")
qemu = subprocess.Popen([
    "qemu-system-i386",
    "-drive", f"format=raw,if=floppy,readonly=on,file={IMAGE}",
    "-nic", "none",
    "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
    "-display", "none", "-no-reboot", "-no-shutdown",
    "-chardev", f"socket,id=wire,path={serial_path},server=on,wait=off",
    "-serial", "chardev:wire",
    "-qmp", f"unix:{qmp_path},server=on,wait=off",
], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

try:
    serial = connect(serial_path)
    monitor = connect(qmp_path)
    hello = b""
    while b"\n" not in hello:
        hello += monitor.recv(4096)
    qmp(monitor, {"execute": "qmp_capabilities"})
    serial.sendall(wire)

    transcript = b""
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            transcript += serial.recv(65536)
        except socket.timeout:
            pass
        without_ticks = transcript.replace(b".", b"")
        if b"JASH:EOT" in without_ticks and b"\r\n>" in without_ticks:
            break

    status = qmp(monitor, {"execute": "query-status"}).get("return", {}).get("status")
    loaded_module = read_phys(monitor, 0x8000, len(module))
    loaded_pack = read_phys(monitor, 0x8200, len(pack))
    expected_pack = bytearray(pack)
    clean = transcript.replace(b".", b"")
    clean = re.sub(rb"\x1b\[[0-9;]* ?[mJHq]", b"", clean)
    text = clean.decode("ascii", "replace")
    # IRQ0 writes literal dots asynchronously; normalization removes them from
    # both timer noise and dotted field names such as cpu.vendor.
    vendor = re.search(rb"\[RUNTIME\] cpuvendor ([ -~]{12})", clean)
    identity_at = pack.index(b"[RUNTIME] cpu.vendor ") + 21
    if vendor:
        expected_pack[identity_at:identity_at + 12] = vendor.group(1)

    checks = [
        (b"." in transcript, "IRQ0 crossed the CPL3 execution"),
        ("JASH/2030" in text and "cpl 3" in text, "JASH booted and reported CPL3"),
        (vendor is not None and "[PROOF] jashsha256" in text,
         "uname -a measured CPUID and rendered its proof ledger"),
        ("PRF1|POLICY|MAP|08|1F|ALLOW" in text
         and "PRF1|POLICY|MAP|08|17|DENY" in text
         and "PRF1|MODEL|MAP|08|17|DENY" in text,
         "live policy and counterfactual PRF1 records survived IRQ noise"),
        ("SURFACES" in text and "JACKED lab" in text, "Surfaces and Deck transition ran"),
        ("JASH:EOT" in text and "\r\n>" in text, "bye returned to the parent monitor"),
        (loaded_module == module, "QMP read back the exact 256-byte RX nucleus"),
        (loaded_pack == expected_pack,
         "QMP read back an immutable Pack except for its CPUID evidence field"),
        (qemu.poll() is None and status == "running", "QEMU remained live"),
    ]
    ok = True
    for passed, description in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {description}")
        ok = ok and passed
    print(f"JASH/QEMU: wire={len(wire)}B serial={len(transcript)}B ticks={transcript.count(b'.')}")
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
finally:
    qemu.terminate()
    try:
        qemu.wait(timeout=3)
    except subprocess.TimeoutExpired:
        qemu.kill()
    tmp.cleanup()
