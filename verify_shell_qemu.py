#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Boot basmos-sh.bin and prove IRQ0, CPL3 monitor, load, exec and return."""
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IMG = sys.argv[1] if len(sys.argv) > 1 else "basmos-sh.bin"
MODULE = bytes.fromhex("b35ab801000000cd80b804000000cd80")  # putc('Z'); q
INPUT = b"?r" + bytes((len(MODULE),)) + MODULE + b"x"

image = Path(IMG).read_bytes()
if len(image) != 512 or image[510:] != b"\x55\xaa":
    print(f"FAIL: {IMG} must be exactly 512 bytes and end in 55 aa", file=sys.stderr)
    sys.exit(1)


def connect(path, tries=80):
    for _ in range(tries):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(path)
            return s
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"could not connect to {path}")


def qmp(sock, request):
    sock.sendall((json.dumps(request) + "\n").encode())
    buf = b""
    while True:
        buf += sock.recv(65536)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            message = json.loads(line)
            if "return" in message or "error" in message:
                return message


def read_phys(sock, address, count):
    response = qmp(sock, {
        "execute": "human-monitor-command",
        "arguments": {"command-line": f"xp /{count}bx {address:#x}"},
    })
    dump = response.get("return", "")
    values = []
    for token in dump.replace(":", " ").split():
        if token.startswith("0x") and len(token) <= 4:
            try:
                values.append(int(token, 16))
            except ValueError:
                pass
    return bytes(values[-count:]) if len(values) >= count else bytes(values)


tmp = tempfile.TemporaryDirectory(prefix="basmos-shell-")
serial_path = str(Path(tmp.name) / "serial.sock")
qmp_path = str(Path(tmp.name) / "qmp.sock")
qemu = subprocess.Popen([
    "qemu-system-i386",
    "-drive", f"format=raw,if=floppy,readonly=on,file={IMG}",
    "-nic", "none",
    "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
    "-display", "none",
    "-no-reboot", "-no-shutdown",
    "-chardev", f"socket,id=serial0,path={serial_path},server=on,wait=off",
    "-serial", "chardev:serial0",
    "-qmp", f"unix:{qmp_path},server=on,wait=off",
], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

try:
    serial = connect(serial_path)
    monitor = connect(qmp_path)
    hello = b""
    while b"\n" not in hello:
        hello += monitor.recv(4096)
    qmp(monitor, {"execute": "qmp_capabilities"})

    serial.sendall(INPUT)
    transcript = b""
    deadline = time.time() + 8
    while time.time() < deadline and b"Z>" not in transcript.replace(b".", b""):
        try:
            transcript += serial.recv(4096)
        except socket.timeout:
            pass

    status = qmp(monitor, {"execute": "query-status"}).get("return", {}).get("status")
    idt = read_phys(monitor, 0x500, 129 * 8)
    pde = int.from_bytes(read_phys(monitor, 0x1000, 4), "little")
    tss = read_phys(monitor, 0xA00, 104)

    gates = [idt[i:i + 8] for i in range(0, len(idt), 8)]
    idt_ok = (
        len(gates) == 129
        and all(len(g) == 8 and g[2:4] == b"\x08\x00" for g in gates)
        and all(g[5] == 0x8E for g in gates[:128])
        and gates[128][5] == 0xEF
    )
    tss_ok = (
        len(tss) == 104
        and int.from_bytes(tss[4:8], "little") == 0x1000
        and int.from_bytes(tss[8:10], "little") == 0x10
        and int.from_bytes(tss[102:104], "little") == 0x68
    )
    irq_ok = b"." in transcript
    module_ok = b"Z>" in transcript.replace(b".", b"")
    live = qemu.poll() is None and status == "running"
    paging_ok = (pde & 0x87) == 0x87 and (pde & 0xFFC00000) == 0
    ok = irq_ok and module_ok and live and idt_ok and paging_ok and tss_ok

    print("serial:", transcript.decode("ascii", "backslashreplace"))
    print(f"  [{'PASS' if irq_ok else 'FAIL'}] IRQ0 emitted '.' and returned")
    print(f"  [{'PASS' if module_ok else 'FAIL'}] module emitted 'Z' and q returned to '>'")
    print(f"  [{'PASS' if idt_ok else 'FAIL'}] IDT: 128 DPL0 gates + int 0x80 DPL3 trap gate")
    print(f"  [{'PASS' if tss_ok else 'FAIL'}] TSS: SS0=0x10 ESP0=0x1000 IOPB=0x68")
    print(f"  [{'PASS' if paging_ok else 'FAIL'}] PDE0: user | rw | present | 4MiB ({pde:#x})")
    print(f"  [{'PASS' if live else 'FAIL'}] QEMU remains running")
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
finally:
    qemu.terminate()
    try:
        qemu.wait(timeout=3)
    except subprocess.TimeoutExpired:
        qemu.kill()
    tmp.cleanup()
