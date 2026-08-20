#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Boot a 512-byte boot-sector image in QEMU and assert the VGA text buffer.

Acceptance contract: physical memory must show
  0xB8000: '3' 0x0F   (task0 ran)
  0xB8002: '6' 0x0F   (task1 ran -> hardware timer preemption works)
  0xB8004: '9' 0x0A   (task1 received task0's IPC byte → both ends of IPC work)

Task 0 is CPU-bound and never yields; task 1 waits in HLT. Uses QMP
(human-monitor-command xp) with -display none (NOT -vga none, so the
VGA device and 0xB8000 still exist). Physical read bypasses guest paging, which
matches the identity map. Exit code 0 on pass, 1 on fail.
"""
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IMG = sys.argv[1] if len(sys.argv) > 1 else "basmos.bin"
EXPECTED = bytes((0x33, 0x0F, 0x36, 0x0F, 0x39, 0x0A))
image = Path(IMG).read_bytes()
if len(image) != 512 or image[510:] != b"\x55\xaa":
    print(f"FAIL: {IMG} must be exactly 512 bytes and end in 55 aa", file=sys.stderr)
    sys.exit(1)

tmp = tempfile.TemporaryDirectory(prefix="basmos-qmp-")
SOCK = str(Path(tmp.name) / "qmp.sock")

qemu = subprocess.Popen([
    "qemu-system-i386",
    "-drive", f"format=raw,if=floppy,readonly=on,file={IMG}",
    "-nic", "none",
    "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
    "-display", "none",
    "-no-reboot", "-no-shutdown",
    "-qmp", f"unix:{SOCK},server,nowait",
], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def connect(path, tries=50):
    for _ in range(tries):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(path)
            return s
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("could not connect to QMP socket")

def qmp(sock, f):
    sock.sendall((json.dumps(f) + "\n").encode())
    buf = b""
    while True:
        buf += sock.recv(65536)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            msg = json.loads(line)
            if "return" in msg or "error" in msg:
                return msg

try:
    s = connect(SOCK)
    # QMP handshake
    hello = b""
    while b"\n" not in hello:
        hello += s.recv(4096)
    qmp(s, {"execute": "qmp_capabilities"})

    def read_phys(address, count):
        r = qmp(s, {"execute": "human-monitor-command",
                    "arguments": {"command-line": f"xp /{count}bx {address:#x}"}})
        dump = r.get("return", "")
        hexbytes = []
        for tok in dump.replace(":", " ").split():
            if tok.startswith("0x") and len(tok) <= 4:
                try:
                    hexbytes.append(int(tok, 16))
                except ValueError:
                    pass
        return (hexbytes[-count:] if len(hexbytes) >= count else hexbytes), dump

    def read_vga():
        return read_phys(0xB8000, 8)

    # Poll the complete contract; observing only task0 would race task1.
    vals, dump = [], ""
    deadline = time.time() + 8.0
    while time.time() < deadline:
        vals, dump = read_vga()
        if bytes(vals[:6]) == EXPECTED:
            break
        time.sleep(0.3)

    # The acceptance contract requires two seconds without reset/triple fault.
    # query-status must remain running and VGA must remain intact after dwell.
    time.sleep(2.0)
    qemu_status = qmp(s, {"execute": "query-status"}).get("return", {}).get("status")
    vals, dump = read_vga()
    idt, _ = read_phys(0x500, 35 * 8)
    pde, _ = read_phys(0x1000, 4)

    # Heartbeat: the timer handler increments the byte at 0x6FC on every
    # serviced IRQ0. Two reads separated by half a second must differ.
    beat1, _ = read_phys(0x6FC, 1)
    time.sleep(0.5)
    beat2, _ = read_phys(0x6FC, 1)
    b1 = beat1[0] if beat1 else None
    b2 = beat2[0] if beat2 else None
    delta = ((b2 - b1) & 0xFF) if (b1 is not None and b2 is not None) else 0
    # 18.2 Hz PIT over ~0.5 s: expect ~9 ticks; allow noisy scheduling.
    heartbeat_ok = b1 is not None and b2 is not None and 1 <= delta <= 127

    print("VGA @0xB8000:", dump.strip().replace("\r\n", " "))
    print("bytes:", " ".join(f"{b:02x}" for b in vals))

    live = qemu.poll() is None and qemu_status == "running"
    ok = live
    gates = [bytes(idt[i:i + 8]) for i in range(0, len(idt), 8)]
    idt_ok = (
        len(gates) == 35
        and all(gate[2:8] == b"\x08\x00\x00\x8e\x00\x00" for gate in gates)
        and all(gate == gates[0] for i, gate in enumerate(gates[:32]) if i != 13)
        and len({gates[i][:2] for i in (0, 13, 32, 33, 34)}) == 5
    )
    pde_value = int.from_bytes(bytes(pde), "little") if len(pde) == 4 else 0
    paging_ok = (pde_value & 0x83) == 0x83 and (pde_value & 0xFFC00000) == 0
    ok = ok and idt_ok and paging_ok and heartbeat_ok
    checks = [
        (0, 0x33, "task0 '3' char @B8000"),
        (1, 0x0F, "task0 attr white @B8001"),
        (2, 0x36, "task1 '6' char @B8002"),
        (3, 0x0F, "task1 attr white @B8003"),
        (4, 0x39, "IPC '9' char @B8004"),
        (5, 0x0A, "IPC attr green @B8005"),
    ]
    for idx, want, desc in checks:
        got = vals[idx] if idx < len(vals) else None
        check_status = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{check_status}] {desc}: got={got:#04x} want={want:#04x}"
              if got is not None else f"  [FAIL] {desc}: missing")

    live_status = "PASS" if live else "FAIL"
    print(f"  [{live_status}] QEMU running after 2.0s dwell: status={qemu_status!r}")
    print("  [PASS] preemption source: task0 is CPU-bound and never sleeps;"
          if live and heartbeat_ok else
          "  [FAIL] preemption/liveness contract",
          "the 6, the 9 and the heartbeat require asynchronous IRQ0 preemption")
    print(f"  [{'PASS' if heartbeat_ok else 'FAIL'}] heartbeat @0x6FC: "
          f"{b1} -> {b2} (+{delta} ticks in 0.5s); a frozen byte would betray a dead PIT")
    print(f"  [{'PASS' if idt_ok else 'FAIL'}] IDT: 31 generic fail-stop + #GP + 3 service gates")
    print(f"  [{'PASS' if paging_ok else 'FAIL'}] PDE0: present | rw | 4MB page "
          f"(runtime={pde_value:#010x})")

    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
finally:
    qemu.terminate()
    try:
        qemu.wait(timeout=3)
    except subprocess.TimeoutExpired:
        qemu.kill()
    tmp.cleanup()
