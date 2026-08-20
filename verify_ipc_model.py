#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Exhaustively verify the BasmOS SPSC ring and its machine encoding."""

import argparse
import json
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


RING = 256
ORG = 0x7C00


def send(tail, head):
    next_tail = (tail + 1) % RING
    return (tail, False) if next_tail == head else (next_tail, True)


def recv(tail, head):
    return (head, False) if tail == head else ((head + 1) % RING, True)


def occupancy(tail, head):
    return (tail - head) % RING


def model_check():
    failures = {name: [] for name in ("P1", "P2", "P3", "P4", "P5")}

    # Every possible cursor pair is a reachable abstract queue state. Give
    # every occupied ring position a unique symbolic token, then explore both
    # operations and compare the resulting physical sequence with the FIFO.
    for tail in range(RING):
        for head in range(RING):
            count = occupancy(tail, head)
            queue = [(head + i) % RING for i in range(count)]
            ring = {position: token for position, token in zip(queue, queue)}

            next_tail, wrote = send(tail, head)
            if count == RING - 1:
                if wrote or next_tail != tail:
                    failures["P1"].append((tail, head, "full send mutated state"))
            else:
                if not wrote or occupancy(next_tail, head) != count + 1:
                    failures["P3"].append((tail, head, "send occupancy"))
                else:
                    token = ("new", tail, head)
                    after = dict(ring)
                    after[tail] = token
                    actual = [after[(head + i) % RING] for i in range(count + 1)]
                    if actual != queue + [token]:
                        failures["P4"].append((tail, head, "send reordered FIFO"))

            next_head, got = recv(tail, head)
            if count == 0:
                if got or next_head != head:
                    failures["P2"].append((tail, head, "empty recv mutated state"))
            else:
                if not got or ring[head] != queue[0]:
                    failures["P2"].append((tail, head, "recv read wrong slot"))
                remaining = [ring[(next_head + i) % RING] for i in range(count - 1)]
                if remaining != queue[1:]:
                    failures["P4"].append((tail, head, "recv reordered FIFO"))

            # Draining any state takes exactly occupancy receives, reaches
            # empty, and is followed by a successful send: no stuck state.
            drain_head = head
            for _ in range(count):
                drain_head, got = recv(tail, drain_head)
                if not got:
                    failures["P5"].append((tail, head, "early empty"))
                    break
            if drain_head != tail or recv(tail, drain_head)[1]:
                failures["P5"].append((tail, head, "drain did not reach empty"))
            if not send(tail, drain_head)[1]:
                failures["P5"].append((tail, head, "cannot send after drain"))

    return failures


def parse_map(path):
    symbols = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0])
    return symbols


def verify_encoding(image, symbols):
    data = Path(image).read_bytes()
    send_code = data[symbols["sys_send"]:symbols["sys_recv"]]
    recv_code = data[symbols["sys_recv"]:symbols["idtr"]]
    other_sp = ORG + symbols["other_sp"]
    address = struct.pack("<I", other_sp)

    # Exact handler bodies, not independent substring checks. These encodings
    # bind every modeled guard, branch displacement, memory operation and
    # cursor commit to the freshly assembled artifact.
    expected_send = (
        b"\x89\xca\xfe\xc2"           # mov edx,ecx; inc dl
        b"\x26\x8b\x1d" + address     # mov ebx,es:[other_sp]
        + b"\x26\x3b\x53\x18"        # cmp edx,es:[ebx+24]
        b"\x74\x05"                   # je iretd
        b"\x26\x88\x01"              # mov es:[ecx],al
        b"\x89\xd1\xcf"              # mov ecx,edx; iretd
    )
    expected_recv = (
        b"\x30\xc0"                   # xor al,al
        b"\x26\x8b\x15" + address     # mov edx,es:[other_sp]
        + b"\x26\x3b\x4a\x18"        # cmp ecx,es:[edx+24]
        b"\x74\x05"                   # je iretd
        b"\x26\x8a\x01"              # mov al,es:[ecx]
        b"\xfe\xc1\xcf"              # inc cl; iretd
    )
    checks = (
        (send_code == expected_send, "exact sys_send body matches the model"),
        (recv_code == expected_recv, "exact sys_recv body matches the model"),
    )
    ok = all(result for result, _ in checks)
    for result, description in checks:
        print(f"  [{'PASS' if result else 'FAIL'}] encoding: {description}")
    if send_code != expected_send:
        print(f"    sys_send expected={expected_send.hex()} actual={send_code.hex()}")
    if recv_code != expected_recv:
        print(f"    sys_recv expected={expected_recv.hex()} actual={recv_code.hex()}")
    return ok


class Qemu:
    def __init__(self, image, directory):
        self.socket_path = str(Path(directory) / "qmp.sock")
        self.buffer = b""
        self.process = subprocess.Popen([
            "qemu-system-i386", "-accel", "kvm",
            "-drive", f"format=raw,if=floppy,readonly=on,file={image}",
            "-nic", "none", "-display", "none", "-no-reboot", "-no-shutdown",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            "-qmp", f"unix:{self.socket_path},server,nowait",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            self.socket = self._connect()
            self._receive()
            self.command({"execute": "qmp_capabilities"})
        except Exception:
            if hasattr(self, "socket"):
                self.socket.close()
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            raise

    def _connect(self):
        for _ in range(50):
            try:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(3)
                connection.connect(self.socket_path)
                return connection
            except OSError:
                connection.close()
                time.sleep(0.1)
        raise RuntimeError("could not connect to QEMU QMP socket")

    def _receive(self):
        while b"\n" not in self.buffer:
            chunk = self.socket.recv(65536)
            if not chunk:
                raise RuntimeError("QEMU closed the QMP socket")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def command(self, request):
        self.socket.sendall((json.dumps(request) + "\n").encode())
        while True:
            reply = self._receive()
            if "return" in reply or "error" in reply:
                return reply

    def read(self, address, count):
        reply = self.command({
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
        return bytes(values[-count:]) if len(values) >= count else b""

    def registers(self):
        reply = self.command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": "info registers"},
        }).get("return", "")
        ecx = re.search(r"\bECX=([0-9a-fA-F]+)", reply)
        ds = re.search(r"\bDS\s*=([0-9a-fA-F]+)", reply)
        if not ecx or not ds:
            return None
        return int(ds.group(1), 16), int(ecx.group(1), 16)

    def close(self):
        self.socket.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def empirical_full_probe(image, symbols, directory):
    qemu = Qemu(image, directory)
    try:
        other_sp = ORG + symbols["other_sp"]
        producer = None
        consumer = None
        stable_tail_samples = 0
        deadline = time.time() + 8
        while time.time() < deadline and stable_tail_samples < 20:
            running = qemu.registers()
            if running:
                selector, cursor = running
                if selector == 0x18:
                    producer = cursor & 0xFF
                    if consumer == 1:
                        stable_tail_samples = (stable_tail_samples + 1
                                               if producer == 0 else 0)
                elif selector == 0x20:
                    consumer = cursor & 0xFF

            parked_bytes = qemu.read(other_sp, 4)
            if len(parked_bytes) != 4:
                time.sleep(0.02)
                continue
            parked = int.from_bytes(parked_bytes, "little")
            if not 0x500 <= parked < 0x10000:
                time.sleep(0.02)
                continue
            frame = qemu.read(parked, 28)
            if len(frame) != 28:
                time.sleep(0.02)
                continue
            selector = int.from_bytes(frame[8:12], "little") & 0xFFFF
            cursor = int.from_bytes(frame[24:28], "little") & 0xFF
            if selector == 0x18:
                producer = cursor
                if consumer == 1:
                    stable_tail_samples = (stable_tail_samples + 1
                                           if producer == 0 else 0)
            elif selector == 0x20:
                consumer = cursor
            time.sleep(0.02)

        ok = producer == 0 and consumer == 1 and stable_tail_samples >= 20
        print(f"  [{'PASS' if ok else 'FAIL'}] empirical full ring: "
              f"head={consumer!r}, tail={producer!r}, stable={stable_tail_samples}/20; "
              "expected head=1, tail=0")
        return ok
    finally:
        qemu.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", nargs="?", default="basmos.bin")
    parser.add_argument("assembler", nargs="?", default="basm-nano/basm-nano")
    parser.add_argument("--model-only", action="store_true",
                        help="skip the KVM execution probe")
    args = parser.parse_args()
    kernel = Path(args.kernel)
    assembler = Path(args.assembler)

    failures = model_check()
    descriptions = {
        "P1": "no overwrite / full send is inert",
        "P2": "no overread / empty recv is inert",
        "P3": "occupancy remains within 255",
        "P4": "FIFO ordering across send and recv",
        "P5": "all states drain and recover",
    }
    print("  model: all 65,536 cursor states, both transitions, symbolic FIFO")
    for name, description in descriptions.items():
        count = len(failures[name])
        print(f"  [{'FAIL' if count else 'PASS'}] {name} {description}"
              + (f" ({count} failures)" if count else ""))

    with tempfile.TemporaryDirectory(prefix="ipc-model-") as directory:
        directory = Path(directory)
        normal_map = directory / "normal.map"
        normal = directory / "normal.bin"
        subprocess.run([
            str(assembler), "-f", "bin", "--map", str(normal_map),
            "-o", str(normal), "basmos.basm",
        ], check=True)
        normal_symbols = parse_map(normal_map)
        identity_ok = normal.read_bytes() == kernel.read_bytes()
        print(f"  [{'PASS' if identity_ok else 'FAIL'}] encoding: "
              "model input matches a fresh source build")
        encoding_ok = identity_ok and verify_encoding(kernel, normal_symbols)

        empirical_ok = True
        if not args.model_only:
            probe = directory / "full-probe.bin"
            probe_map = directory / "full-probe.map"
            subprocess.run([
                str(assembler), "-f", "bin", "-DIPC_FULL_PROBE",
                "--map", str(probe_map), "-o", str(probe), "basmos.basm",
            ], check=True)
            probe_symbols = parse_map(probe_map)
            layout_ok = all(name in probe_symbols
                            and normal_symbols[name] == probe_symbols[name]
                            for name in normal_symbols)
            print(f"  [{'PASS' if layout_ok else 'FAIL'}] probe: "
                  "all shared symbol offsets match the shipped build")
            empirical_ok = layout_ok and empirical_full_probe(
                probe, probe_symbols, directory)

    model_ok = not any(failures.values())
    ok = model_ok and encoding_ok and empirical_ok
    success = ("PASS - SPSC model and exact handler encoding agree"
               if args.model_only else
               "PASS - SPSC model, exact encoding, and full-ring execution agree")
    print("RESULT:", success if ok else "FAIL")
    for name in descriptions:
        for failure in failures[name][:3]:
            print(f"    {name}: {failure}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
