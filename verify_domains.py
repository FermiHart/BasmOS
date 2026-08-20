#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Prove BasmOS task-data segmentation with positive and negative executions."""

import json
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


KERNEL = Path(sys.argv[1] if len(sys.argv) > 1 else "basmos.bin")
VM_KERNEL = Path(sys.argv[2] if len(sys.argv) > 2 else "basmos-vm.bin")
ASSEMBLER = Path(sys.argv[3] if len(sys.argv) > 3 else "basm-nano/basm-nano")
VMM = Path(sys.argv[4] if len(sys.argv) > 4 else "bemu/bemu-nano")
ORG = 0x7C00
TASK0_BASE = 0x800
TASK1_BASE = 0x900


def parse_map(path):
    symbols = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0])
    return symbols


class Qemu:
    def __init__(self, image, directory):
        self.sock_path = str(Path(directory) / (Path(image).stem + ".sock"))
        self.buffer = b""
        self.proc = subprocess.Popen([
            "qemu-system-i386",
            "-accel", "kvm",
            "-drive", f"format=raw,if=floppy,readonly=on,file={image}",
            "-nic", "none", "-display", "none", "-no-reboot", "-no-shutdown",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            "-qmp", f"unix:{self.sock_path},server,nowait",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.sock = self._connect()
        self._recv_line()
        self.command({"execute": "qmp_capabilities"})

    def _connect(self):
        for _ in range(50):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect(self.sock_path)
                return sock
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("could not connect to QEMU QMP socket")

    def _recv_line(self):
        while b"\n" not in self.buffer:
            self.buffer += self.sock.recv(65536)
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def command(self, request):
        self.sock.sendall((json.dumps(request) + "\n").encode())
        while True:
            reply = self._recv_line()
            if "return" in reply or "error" in reply:
                return reply

    def hmp(self, command):
        return self.command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": command},
        }).get("return", "")

    def read(self, address, count):
        dump = self.hmp(f"xp /{count}bx {address:#x}")
        values = []
        for token in dump.replace(":", " ").split():
            if token.startswith("0x") and len(token) <= 4:
                try:
                    values.append(int(token, 16))
                except ValueError:
                    pass
        return bytes(values[-count:]) if len(values) >= count else bytes(values)

    def registers(self):
        text = self.hmp("info registers")
        values = {}
        for name in ("EIP", "ESP"):
            match = re.search(rf"\b{name}=([0-9a-fA-F]+)", text)
            if match:
                values[name.lower()] = int(match.group(1), 16)
        return values

    def register_text(self):
        return self.hmp("info registers")

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def assemble(output, map_path, *defines):
    command = [str(ASSEMBLER), "-f", "bin"]
    command.extend(f"-D{name}" for name in defines)
    command.extend(["--map", str(map_path), "-o", str(output), "basmos.basm"])
    subprocess.run(command, check=True)


def code_descriptor(limit, base):
    """Byte-granular 32-bit task code descriptor, accessed at runtime."""
    return bytes([limit & 0xFF, (limit >> 8) & 0xFF,
                  base & 0xFF, (base >> 8) & 0xFF,
                  (base >> 16) & 0xFF, 0x9B, 0x40, (base >> 24) & 0xFF])


def positive_probe(image, symbols, directory):
    qemu = Qemu(image, directory)
    try:
        deadline = time.time() + 8
        private = b""
        while time.time() < deadline:
            private = qemu.read(TASK0_BASE, 1) + qemu.read(TASK1_BASE, 1)
            if private == b"39":
                break
            time.sleep(0.1)

        gdt_base = ORG + symbols["gdt"] - 2
        gdt = qemu.read(gdt_base, 64)
        fixed = bytes.fromhex(
            "ffff0000009bcf00"  # 0x08: flat code (accessed)
            "ffff00000093cf00"  # 0x10: flat kernel data / stacks (accessed)
            "ff00000800934000"  # 0x18: task0, base 0x800, limit 0xff
            "ff00000900934000"  # 0x20: task1, base 0x900, limit 0xff
            "ff0f00800b934000"  # 0x28: VGA, base 0xb8000, limit 0xfff
        )
        task0 = ORG + symbols["task0"]
        task1 = ORG + symbols["task1"]
        exception = ORG + symbols["exception_handler"]
        expected_code = (
            code_descriptor(symbols["task1"] - symbols["task0"] - 1, task0)
            + code_descriptor(symbols["exception_handler"] - symbols["task1"] - 1,
                              task1)
        )
        data_ok = private == b"39" and len(gdt) == 64 and gdt[8:48] == fixed
        code_ok = len(gdt) == 64 and gdt[48:64] == expected_code
        print(f"  [{'PASS' if private == b'39' else 'FAIL'}] own-domain writes: "
              f"task0={private[:1].hex() or 'missing'} task1={private[1:].hex() or 'missing'}")
        print(f"  [{'PASS' if data_ok else 'FAIL'}] "
              "GDT: flat kernel + task0[0x800,0x8ff] + task1[0x900,0x9ff] + VGA")
        print(f"  [{'PASS' if code_ok else 'FAIL'}] "
              f"code windows: task0[{task0:#x},{task1 - 1:#x}] "
              f"task1[{task1:#x},{exception - 1:#x}]")
        if not data_ok or not code_ok:
            print(f"    observed GDT bytes: {gdt.hex() or 'missing'}")
        return data_ok and code_ok
    finally:
        qemu.close()


def negative_probe(image, symbols, directory):
    qemu = Qemu(image, directory)
    gp_halt = ORG + symbols["gp_handler"] + 1
    fault_eip = symbols["domain_fault"] - symbols["task0"]  # offset in CS 0x30
    try:
        deadline = time.time() + 5
        regs = {}
        while time.time() < deadline:
            regs = qemu.registers()
            if regs.get("eip") == gp_halt:
                break
            time.sleep(0.05)
        frame_bytes = qemu.read(regs.get("esp", 0), 16) if "esp" in regs else b""
        frame = [int.from_bytes(frame_bytes[i:i + 4], "little")
                 for i in range(0, len(frame_bytes), 4)]
        exact = (regs.get("eip") == gp_halt and len(frame) == 4
                 and frame[0] == 0 and frame[1] == fault_eip and frame[2] == 0x30)
        own = qemu.read(TASK0_BASE, 1)
        neighbor = qemu.read(TASK1_BASE, 1)
        untouched = own == b"3" and neighbor == b"\0"
        print(f"  [{'PASS' if exact else 'FAIL'}] cross-domain DS:[0x100] -> #GP13: "
              f"handler={regs.get('eip', 0):#x} saved-eip={frame[1] if len(frame) > 1 else 0:#x} error={frame[0] if frame else -1}")
        print(f"  [{'PASS' if untouched else 'FAIL'}] denied access cannot start peer: "
              f"task0={own.hex() or 'missing'} task1={neighbor.hex() or 'missing'}")
        if not exact:
            print(qemu.register_text().strip())
        return exact and untouched
    finally:
        qemu.close()


def code_negative_probe(image, symbols, directory):
    """task0 jumps to task1's first byte; the fetch must raise #GP13."""
    qemu = Qemu(image, directory)
    gp_halt = ORG + symbols["gp_handler"] + 1
    jmp_eip = symbols["domain_code_fault"] - symbols["task0"]
    target_offset = symbols["task1"] - symbols["task0"]
    try:
        deadline = time.time() + 5
        regs = {}
        while time.time() < deadline:
            regs = qemu.registers()
            if regs.get("eip") == gp_halt:
                break
            time.sleep(0.05)
        frame_bytes = qemu.read(regs.get("esp", 0), 16) if "esp" in regs else b""
        frame = [int.from_bytes(frame_bytes[i:i + 4], "little")
                 for i in range(0, len(frame_bytes), 4)]
        gdt_base = ORG + symbols["gdt"] - 2
        gdt = qemu.read(gdt_base, 64)
        limit = gdt[48] | (gdt[49] << 8) if len(gdt) == 64 else -1
        beyond = target_offset > limit
        exact = (regs.get("eip") == gp_halt and len(frame) == 4
                 and frame[0] == 0 and frame[1] == jmp_eip and frame[2] == 0x30)
        vga = qemu.read(0xB8000, 4)
        peer_silent = vga[:2] == b"3\x0f" and vga[2:4] != b"6\x0f"
        print(f"  [{'PASS' if exact and beyond else 'FAIL'}] "
              f"jmp task1's first byte -> #GP13 at the fetch: "
              f"handler={regs.get('eip', 0):#x} saved-eip={frame[1] if len(frame) > 1 else 0:#x} "
              f"cs={frame[2] if len(frame) > 2 else 0:#x}")
        print(f"  [{'PASS' if beyond else 'FAIL'}] live CS window: "
              f"limit={limit:#x} < fetch offset {target_offset:#x}")
        print(f"  [{'PASS' if peer_silent else 'FAIL'}] target code never executed: "
              f"VGA={vga.hex() or 'missing'}")
        if not exact:
            print(qemu.register_text().strip())
        return exact and beyond and peer_silent
    finally:
        qemu.close()


def contract_positive_probe(image):
    result = subprocess.run(
        [str(VMM), str(image), "--contract", "--irqs", "4"],
        capture_output=True, text=True, timeout=15)
    exact = (result.returncode == 0
             and "domains: task0[0x800]=33 task1[0x900]=39" in result.stdout)
    print(f"  [{'PASS' if exact else 'FAIL'}] machine-contract domain bases: "
          "task0=0x800 task1=0x900")
    if not exact:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
    return exact


def contract_negative_probe(image, symbols, fault_symbol, task):
    gp_halt = ORG + symbols["gp_handler"] + 1
    fault_eip = ORG + symbols[fault_symbol]
    result = subprocess.run(
        [str(VMM), str(image), "--contract", "--max-exits", "100000"],
        capture_output=True, text=True, timeout=15)
    eip_match = re.search(r"\beip=(0x[0-9a-fA-F]+)", result.stderr)
    frame_match = re.search(
        r"\bframe=([0-9a-fA-F]{8})/([0-9a-fA-F]{8})/([0-9a-fA-F]{8})/",
        result.stderr)
    eip = int(eip_match.group(1), 16) if eip_match else 0
    frame = ([int(frame_match.group(i), 16) for i in range(1, 4)]
             if frame_match else [])
    exact = (result.returncode == 1 and eip == gp_halt and len(frame) == 3
             and frame[0] == 0 and frame[1] == fault_eip and frame[2] == 8)
    print(f"  [{'PASS' if exact else 'FAIL'}] machine-contract task{task} limit -> #GP13: "
          f"handler={eip:#x} saved-eip={frame[1] if len(frame) > 1 else 0:#x}")
    if not exact:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
    return exact


def main():
    if len(KERNEL.read_bytes()) != 512:
        raise SystemExit(f"FAIL: {KERNEL} is not 512 bytes")
    with tempfile.TemporaryDirectory(prefix="basmos-domains-") as directory:
        normal = Path(directory) / "normal.bin"
        normal_map = Path(directory) / "normal.map"
        fault = Path(directory) / "fault.bin"
        fault_map = Path(directory) / "fault.map"
        code_fault = Path(directory) / "code-fault.bin"
        code_fault_map = Path(directory) / "code-fault.map"
        vm_normal = Path(directory) / "vm-normal.bin"
        vm_normal_map = Path(directory) / "vm-normal.map"
        vm_fault = Path(directory) / "vm-fault.bin"
        vm_fault_map = Path(directory) / "vm-fault.map"
        vm_task1_fault = Path(directory) / "vm-task1-fault.bin"
        vm_task1_fault_map = Path(directory) / "vm-task1-fault.map"
        assemble(normal, normal_map)
        if normal.read_bytes() != KERNEL.read_bytes():
            raise SystemExit("FAIL: committed artifact differs from a fresh domain build")
        assemble(fault, fault_map, "DOMAIN_FAULT_PROBE")
        assemble(code_fault, code_fault_map, "DOMAIN_CODE_FAULT_PROBE")
        assemble(vm_normal, vm_normal_map, "BEMU_CONTRACT")
        if vm_normal.read_bytes() != VM_KERNEL.read_bytes():
            raise SystemExit("FAIL: committed contract artifact differs from a fresh domain build")
        assemble(vm_fault, vm_fault_map, "BEMU_CONTRACT", "DOMAIN_FAULT_PROBE")
        assemble(vm_task1_fault, vm_task1_fault_map,
                 "BEMU_CONTRACT", "DOMAIN_TASK1_FAULT_PROBE")
        positive = positive_probe(normal, parse_map(normal_map), directory)
        negative = negative_probe(fault, parse_map(fault_map), directory)
        code_negative = code_negative_probe(
            code_fault, parse_map(code_fault_map), directory)
        contract_positive = contract_positive_probe(vm_normal)
        contract_task0 = contract_negative_probe(
            vm_fault, parse_map(vm_fault_map), "domain_fault", 0)
        contract_task1 = contract_negative_probe(
            vm_task1_fault, parse_map(vm_task1_fault_map), "domain_task1_fault", 1)
    ok = (positive and negative and code_negative and contract_positive
          and contract_task0 and contract_task1)
    print("RESULT:", "PASS - bounded task domains and #GP denial are exact" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
