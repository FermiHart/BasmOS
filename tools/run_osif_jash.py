#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
"""Boot the BasmOS OSIF sector, load Jash, and attach its serial terminal.

Interactive mode forwards terminal bytes; Ctrl-] quits the host runner and
restores terminal settings. With --commands FILE, LF/CRLF command lines are
sent after the Jash prompt and the runner returns the guest's exit status.
Command files should finish with `exit N`. A timeout returns 124; an abnormal
halt or runner error returns 125. QEMU uses TCG, serial FIFOs and QMP stdio.
"""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import tty

from qemu_lab import Qemu

MAX_MODULE_BYTES = 0x1F0000
PROMPT = b"jash[basmos]> "


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


@contextmanager
def terminal_mode(interactive):
    """Restore the terminal for normal exit, Ctrl-], exceptions and signals."""
    previous = {}
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd) if interactive else None
    def interrupted(signum, _frame):
        raise Interrupted(signum)
    try:
        for signum in (signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, interrupted)
        if interactive:
            tty.setraw(fd, when=termios.TCSANOW)
            # The guest emits LF. Retain normal terminal output line endings
            # while making input raw, including Ctrl-C and editing sequences.
            attributes = termios.tcgetattr(fd)
            attributes[1] |= termios.OPOST | termios.ONLCR
            termios.tcsetattr(fd, termios.TCSANOW, attributes)
        yield fd
    finally:
        if saved is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


class Serial:
    def __init__(self, directory):
        self.path = Path(directory) / "serial"
        for suffix in (".in", ".out"):
            os.mkfifo(str(self.path) + suffix, mode=0o600)
        self.input = os.open(str(self.path) + ".in", os.O_RDWR | os.O_NONBLOCK)
        self.output = os.open(str(self.path) + ".out", os.O_RDWR | os.O_NONBLOCK)
        self.tail = b""

    def receive(self, emit=True):
        try:
            data = os.read(self.output, 65536)
        except BlockingIOError:
            return b""
        self.tail = (self.tail + data)[-8192:]
        if emit and data:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        return data

    def ready(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([self.output], [], [], 0.05)[0]:
                data = self.receive(emit=False)
                if b"B" in data:
                    # The loader's single-byte greeting is a protocol byte,
                    # not part of the user's Jash terminal.
                    after = data.split(b"B", 1)[1]
                    if after:
                        sys.stdout.buffer.write(after)
                        sys.stdout.buffer.flush()
                    return
        raise TimeoutError("kernel did not send the BasmOS loader ready byte")

    def send(self, data, timeout):
        remaining = memoryview(data)
        deadline = time.monotonic() + timeout
        while remaining:
            if time.monotonic() >= deadline:
                raise TimeoutError("serial module upload timed out")
            readable, writable, _ = select.select([self.output], [self.input], [], 0.05)
            if readable:
                self.receive()
            if writable:
                try:
                    remaining = remaining[os.write(self.input, remaining):]
                except BlockingIOError:
                    pass

    def close(self):
        os.close(self.input)
        os.close(self.output)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class SerialQemu(Qemu):
    def __init__(self, kernel, serial):
        # Reuse the QMP implementation while choosing COM1's real backend.
        # Adding a second -serial after Qemu's default -serial none would
        # attach the terminal to COM2 instead of this kernel's COM1.
        command = [os.environ.get("BASMOS_QEMU", "qemu-system-i386"),
                   "-accel", "tcg", "-m", "16M", "-display", "none",
                   "-nic", "none", "-monitor", "none", "-no-reboot", "-no-shutdown",
                   "-drive", f"format=raw,if=floppy,readonly=on,file={kernel}",
                   "-chardev", f"pipe,id=console,path={serial.path}",
                   "-serial", "chardev:console", "-qmp", "stdio"]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.buffer = b""
        self.serial = 0
        try:
            self.version = self.receive()["QMP"]["version"]
            self.command("qmp_capabilities")
        except BaseException:
            self.close()
            raise


def guest_exit(qemu, registers):
    """Require the kernel exit marker; fault registers can mimic an exit frame."""
    status, exit_marker = qemu.read(0xB08, 2)
    def register(name):
        match = re.search(r"\b" + name + r"=([0-9a-fA-F]{8})\b", registers)
        return int(match[1], 16) if match else None
    eax, ebx, esp = (register(name) for name in ("EAX", "EBX", "ESP"))
    normal = (exit_marker == 4 and "CPL=0" in registers and "HLT=1" in registers and eax == 4 and
              ebx is not None and (ebx & 255) == status and esp == 0xFEC)
    if normal:
        print(f"\n[BasmOS] guest OSIF exit: status={status}; memory[0xB08]={status}; exit_marker={exit_marker}; halted=yes.", file=sys.stderr)
        return status
    print(f"\n[BasmOS] abnormal guest halt: memory[0xB08]={status}; exit_marker={exit_marker}; verified OSIF exit absent.", file=sys.stderr)
    return 125


def session(qemu, serial, module, commands, timeout, input_fd):
    serial.ready(timeout)
    serial.send(len(module).to_bytes(4, "little") + module, timeout)
    pending = b""
    prompt_seen = False
    commands_sent = False
    deadline = time.monotonic() + timeout
    next_check = 0.0
    while True:
        now = time.monotonic()
        if not prompt_seen and PROMPT in serial.tail:
            prompt_seen = True
            deadline = now + timeout
        if prompt_seen and commands is not None and not commands_sent:
            pending += commands
            commands_sent = True
        readers = [serial.output]
        if commands is None and prompt_seen:
            readers.append(input_fd)
        readable, writable, _ = select.select(readers, [serial.input] if pending else [], [], 0.05)
        if serial.output in readable:
            serial.receive()
        if input_fd in readable:
            data = os.read(input_fd, 4096)
            if not data or b"\x1d" in data:
                print("\n[BasmOS] terminal detached; guest exit was not requested.", file=sys.stderr)
                return 0
            pending += data
        if writable:
            try:
                pending = pending[os.write(serial.input, pending):]
            except BlockingIOError:
                pass
        now = time.monotonic()
        if now >= next_check:
            registers = qemu.monitor("info registers")
            if "HLT=1" in registers:
                # Drain the final UART bytes before the exit receipt.
                until = time.monotonic() + 0.05
                while time.monotonic() < until:
                    if select.select([serial.output], [], [], 0.01)[0]:
                        serial.receive()
                return guest_exit(qemu, registers)
            next_check = now + 0.1
        if now >= deadline and (commands is not None or not prompt_seen):
            label = "command file did not reach guest exit" if prompt_seen else "Jash prompt did not appear"
            raise TimeoutError(label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True, help="512-byte BasmOS OSIF sector")
    parser.add_argument("--module", type=Path, required=True, help="flat freestanding Jash binary")
    parser.add_argument("--commands", type=Path, help="command file ending with exit N; - reads stdin")
    parser.add_argument("--timeout", type=float, default=30,
                        help="boot/upload and command-mode timeout in seconds (default: 30)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    interactive = args.commands is None
    if interactive and not sys.stdin.isatty():
        parser.error("interactive mode requires a terminal; use --commands FILE")
    try:
        kernel = args.kernel.resolve()
        sector = kernel.read_bytes()
        if len(sector) != 512 or sector[-2:] != b"\x55\xaa":
            raise ValueError("kernel must be a complete 512-byte boot sector with signature 55 AA")
        module = args.module.read_bytes()
        if not 1 <= len(module) <= MAX_MODULE_BYTES:
            raise ValueError(f"module length must be 1..{MAX_MODULE_BYTES} bytes")
        commands = None
        if args.commands is not None:
            commands = sys.stdin.buffer.read() if str(args.commands) == "-" else args.commands.read_bytes()
            commands = commands.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r")
            if not commands.endswith(b"\r"):
                commands += b"\r"
        if interactive:
            print("[BasmOS] loading Jash; Ctrl-] quits the host terminal.", file=sys.stderr)
        with terminal_mode(interactive) as input_fd:
            with tempfile.TemporaryDirectory(prefix="basmos-jash-") as directory:
                with Serial(directory) as serial, SerialQemu(kernel, serial) as qemu:
                    return session(qemu, serial, module, commands, args.timeout, input_fd)
    except TimeoutError as error:
        print(f"[BasmOS] timeout: {error}", file=sys.stderr)
        return 124
    except Interrupted as error:
        return 128 + error.signum
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError) as error:
        print(f"[BasmOS] runner error: {error}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    sys.exit(main())
