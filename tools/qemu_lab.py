#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Small QMP stdio adapter: no Unix/TCP socket is needed for local probes."""
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time


class Qemu:
    def __init__(self, arguments, executable=None):
        command = [executable or os.environ.get("BASMOS_QEMU", "qemu-system-i386")]
        command += ["-accel", "tcg", "-display", "none", "-nic", "none", "-serial", "none",
                    "-monitor", "none", "-no-reboot", "-no-shutdown",
                    "-qmp", "stdio"] + list(arguments)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.buffer = b""
        self.serial = 0
        try:
            greeting = self.receive()
            if "QMP" not in greeting:
                raise RuntimeError(f"missing QMP greeting: {greeting}")
            self.version = greeting["QMP"]["version"]
            self.command("qmp_capabilities")
        except BaseException:
            self.close()
            raise

    def receive(self, timeout=10):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("QMP response timed out")
            ready, _, _ = select.select([self.process.stdout], [], [], left)
            if not ready:
                raise TimeoutError("QMP response timed out")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                details = self.process.stderr.read().decode(errors="replace")
                raise RuntimeError(f"QEMU closed QMP: {details}")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def command(self, command, arguments=None):
        self.serial += 1
        request = {"execute": command, "id": self.serial}
        if arguments is not None:
            request["arguments"] = arguments
        self.process.stdin.write((json.dumps(request) + "\n").encode())
        self.process.stdin.flush()
        while True:
            reply = self.receive()
            if reply.get("id") == self.serial:
                if "error" in reply:
                    raise RuntimeError(reply["error"])
                return reply.get("return")

    def monitor(self, command):
        return self.command("human-monitor-command", {"command-line": command})

    def read(self, address, count):
        dump = self.monitor(f"xp /{count}bx {address:#x}")
        values = re.findall(r"(?<![0-9A-Fa-f])0x([0-9A-Fa-f]{2})(?![0-9A-Fa-f])", dump)
        if len(values) != count:
            raise RuntimeError(f"QMP memory read size {len(values)} != {count}: {dump}")
        return bytes(int(x, 16) for x in values)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.stderr = self.process.stderr.read().decode(errors="replace")
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def parse_map(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if len(parts) == 3:
            result[parts[2]] = int(parts[0])
    return result
