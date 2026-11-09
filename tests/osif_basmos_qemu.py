#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Execute the native BasmOS OSIF ABI and real freestanding Jash in QEMU TCG.

Serial uses FIFOs; QMP and GDB use stdio.  The independent ABI client and the
Jash module are booted through the kernel's real serial loader.  Hardware
breakpoints observe CPL3 without replacing any guest instruction.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.gdb_lab import Gdb
from tools.qemu_lab import Qemu, parse_map

ARENA_BASE = 0x100000
ARENA_BYTES = 0x200000
MAX_IMAGE = 0x1F0000
VISIBLE_PROMPT = b"fh@nanokernel.org $ "
PROMPT = b"\x1b[1;36mfh\x1b[0;37m@\x1b[1;32mnanokernel.org\x1b[0m $ "


def digest(data):
    return hashlib.sha256(data).hexdigest()


def plain(data):
    # Preserve literal dots, NULs, and all other non-ANSI payload bytes.
    return re.sub(rb"\x1b\[[0-9;?]*[ -/]*[@-~]", b"", data).replace(b"\r", b"")


class Wire:
    def __init__(self, directory):
        self.path = Path(directory) / "serial"
        for suffix in (".in", ".out"):
            os.mkfifo(str(self.path) + suffix)
        self.input = os.open(str(self.path) + ".in", os.O_RDWR | os.O_NONBLOCK)
        self.output = os.open(str(self.path) + ".out", os.O_RDWR | os.O_NONBLOCK)
        self.transcript = bytearray()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.pump, daemon=True)
        self.thread.start()

    def pump(self):
        while not self.stopped.is_set():
            if select.select([self.output], [], [], 0.02)[0]:
                self.transcript.extend(os.read(self.output, 65536))

    def write(self, data, timeout=30):
        deadline = time.monotonic() + timeout
        while data:
            if time.monotonic() > deadline:
                raise TimeoutError("serial input stalled")
            if select.select([], [self.input], [], 0.05)[1]:
                try:
                    sent = os.write(self.input, data)
                except BlockingIOError:
                    continue
                data = data[sent:]

    def wait(self, marker, timeout=10, offset=0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if marker in plain(bytes(self.transcript[offset:])):
                return True
            time.sleep(0.01)
        return False

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=1)
        os.close(self.input)
        os.close(self.output)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def base_command(image, wire):
    return [os.environ.get("BASMOS_QEMU", "qemu-system-i386"), "-accel", "tcg",
            "-drive", f"format=raw,if=floppy,readonly=on,file={image}",
            "-nic", "none", "-display", "none", "-monitor", "none",
            "-no-reboot", "-no-shutdown", "-m", "16M",
            "-chardev", f"pipe,id=wire,path={wire.path}", "-serial", "chardev:wire"]


class OsifQmp(Qemu):
    def __init__(self, image, wire):
        self.process = subprocess.Popen(base_command(image, wire) + ["-qmp", "stdio"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.buffer = b""
        self.serial = 0
        try:
            self.version = self.receive()["QMP"]["version"]
            self.command("qmp_capabilities")
        except BaseException:
            self.close()
            raise


class OsifGdb(Gdb):
    def __init__(self, image, wire):
        self.process = subprocess.Popen(base_command(image, wire) + ["-S", "-gdb", "stdio"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.buffer = b""
        try:
            self.command("qSupported")
        except BaseException:
            self.close()
            raise

    def receive(self, timeout=30):
        return super().receive(timeout)


def upload(wire, module):
    if not wire.wait(b"B"):
        raise TimeoutError("kernel loader ready byte missing")
    wire.write(len(module).to_bytes(4, "little") + module)


def build_probe(output):
    source = ROOT / "tests/fixtures/osif_abi_probe.S"
    obj, elf, image = (output / ("abi-probe." + s) for s in ("o", "elf", "bin"))
    subprocess.run(["as", "--32", "-o", str(obj), str(source)], check=True)
    subprocess.run(["ld", "-m", "elf_i386", "-Ttext", "0", "-o", str(elf), str(obj)], check=True)
    subprocess.run(["objcopy", "-O", "binary", str(elf), str(image)], check=True)
    return image


def halt_state(q, timeout=3):
    deadline = time.monotonic() + timeout
    monitor = ""
    while time.monotonic() < deadline:
        monitor = q.monitor("info registers")
        if "HLT=1" in monitor:
            return monitor
        time.sleep(0.01)
    return monitor


def run_abi(kernel, probe, output):
    module = probe.read_bytes()
    with tempfile.TemporaryDirectory(prefix="osif-abi-") as directory, Wire(directory) as wire:
        with OsifQmp(kernel, wire) as q:
            upload(wire, module)
            requested = wire.wait(b"NEED-NUL\n")
            before_nul = bytes(wire.transcript)
            if requested:
                wire.write(b"\x00")
            done = wire.wait(b"ABI:DONE\n")
            monitor = halt_state(q)
            state = q.read(0xB00, 12)
            gate = q.read(0x500 + 128 * 8, 8)
            version = q.version
        raw = bytes(wire.transcript)
    checks = {
        "query_abi1_caps15_arena2m": b"QUERY:OK\n" in raw,
        "empty_poll_eagain": b"EMPTY:EAGAIN\n" in before_nul,
        "two_unknown_syscalls_enosys": b"UNKNOWN:ENOSYS\n" in raw,
        "callee_saved_registers_preserved": b"CALLEE:OK\n" in raw,
        "transmitted_nul_byte": b"WRITE:\x00\n" in raw,
        "ticks_advance_in_user_wait": b"TICKS:PROGRESS\n" in raw,
        "requested_nul_input": requested,
        "nul_received_as_zero": b"READ:NUL\n" in raw,
        "empty_after_nul_eagain": b"AFTER:EAGAIN\n" in raw,
        "probe_reached_done": done,
        "exit_status7_recorded": state[8] == 7,
        "exit_marker_recorded": state[9] == 4,
        "exit_enters_kernel_halt": "CPL=0" in monitor and "HLT=1" in monitor,
        "int80_interrupt_gate_dpl3": gate[2:6] == b"\x08\x00\x00\xee",
        "no_probe_failure": b"FAIL:" not in raw,
    }
    (output / "abi-session.bin").write_bytes(raw)
    (output / "abi-session.txt").write_text(raw.decode("utf-8", "backslashreplace").replace("\0", "\\0"))
    return {"pass": all(checks.values()), "checks": checks,
            "implementation": "independent direct int 0x80 assembly client; no Jash wrapper",
            "probe_bytes": len(module), "probe_sha256": digest(module),
            "qemu_version": version, "kernel_state_hex": state.hex(), "halt_registers": monitor}


def gdb_upload(g, wire, kernel_symbols, module, breakpoint):
    # Stop after UART setup before starting a potentially >pipe-buffer upload.
    loader = 0x7C00 + kernel_symbols["load_header"]
    g.breakpoint(loader)
    g.resume()
    if not wire.wait(b"B"):
        raise TimeoutError("GDB run missing loader ready byte")
    g.breakpoint(loader, remove=True)
    g.breakpoint(breakpoint)
    errors = []
    def sender():
        try:
            wire.write(len(module).to_bytes(4, "little") + module)
        except BaseException as exc:
            errors.append(exc)
    writer = threading.Thread(target=sender, daemon=True)
    writer.start()
    g.resume()
    writer.join(timeout=1)
    if errors:
        raise errors[0]
    if writer.is_alive():
        raise TimeoutError("module upload did not complete at entry breakpoint")


def observe_entry(kernel, kernel_symbols, module, prompt_offset=None):
    with tempfile.TemporaryDirectory(prefix="osif-cpl3-") as directory, Wire(directory) as wire:
        with OsifGdb(kernel, wire) as g:
            gdb_upload(g, wire, kernel_symbols, module, ARENA_BASE)
            registers = g.registers()
            monitor = g.monitor("info registers")
            loaded = b"".join(g.read(ARENA_BASE + i, min(1024, len(module)-i))
                              for i in range(0, len(module), 1024))
            tss = g.read(0xA00, 104)
            page_directory = b"".join(g.read(0x1000 + i, 1024) for i in range(0, 4096, 1024))
            prompt = None
            if prompt_offset is not None:
                g.breakpoint(ARENA_BASE, remove=True)
                g.breakpoint(ARENA_BASE + prompt_offset)
                g.resume()
                prompt = {"registers": g.registers(), "monitor": g.monitor("info registers")}
    expected_tss = bytearray(104)
    expected_tss[4:8] = (0x1000).to_bytes(4, "little")
    expected_tss[8:10] = (0x10).to_bytes(2, "little")
    expected_tss[102:104] = (0x68).to_bytes(2, "little")
    checks = {
        "entry_actual_cpl3": registers["cs"] == 0x1B and "CPL=3" in monitor,
        "entry_eip_zero": registers["eip"] == 0,
        "entry_stack_top": registers["esp"] == 0x1FFFF0,
        "entry_ds_es_ss": registers["ds"] == registers["es"] == registers["ss"] == 0x23,
        "entry_iopl_zero_if_enabled_df_clear": registers["eflags"] & 0x3600 == 0x200,
        "entry_code_arena": bool(re.search(r"CS\s*=001b 00100000 001fffff .*DPL=3", monitor, re.I)),
        "entry_data_arena": bool(re.search(r"DS\s*=0023 00100000 001fffff .*DPL=3", monitor, re.I)),
        "loaded_module_exact": loaded == module,
        "tss_esp0": int.from_bytes(tss[4:8], "little") == 0x1000,
        "tss_ss0": int.from_bytes(tss[8:10], "little") == 0x10,
        "io_bitmap_beyond_tss": int.from_bytes(tss[102:104], "little") == 0x68,
        "tss_unused_fields_zero": tss == expected_tss,
        # The accessed/dirty bits can be set by the CPU after enabling paging.
        "single_identity_large_page": int.from_bytes(page_directory[:4], "little") & ~0x60 == 0x87,
        "remaining_page_directory_zero": page_directory[4:] == bytes(4092),
    }
    if prompt:
        checks["jash_prompt_actual_cpl3"] = prompt["registers"]["cs"] == 0x1B and "CPL=3" in prompt["monitor"]
        checks["jash_prompt_iopl_zero"] = prompt["registers"]["eflags"] & 0x3000 == 0
    return {"pass": all(checks.values()), "checks": checks,
            "method": "QEMU GDB stdio hardware breakpoints; guest instruction bytes unchanged",
            "guest_instructions_modified": False, "entry": {"registers": registers, "monitor": monitor},
            "prompt": prompt, "loaded_bytes": len(loaded), "loaded_sha256": digest(loaded)}


def loader_bounds(kernel, symbols):
    cases = []
    for length in (0, MAX_IMAGE + 1, 0xFFFFFFFF):
        with tempfile.TemporaryDirectory(prefix="osif-bound-") as directory, Wire(directory) as wire:
            with OsifQmp(kernel, wire) as q:
                if not wire.wait(b"B"):
                    raise TimeoutError("loader did not announce readiness")
                before = q.read(ARENA_BASE, 32)
                wire.write(length.to_bytes(4, "little") + b"X" * 32)
                monitor = halt_state(q)
                after = q.read(ARENA_BASE, 32)
                actual_length = int.from_bytes(q.read(0xB04, 4), "little")
        ok = before == after and actual_length == length and "CPL=0" in monitor and "HLT=1" in monitor
        cases.append({"length": length, "expected": "reject before payload store",
                      "pass": ok, "payload_prefix_unchanged": before == after,
                      "observed_length": actual_length, "halt_registers": monitor})
    # Exercise the accepted lower boundary with a complete image.
    with tempfile.TemporaryDirectory(prefix="osif-bound-") as directory, Wire(directory) as wire:
        with OsifGdb(kernel, wire) as g:
            gdb_upload(g, wire, symbols, b"\x90", ARENA_BASE)
            regs = g.registers()
            observed_length = int.from_bytes(g.read(0xB04, 4), "little")
            first = g.read(ARENA_BASE, 1)
    ok = regs["cs"] == 0x1B and regs["eip"] == 0 and observed_length == 1 and first == b"\x90"
    cases.append({"length": 1, "expected": "accept complete image and enter CPL3",
                  "pass": ok, "observed_length": observed_length, "entry_registers": regs})
    # Verify acceptance of the upper-bound header directly at the payload
    # loop. A full 1.94 MiB serial transfer is not part of this boundary test;
    # complete transfers are exercised with the ABI and actual Jash modules.
    with tempfile.TemporaryDirectory(prefix="osif-bound-") as directory, Wire(directory) as wire:
        with OsifGdb(kernel, wire) as g:
            loader = 0x7C00 + symbols["load_header"]
            payload = 0x7C00 + symbols["load_payload"]
            g.breakpoint(loader)
            g.resume()
            g.breakpoint(loader, remove=True)
            g.breakpoint(payload)
            wire.write(MAX_IMAGE.to_bytes(4, "little"))
            g.resume()
            regs = g.registers()
            observed_length = int.from_bytes(g.read(0xB04, 4), "little")
    ok = regs["cs"] == 8 and regs["eip"] == payload and regs["ecx"] == MAX_IMAGE and regs["edi"] == ARENA_BASE and observed_length == MAX_IMAGE
    cases.append({"length": MAX_IMAGE, "expected": "accept header and enter payload loop",
                  "pass": ok, "observed_length": observed_length, "payload_loop_registers": regs,
                  "full_size_payload_transferred": False})
    return {"pass": all(c["pass"] for c in cases), "cases": cases,
            "note": "Boundary fixtures are serial-loaded guest images; no debugger writes."}


def elf_symbols(elf):
    output = subprocess.check_output(["nm", "-n", str(elf)], text=True)
    return {parts[2]: int(parts[0], 16) for line in output.splitlines()
            if len(parts := line.split()) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0])}


def static_user_instructions(elf):
    disassembly = subprocess.check_output(["objdump", "-d", str(elf)], text=True)
    forbidden = []
    for line in disassembly.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9]*)\b", line)
        if match and match[2] in {"in", "inb", "inw", "inl", "out", "outb", "outw", "outl", "cli", "sti", "hlt", "lgdt", "lidt", "ltr"}:
            forbidden.append(line.strip())
    return {"pass": not forbidden, "forbidden_instructions": forbidden,
            "scope": "objdump -d of executable sections in the linked Jash ELF; not a proof about arbitrary hostile code"}


def run_shell(kernel, module, output):
    cases = []
    def json_lines(data):
        values = []
        for line in plain(data).splitlines():
            if line.startswith((b"{", b"[")):
                try:
                    values.append(json.loads(line))
                except (ValueError, UnicodeError):
                    pass
        return values
    with tempfile.TemporaryDirectory(prefix="osif-jash-") as directory, Wire(directory) as wire:
        with OsifQmp(kernel, wire) as q:
            upload(wire, module)
            ready = wire.wait(VISIBLE_PROMPT)
            if not ready:
                raise TimeoutError("Jash native prompt missing: " + repr(bytes(wire.transcript[-1000:])))
            ticks_before = int.from_bytes(q.read(0xB00, 4), "little")
            time.sleep(0.08)
            ticks_after = int.from_bytes(q.read(0xB00, 4), "little")
            def command(name, commands, predicate):
                offset = len(wire.transcript)
                marker = ("__OSIF_CASE_%02d__" % len(cases)).encode()
                wire.write(commands + b"\recho " + marker + b"\r")
                finished = wire.wait(b"\n" + marker + b"\n", offset=offset)
                data = bytes(wire.transcript[offset:])
                error = None
                try:
                    good = finished and bool(predicate(data))
                except Exception as exc:
                    good, error = False, repr(exc)
                cases.append({"name": name, "input": commands.decode("utf-8", "backslashreplace"),
                              "pass": good, "completed": finished, "predicate_error": error,
                              "response": plain(data).decode("utf-8", "backslashreplace")})
                return data
            command("help_registry", b"help", lambda d:
                    b"Jash BasmOS commands: help version echo argv json osif uname ps ticks status clear true false exit byte\n" in plain(d))
            command("canonical_source_version", b"version", lambda d:
                    b"082ab18b1770ae32c54ab34acf87666935416090 / i386 OSIF v1" in d)
            command("argv_quotes_empty_argument", b'argv "a b" \'\' x', lambda d:
                    ["a b", "", "x"] in json_lines(d))
            command("echo_json_array", b'echo --json one "two words" \'\'', lambda d:
                    ["one", "two words", ""] in json_lines(d))
            command("echo_literal_arguments", b"echo alpha 'two words' '' omega", lambda d:
                    b"\nalpha two words  omega\n" in plain(d))
            command("quoted_operators_stay_literal", b"argv 'a|b' 'x;y' '$HOME'", lambda d:
                    ["a|b", "x;y", "$HOME"] in json_lines(d))
            expected_json = {"name": "BasmOS", "n": 7, "ratio": 3.125, "exponent": 602.0,
                             "ok": True, "a": [None, False]}
            command("strict_json_nested_types", b"json '{\"name\":\"BasmOS\",\"n\":7,\"ratio\":3.125,\"exponent\":6.02e2,\"ok\":true,\"a\":[null,false]}'",
                    lambda d: expected_json in json_lines(d))
            command("strict_json_escapes", b"json '{\"s\":\"line\\nquote\\\" slash\\\\ zero\\u0000\"}'", lambda d:
                    {"s": 'line\nquote" slash\\ zero\0'} in json_lines(d))
            command("reject_duplicate_json_keys", b"json '{\"a\":1,\"a\":2}'\rstatus", lambda d:
                    b"\njson: invalid input errno=17\n" in plain(d) and b"\nstatus=2\n" in plain(d))
            command("reject_json_trailing_content", b"json '{\"a\":1}x'\rstatus", lambda d:
                    b"\njson: invalid input errno=" in plain(d) and b"\nstatus=2\n" in plain(d))
            command("osif_actual_capabilities", b"osif", lambda d:
                    any(isinstance(v, dict) and v.get("target") == "basmos" and v.get("abi") == 1 and
                        v.get("kernel_caps") == 15 and v.get("arena_bytes") == ARENA_BYTES and
                        v.get("console") is True and v.get("ticks") is True and
                        all(v.get(k) is False for k in ("filesystem", "process_spawn", "ipc", "network"))
                        for v in json_lines(d)))
            command("osif_unsupported_and_zero_length", b"osif test", lambda d:
                    b"\nosif-test open=-38 unknown=-38 zero_write=0\n" in plain(d))
            command("osinfo_identity", b"uname", lambda d:
                    bool(re.search(rb"\nBasmOS [^\n]+ i[3-6]86\n", plain(d))))
            first_tick = command("ticks_command", b"ticks", lambda d:
                    bool(re.search(rb"\nticks=\d+\n", plain(d))))
            time.sleep(0.04)
            command("ticks_advance", b"ticks", lambda d:
                    int(re.search(rb"\nticks=(\d+)\n", plain(d))[1]) >
                    int(re.search(rb"\nticks=(\d+)\n", plain(first_tick))[1]) if re.search(rb"\nticks=(\d+)\n", plain(d)) else False)
            command("byte_zero_output", b"byte 0", lambda d: b"\nbyte[\0] value=0\n" in d)
            command("false_status", b"false\rstatus", lambda d: b"\nstatus=1\n" in plain(d))
            command("true_status", b"true\rstatus", lambda d: b"\nstatus=0\n" in plain(d))
            command("unknown_command_status", b"no_such_command\rstatus", lambda d:
                    b"\njash: unavailable command: no_such_command\n" in plain(d) and b"\nstatus=127\n" in plain(d))
            command("reject_unquoted_pipeline", b"echo left | echo right\rstatus", lambda d:
                    b"\njash: unsupported syntax or unclosed quote; command discarded\n" in plain(d) and b"\nstatus=2\n" in plain(d) and
                    b"\nleft\n" not in plain(d) and b"\nright\n" not in plain(d))
            command("reject_unclosed_quote", b"echo 'unfinished\rstatus", lambda d:
                    b"command discarded\n" in plain(d) and b"\nstatus=2\n" in plain(d))
            command("editor_backspace", b"echo worlX\x7fd", lambda d: b"\nworld\n" in plain(d))
            command("editor_left_insert", b"echo ac\x1b[Db", lambda d: b"\nabc\n" in plain(d))
            command("editor_home_end_colour_width", b"cho ome\x1b[He\x1b[Fga", lambda d:
                    b"\nomega\n" in plain(d) and b"\x1b[7D" in d and PROMPT in d)
            command("editor_delete_colour_width", b"echo abXc\x1b[D\x1b[D\x1b[3~", lambda d:
                    b"\nabc\n" in plain(d) and b"\x1b[2D" in d and PROMPT in d)
            command("editor_ctrl_u", b"echo discarded\x15echo rebuilt", lambda d: b"\nrebuilt\n" in plain(d))
            command("editor_previous_line", b"echo recalled\r\x1b[A", lambda d: plain(d).count(b"\nrecalled\n") == 2)
            command("crlf_single_command", b"echo crlf\r\nstatus", lambda d:
                    plain(d).count(b"\ncrlf\n") == 1 and b"\nstatus=0\n" in plain(d))
            command("oversize_line_discarded", b"echo " + b"x"*1024 + b"\rstatus", lambda d:
                    b"\njash: line too long; command discarded\n" in plain(d) and b"\nstatus=2\n" in plain(d) and
                    b"\n" + b"x"*100 not in plain(d))
            command("clear_sequence", b"clear", lambda d: b"\x1b[2J\x1b[H" in d)
            command("ps_single_context_observed_privilege", b"ps --json", lambda d:
                    any(isinstance(v, dict) and v.get("model") == "fixed-contexts" and
                        v.get("abi") == 1 and v.get("shared_arena") is False and
                        len(v.get("tasks", [])) == 1 and v["tasks"][0].get("tid") == 0 and
                        v["tasks"][0].get("name") == "jash" and v["tasks"][0].get("cpl") == 3 and
                        v["tasks"][0].get("iopl") == 0 and v["tasks"][0].get("commands", 0) > 0
                        for v in json_lines(d)))
            offset = len(wire.transcript)
            wire.write(b"exit 7\r")
            exit_message = wire.wait(b"Jash BasmOS exit=7\n", offset=offset)
            monitor = halt_state(q)
            exit_record = q.read(0xB08, 2)
            exit_status = exit_record[0]
            version = q.version
        raw = bytes(wire.transcript)
    checks = {"startup_prompt": ready,
              "colour_identity_and_reset_on_real_uart": PROMPT in raw and VISIBLE_PROMPT in plain(raw),
              "timer_progress_while_prompt_idle": ticks_after > ticks_before,
              "all_command_cases": all(c["pass"] for c in cases), "exit_message": exit_message,
              "exit_status7": exit_status == 7, "exit_marker": exit_record[1] == 4,
              "exit_kernel_halt": "CPL=0" in monitor and "HLT=1" in monitor}
    (output / "jash-session.ansi").write_bytes(raw)
    (output / "jash-session.txt").write_text(plain(raw).decode("utf-8", "backslashreplace").replace("\0", "\\0"))
    return {"pass": all(checks.values()), "checks": checks, "cases": cases,
            "qemu_version": version, "serial_bytes": len(raw), "idle_ticks": [ticks_before, ticks_after],
            "exit_status": exit_status, "exit_registers": monitor,
            "normalization": "ANSI CSI sequences and CR removed; NUL escaped in text copy; raw bytes retained"}


def file_record(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": digest(data)}


def snapshot(source, destination):
    # Read each supplied artifact once, then boot and inspect only these
    # immutable-for-this-run copies. This binds every phase to the same bytes.
    data = source.resolve().read_bytes()
    destination.write_bytes(data)
    record = file_record(destination)
    record["source_path"] = str(source.resolve())
    return destination, record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=ROOT / "experiments/osif/basmos-osif.bin")
    parser.add_argument("--kernel-map", type=Path, default=ROOT / "experiments/osif/basmos-osif.map")
    parser.add_argument("--module", type=Path)
    parser.add_argument("--module-elf", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "evidence/lab/osif-basmos")
    parser.add_argument("--abi-only", action="store_true")
    args = parser.parse_args()
    if not args.abi_only and (not args.module or not args.module_elf):
        parser.error("--module and --module-elf are required unless --abi-only is used")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    kernel, kernel_record = snapshot(args.kernel, output / "basmos-osif.bin")
    kernel_map, kernel_map_record = snapshot(args.kernel_map, output / "basmos-osif.map")
    symbols = parse_map(kernel_map)
    report = {"executor": "QEMU TCG", "physical_hardware": False,
              "scope": "native kernel ABI only" if args.abi_only else "native kernel ABI and real reduced Jash profile",
              "pass": False, "artifacts": {"kernel": kernel_record, "kernel_map": kernel_map_record}, "checks": {},
              "coverage": {"maximum_length_header_accepted": None,
                           "maximum_length_full_payload_transfer_qualified": False,
                           "full_transfers": [],
                           "earlier_max_transfer": "Initial full 0x1f0000-byte UART transfer exceeded the 30-second GDB timeout; no PASS claimed for that transfer."}}
    try:
        module = elf = None
        if not args.abi_only:
            module, report["artifacts"]["jash"] = snapshot(args.module, output / "jash-basmos.bin")
            elf, report["artifacts"]["jash_elf"] = snapshot(args.module_elf, output / "jash-basmos.elf")
            report["kernel_and_jash_bytes"] = kernel.stat().st_size + module.stat().st_size
        probe = build_probe(output)
        report["artifacts"]["independent_abi_probe"] = file_record(probe)
        report["checks"]["sector512_signature"] = kernel.stat().st_size == 512 and kernel.read_bytes()[-2:] == b"\x55\xaa"
        report["kernel_payload_bytes"] = symbols["payload_end"]
        report["abi"] = run_abi(kernel, probe, output)
        report["checks"]["native_abi"] = report["abi"]["pass"]
        if report["abi"]["pass"]:
            report["coverage"]["full_transfers"].append("independent_abi_probe")
        print("NATIVE ABI:", "PASS" if report["abi"]["pass"] else "FAIL", flush=True)
        report["loader"] = loader_bounds(kernel, symbols)
        report["coverage"]["maximum_length_header_accepted"] = report["loader"]["cases"][-1]["pass"]
        report["checks"]["loader_bounds"] = report["loader"]["pass"]
        print("LOADER BOUNDS:", "PASS" if report["loader"]["pass"] else "FAIL", flush=True)
        if args.abi_only:
            report["privileges"] = observe_entry(kernel, symbols, probe.read_bytes())
        else:
            jash_symbols = elf_symbols(elf)
            report["privileges"] = observe_entry(kernel, symbols, module.read_bytes(), jash_symbols["jash_basmos_prompt"])
            report["user_instructions"] = static_user_instructions(elf)
            report["checks"]["user_instructions"] = report["user_instructions"]["pass"]
            report["commands"] = run_shell(kernel, module.read_bytes(), output)
            report["checks"]["commands"] = report["commands"]["pass"]
            if report["privileges"]["checks"]["loaded_module_exact"]:
                report["coverage"]["full_transfers"].append("complete_jash_module")
            print("JASH COMMANDS:", "PASS" if report["commands"]["pass"] else "FAIL", flush=True)
        report["checks"]["privileges"] = report["privileges"]["pass"]
        print("CPU PRIVILEGES:", "PASS" if report["privileges"]["pass"] else "FAIL", flush=True)
        report["pass"] = all(report["checks"].values())
    except Exception as exc:
        report["error"] = repr(exc)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pass": report["pass"], "error": report.get("error"), "report": str(output / "report.json")}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
