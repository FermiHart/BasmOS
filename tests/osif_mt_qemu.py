#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
"""Qualify the 512-byte, two-context BasmOS profile on native i386 QEMU.

Every execution uses frozen copies of the supplied bytes and the real UART
loader. QMP memory reads and GDB hardware breakpoints observe the guest; no
debugger memory/register writes or instruction replacements are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from osif_basmos_qemu import (Wire, OsifQmp, OsifGdb, PROMPT, VISIBLE_PROMPT, digest, elf_symbols,
                              file_record, gdb_upload, halt_state, plain,
                              snapshot, static_user_instructions, upload)

ROOT = Path(__file__).resolve().parents[1]
from tools.qemu_lab import parse_map

ARENA_BASE = 0x100000
ARENA_BYTES = 0x200000
MAX_IMAGE = 0x1B0000


def json_lines(data):
    values = []
    for line in plain(data).splitlines():
        if line.startswith((b"{", b"[")):
            try:
                values.append(json.loads(line))
            except (UnicodeError, ValueError):
                pass
    return values


def read_u32(q, address):
    return int.from_bytes(q.read(address, 4), "little")


def ps_snapshot(data):
    return next(v for v in json_lines(data)
                if isinstance(v, dict) and v.get("model") == "fixed-contexts")


def ps_contexts_valid(snapshot):
    tasks = snapshot.get("tasks", [])
    return (snapshot.get("abi") == 2 and snapshot.get("shared_arena") is True and
            len(tasks) == 2 and [t.get("tid") for t in tasks] == [0, 1] and
            [t.get("name") for t in tasks] == ["jash", "ipc-peer"] and
            [t.get("state") for t in tasks] == ["running", "runnable"] and
            all(t.get("cpl") == 3 and t.get("iopl") == 0 for t in tasks) and
            tasks[0].get("commands", 0) > 0 and tasks[1].get("progress", 0) > 0 and
            tasks[1].get("error") == 0)


def progress_snapshot(q, symbols):
    return {name: read_u32(q, ARENA_BASE + symbols[name]) for name in
            ("basmos_peer_progress", "basmos_peer_received",
             "basmos_peer_last", "basmos_peer_error")}


def run_shell(kernel, module, symbols, output):
    cases = []
    with tempfile.TemporaryDirectory(prefix="basmos-mt-jash-") as directory, Wire(directory) as wire:
        with OsifQmp(kernel, wire) as q:
            upload(wire, module)
            if not wire.wait(VISIBLE_PROMPT):
                raise TimeoutError("Jash prompt missing: " + repr(bytes(wire.transcript[-1000:])))
            idle_before = progress_snapshot(q, symbols)
            time.sleep(0.15)
            idle_after = progress_snapshot(q, symbols)

            def command(name, source, predicate):
                offset = len(wire.transcript)
                marker = ("__MT_CASE_%02d__" % len(cases)).encode()
                wire.write(source + b"\recho " + marker + b"\r")
                done = wire.wait(b"\n" + marker + b"\n", offset=offset)
                data = bytes(wire.transcript[offset:])
                error = None
                try:
                    good = done and bool(predicate(data))
                except Exception as exc:
                    good, error = False, repr(exc)
                cases.append({"name": name, "input": source.decode("utf-8", "backslashreplace"),
                              "pass": good, "completed": done, "predicate_error": error,
                              "response": plain(data).decode("utf-8", "backslashreplace")})
                return data

            command("help_has_ps_peer_and_ipc", b"help", lambda d:
                    b" ps" in plain(d) and b"peer" in plain(d) and b"ipc" in plain(d))
            command("argv_quotes_empty_argument", b'argv "a b" \'\' x', lambda d:
                    ["a b", "", "x"] in json_lines(d))
            command("echo_json_array", b'echo --json one "two words" \'\'', lambda d:
                    ["one", "two words", ""] in json_lines(d))
            command("quoted_operators_literal", b"argv 'a|b' 'x;y' '$HOME'", lambda d:
                    ["a|b", "x;y", "$HOME"] in json_lines(d))
            command("strict_json_nested_types", b"json '{\"n\":0,\"ratio\":3.125,\"ok\":true,\"a\":[null,false]}'", lambda d:
                    {"n": 0, "ratio": 3.125, "ok": True, "a": [None, False]} in json_lines(d))
            command("strict_json_nul_escape", b"json '{\"s\":\"zero\\u0000\"}'", lambda d:
                    {"s": "zero\0"} in json_lines(d))
            command("strict_json_duplicate_rejected", b"json '{\"a\":1,\"a\":2}'\rstatus", lambda d:
                    b"\njson: invalid input errno=17\n" in plain(d) and b"\nstatus=2\n" in plain(d))
            command("editor_backspace", b"echo worlX\x7fd", lambda d: b"\nworld\n" in plain(d))
            command("editor_left_insert", b"echo ac\x1b[Db", lambda d: b"\nabc\n" in plain(d))
            command("editor_home_end_colour_width", b"cho ome\x1b[He\x1b[Fga", lambda d:
                    b"\nomega\n" in plain(d) and b"\x1b[7D" in d and PROMPT in d)
            command("editor_delete_colour_width", b"echo abXc\x1b[D\x1b[D\x1b[3~", lambda d:
                    b"\nabc\n" in plain(d) and b"\x1b[2D" in d and PROMPT in d)
            command("editor_ctrl_u", b"echo discarded\x15echo rebuilt", lambda d: b"\nrebuilt\n" in plain(d))
            command("editor_previous_line", b"echo recalled\r\x1b[A", lambda d:
                    plain(d).count(b"\nrecalled\n") == 2)
            command("reject_unquoted_pipeline", b"echo left | echo right\rstatus", lambda d:
                    b"command discarded\n" in plain(d) and b"\nstatus=2\n" in plain(d))
            command("false_status", b"false\rstatus", lambda d: b"\nstatus=1\n" in plain(d))
            command("true_status", b"true\rstatus", lambda d: b"\nstatus=0\n" in plain(d))
            command("native_tx_nul", b"byte 0", lambda d: b"\nbyte[\0] value=0\n" in d)
            command("osif_two_context_profile", b"osif", lambda d:
                    any(isinstance(v, dict) and v.get("abi") == 2 and v.get("ipc") is True
                        and v.get("console") is True and v.get("arena_bytes") == ARENA_BYTES
                        and all(v.get(k) is False for k in ("filesystem", "process_spawn", "network"))
                        for v in json_lines(d)))
            command("osif_unknown_and_zero_length", b"osif test", lambda d:
                    b"\nosif-test open=-38 unknown=-38 zero_write=0\n" in plain(d))
            command("peer_status", b"peer", lambda d:
                    b"progress" in plain(d) and b"received" in plain(d))
            command("ps_table_real_contexts", b"ps", lambda d:
                    b"TID CPL IOPL STATE" in plain(d) and
                    re.search(rb"\n0 +3 +0 +running +jash\n", plain(d)) and
                    re.search(rb"\n1 +3 +0 +runnable +ipc-peer\n", plain(d)))
            before_ps = ps_snapshot(command("ps_json_runtime_privilege", b"ps --json", lambda d:
                    ps_contexts_valid(ps_snapshot(d))))
            time.sleep(0.15)
            after_ps = ps_snapshot(command("ps_short_json_peer_progress", b"ps -j", lambda d:
                    ps_contexts_valid(ps_snapshot(d)) and
                    ps_snapshot(d)["tasks"][1]["progress"] != before_ps["tasks"][1]["progress"] and
                    ps_snapshot(d)["tasks"][1]["received"] == before_ps["tasks"][1]["received"] and
                    ps_snapshot(d)["tasks"][0]["commands"] > before_ps["tasks"][0]["commands"]))
            initial_received = after_ps["tasks"][1]["received"]
            for value in (0, 255, 1, 127, 128, 0):
                command("ipc_roundtrip_%d_%d" % (len(cases), value), ("ipc %d" % value).encode(),
                        lambda d, n=value: ("ipc sent=%d received=%d" % (n, n)).encode() in plain(d))
            command("ps_observes_six_real_ipc_messages", b"ps --json", lambda d:
                    ps_contexts_valid(ps_snapshot(d)) and
                    ps_snapshot(d)["tasks"][1]["received"] == initial_received + 6 and
                    ps_snapshot(d)["tasks"][1]["last"] == 0)
            command("ipc_builtin_regression", b"ipc test", lambda d:
                    b"ipc-test bytes=32 zero=pass empty=pass" in plain(d))
            command("ps_observes_ipc_selftest", b"ps --json", lambda d:
                    ps_contexts_valid(ps_snapshot(d)) and
                    ps_snapshot(d)["tasks"][1]["received"] == initial_received + 38)
            command("ps_rejects_unknown_option", b"ps --bogus\rstatus", lambda d:
                    b"usage: ps" in plain(d) and b"\nstatus=2\n" in plain(d))
            command("ticks_explicitly_unsupported", b"ticks\rstatus", lambda d:
                    b"ticks: unavailable" in plain(d) and b"\nstatus=125\n" in plain(d))
            busy_after = progress_snapshot(q, symbols)
            offset = len(wire.transcript)
            wire.write(b"exit 7\r")
            exit_message = wire.wait(b"Jash BasmOS exit=7\n", offset=offset)
            monitor = halt_state(q)
            exit_record = q.read(0xB08, 2)
            version = q.version
        raw = bytes(wire.transcript)
    checks = {"all_command_cases": all(c["pass"] for c in cases),
              "colour_identity_and_reset_on_real_uart": PROMPT in raw and VISIBLE_PROMPT in plain(raw),
              "peer_progresses_while_prompt_idle": idle_after["basmos_peer_progress"] != idle_before["basmos_peer_progress"],
              "peer_progresses_during_commands": busy_after["basmos_peer_progress"] != idle_after["basmos_peer_progress"],
              "peer_reports_no_transport_error": busy_after["basmos_peer_error"] == 0,
              "peer_received_requests": busy_after["basmos_peer_received"] >= 6,
              "exit_message": exit_message, "exit_status7": exit_record[0] == 7,
              "exit_marker4": exit_record[1] == 4,
              "exit_halts_kernel": "CPL=0" in monitor and "HLT=1" in monitor}
    (output / "jash-mt-session.ansi").write_bytes(raw)
    (output / "jash-mt-session.txt").write_text(plain(raw).decode("utf-8", "backslashreplace").replace("\0", "\\0"))
    return {"pass": all(checks.values()), "checks": checks, "cases": cases,
            "qemu_version": version, "idle_before": idle_before, "idle_after": idle_after,
            "busy_after": busy_after, "exit_status_marker_hex": exit_record.hex(),
            "halt_registers": monitor, "serial_bytes": len(raw)}


def inspect_privileged_footprint(kernel, kernel_symbols, elf):
    binary = kernel.read_bytes()
    instructions = static_user_instructions(elf)
    payload = kernel_symbols["payload_end"]
    checks = {"kernel_is_exactly512": len(binary) == 512,
              "boot_signature55aa": binary[510:] == b"\x55\xaa",
              "payload_within510": 0 < payload <= 510,
              "padding_is_zero": binary[payload:510] == bytes(510 - payload),
              "no_privileged_instructions_in_jash_text": instructions["pass"]}
    return {"pass": all(checks.values()), "checks": checks, "payload_bytes": payload,
            "padding_bytes": 510 - payload, "signature_bytes": 2,
            "module_instruction_audit": instructions,
            "scope": "All supplied supervisor implementation is this boot sector. The separately loaded shell is entered at CPL3. Ordinary BIOS initialization and emulated hardware are not counted as project kernel bytes."}


def build_probe(output):
    source = ROOT / "tests/fixtures/osif_mt_probe.S"
    obj, elf, binary = (output / ("mt-probe." + suffix) for suffix in ("o", "elf", "bin"))
    subprocess.run(["as", "--32", "-o", str(obj), str(source)], check=True)
    subprocess.run(["ld", "-m", "elf_i386", "-Ttext", "0", "-o", str(elf), str(obj)], check=True)
    subprocess.run(["objcopy", "-O", "binary", str(elf), str(binary)], check=True)
    return binary, elf


def run_probe(kernel, probe, symbols, output):
    with tempfile.TemporaryDirectory(prefix="basmos-mt-probe-") as directory, Wire(directory) as wire:
        with OsifQmp(kernel, wire) as q:
            upload(wire, probe.read_bytes())
            requested = wire.wait(b"MT:NEED-NUL\n", timeout=30)
            if requested:
                wire.write(b"\0")
            done = wire.wait(b"MT:DONE\n", timeout=5)
            monitor = halt_state(q)
            state = q.read(0xB00, 16)
            counters = {name: read_u32(q, ARENA_BASE + symbols[name]) for name in
                        ("main_loops", "peer_loops", "peer_error", "peer_received")}
            version = q.version
        raw = bytes(wire.transcript)
    checks = {
        "abi2_caps59_arena2m": b"MT:QUERY\n" in raw,
        "both_contexts_preserve_all_gprs_segments_and_df": b"MT:CONTEXT\n" in raw,
        "main_cpu_loop_progress_without_syscall": counters["main_loops"] >= 100000,
        "peer_cpu_loop_progress_without_syscall": counters["peer_loops"] >= 100000,
        "peer_context_error_zero": counters["peer_error"] == 0,
        "callee_saved_registers_and_enosys": b"MT:CALLEE\n" in raw,
        "mailbox_empty_distinct_from_nul": b"MT:NUL\n" in raw,
        "full_rejected_without_overwrite": b"MT:FULL\n" in raw,
        "channels_independent": b"MT:CHANNELS\n" in raw,
        "all256_values_both_channels_recovery": b"MT:VALUES512\n" in raw,
        "channel_selector_bounded_to_bit0": b"MT:CHANNEL-MASK\n" in raw,
        "actual512_cross_context_roundtrips": b"MT:ROUNDTRIPS512\n" in raw and counters["peer_received"] == 512,
        "requested_native_rx_nul": requested,
        "native_rx_nul_then_empty": b"MT:RX-NUL\n" in raw,
        "native_tx_nul": b"MT:TX[\0]\n" in raw,
        "probe_finished": done,
        "no_failure_marker": b"FAIL:" not in raw,
        "exit_status7_marker4": state[8:10] == b"\x07\x04",
        "exit_kernel_halted": "CPL=0" in monitor and "HLT=1" in monitor,
    }
    (output / "mt-probe-session.bin").write_bytes(raw)
    (output / "mt-probe-session.txt").write_text(raw.decode("utf-8", "backslashreplace").replace("\0", "\\0"))
    return {"pass": all(checks.values()), "checks": checks, "counters": counters,
            "kernel_state_hex": state.hex(), "halt_registers": monitor, "qemu_version": version,
            "implementation": "Independent direct-int21 assembly client; no Jash wrapper; two capacity-one named mailboxes.",
            "capacity_per_channel": 1, "channels": 2, "fifo255_claimed": False,
            "exclusive_cycles": 512, "cross_context_roundtrips": 512}


def observe_contexts(kernel, symbols, module, prompt_offset=None):
    with tempfile.TemporaryDirectory(prefix="basmos-mt-context-") as directory, Wire(directory) as wire:
        with OsifGdb(kernel, wire) as g:
            # A timer may be pending when IF first becomes one. Observe both
            # legal entry orders rather than assuming main wins that race.
            g.breakpoint(ARENA_BASE + 4)
            gdb_upload(g, wire, symbols, module, ARENA_BASE)
            first_regs, first_monitor = g.registers(), g.monitor("info registers")
            first_tss = g.read(0xA00, 104)
            loaded = b"".join(g.read(ARENA_BASE + i, min(1024, len(module) - i))
                              for i in range(0, len(module), 1024))
            syscall_gate = g.read(0x500 + 33 * 8, 8)
            timer_gate = g.read(0x500 + 32 * 8, 8)
            g.breakpoint(ARENA_BASE + first_regs["eip"], remove=True)
            g.resume()
            second_regs, second_monitor = g.registers(), g.monitor("info registers")
            second_tss = g.read(0xA00, 104)
    entries = {first_regs["eip"]: (first_regs, first_monitor, first_tss),
               second_regs["eip"]: (second_regs, second_monitor, second_tss)}
    main_regs, main_monitor, tss = entries[0]
    peer_regs, peer_monitor, peer_tss = entries[4]
    prompt = None
    if prompt_offset is not None:
        with tempfile.TemporaryDirectory(prefix="basmos-mt-prompt-") as directory, Wire(directory) as wire:
            with OsifGdb(kernel, wire) as g:
                gdb_upload(g, wire, symbols, module, ARENA_BASE + prompt_offset)
                prompt = {"registers": g.registers(), "monitor": g.monitor("info registers")}
    cr0 = re.search(r"CR0=([0-9a-f]+)", main_monitor, re.I)
    checks = {
        "main_actual_cpl3": main_regs["cs"] == 0x1B and "CPL=3" in main_monitor,
        "main_entry_offset0": main_regs["eip"] == 0,
        "main_stack1ffff0": main_regs["esp"] == 0x1FFFF0,
        "peer_actual_cpl3": peer_regs["cs"] == 0x1B and "CPL=3" in peer_monitor,
        "peer_entry_offset4": peer_regs["eip"] == 4,
        "peer_stack1bfff0": peer_regs["esp"] == 0x1BFFF0,
        "both_iopl0_if1_df0_initial": all(r["eflags"] & 0x3600 == 0x200 for r in (main_regs, peer_regs)),
        "both_ds_es_ss23_initial": all(r["ds"] == r["es"] == r["ss"] == 0x23 for r in (main_regs, peer_regs)),
        "both_fs_gs_null_initial": all(r["fs"] == r["gs"] == 0 for r in (main_regs, peer_regs)),
        "shared_user_code_arena": all(bool(re.search(r"CS\s*=001b 00100000 001fffff .*DPL=3", m, re.I))
                                      for m in (main_monitor, peer_monitor)),
        "shared_user_data_arena": all(bool(re.search(r"DS\s*=0023 00100000 001fffff .*DPL=3", m, re.I))
                                      for m in (main_monitor, peer_monitor)),
        "paging_disabled": bool(cr0) and int(cr0[1], 16) & 0x80000000 == 0,
        "module_loaded_exactly": loaded == module,
        "main_tss_kernel_stack1800": int.from_bytes(tss[4:8], "little") == 0x1800,
        "peer_tss_kernel_stack1000": int.from_bytes(peer_tss[4:8], "little") == 0x1000,
        "tss_ss0_kernel_data": tss[8:10] == peer_tss[8:10] == b"\x10\0",
        "io_bitmap_beyond_tss": tss[102:104] == b"\x68\0",
        "int21_gate_interrupt_dpl3": syscall_gate[2:6] == b"\x08\0\0\xee",
        "irq0_gate_interrupt_dpl0": timer_gate[2:6] == b"\x08\0\0\x8e",
    }
    if prompt:
        checks["jash_prompt_actual_cpl3"] = prompt["registers"]["cs"] == 0x1B and "CPL=3" in prompt["monitor"]
        checks["jash_prompt_iopl0"] = prompt["registers"]["eflags"] & 0x3000 == 0
    return {"pass": all(checks.values()), "checks": checks,
            "main": {"registers": main_regs, "monitor": main_monitor},
            "peer": {"registers": peer_regs, "monitor": peer_monitor}, "prompt": prompt,
            "loaded_bytes": len(loaded), "loaded_sha256": digest(loaded),
            "debugger_memory_writes": False, "debugger_register_writes": False,
            "guest_instruction_bytes_modified": False}


def loader_bounds(kernel, symbols):
    cases = []
    for length in (0, MAX_IMAGE + 1, 0xFFFFFFFF):
        with tempfile.TemporaryDirectory(prefix="basmos-mt-bound-") as directory, Wire(directory) as wire:
            with OsifQmp(kernel, wire) as q:
                if not wire.wait(b"B"):
                    raise TimeoutError("loader readiness missing")
                before = q.read(ARENA_BASE, 32)
                wire.write(length.to_bytes(4, "little") + b"X" * 32)
                monitor = halt_state(q)
                after = q.read(ARENA_BASE, 32)
                actual = read_u32(q, 0xB04)
        cases.append({"length": length, "expected": "reject before payload store", "observed_length": actual,
                      "pass": before == after and actual == length and "CPL=0" in monitor and "HLT=1" in monitor,
                      "prefix_unchanged": before == after, "halt_registers": monitor})
    # One byte is a valid transfer length but not a two-entry executable.
    # Observe acceptance before launch setup rather than executing invalid code.
    with tempfile.TemporaryDirectory(prefix="basmos-mt-bound-") as directory, Wire(directory) as wire:
        with OsifGdb(kernel, wire) as g:
            launch = 0x7C00 + symbols["enter_user"]
            gdb_upload(g, wire, symbols, b"\x90", launch)
            regs = g.registers()
            actual = read_u32(g, 0xB04)
            first = g.read(ARENA_BASE, 1)
    cases.append({"length": 1, "expected": "accept complete transfer and reach launch setup",
                  "pass": regs["cs"] == 8 and regs["eip"] == launch and actual == 1 and first == b"\x90",
                  "observed_length": actual, "registers": regs})
    with tempfile.TemporaryDirectory(prefix="basmos-mt-bound-") as directory, Wire(directory) as wire:
        with OsifGdb(kernel, wire) as g:
            loader, payload = (0x7C00 + symbols[n] for n in ("load_header", "load_payload"))
            g.breakpoint(loader)
            g.resume()
            g.breakpoint(loader, remove=True)
            g.breakpoint(payload)
            wire.write(MAX_IMAGE.to_bytes(4, "little"))
            g.resume()
            regs, actual = g.registers(), read_u32(g, 0xB04)
    cases.append({"length": MAX_IMAGE, "expected": "accept header and enter payload loop",
                  "pass": regs["cs"] == 8 and regs["eip"] == payload and regs["ecx"] == MAX_IMAGE and regs["edi"] == ARENA_BASE and actual == MAX_IMAGE,
                  "observed_length": actual, "registers": regs, "full_size_payload_transferred": False})
    return {"pass": all(c["pass"] for c in cases), "cases": cases,
            "maximum_image_bytes": MAX_IMAGE,
            "maximum_length_full_payload_transfer_qualified": False}


def protection_faults(kernel, output, kernel_symbols, names=None):
    instructions = {
        # ABI 2 dispatch leaves EAX=0 in the genuine exit handler.
        "ud2_exit_collision": "xorl %ebx, %ebx\nxorl %eax, %eax\nud2",
        "privileged_cli": "cli",
        "privileged_hlt": "hlt",
        "privileged_port_io": "outb %al, $0x80",
        "kernel_data_selector": "movw $0x10, %ax\nmovw %ax, %ds",
        "data_segment_limit": "movl 0x200000, %eax",
        "forged_timer_interrupt": "int $0x20",
    }
    cases, diagnostics = [], []
    for name, fault in instructions.items():
        if names is not None and name not in names:
            continue
        source = (".section .text\n.code32\n.global _start\n_start:\njmp main\n.org 4\npeer:\njmp peer\nmain:\n" +
                  fault + "\nafter_fault:\njmp main\n.section .note.GNU-stack,\"\",@progbits\n")
        src, obj, binary = (output / (name + suffix) for suffix in (".S", ".o", ".bin"))
        src.write_text(source)
        subprocess.run(["as", "--32", "-o", str(obj), str(src)], check=True)
        subprocess.run(["ld", "-m", "elf_i386", "-Ttext", "0", "--oformat", "binary", "-o", str(binary), str(obj)], check=True)
        with tempfile.TemporaryDirectory(prefix="basmos-mt-fault-") as directory, Wire(directory) as wire:
            with OsifQmp(kernel, wire) as q:
                upload(wire, binary.read_bytes())
                monitor = halt_state(q)
                receipt = q.read(0xB08, 2)
        observed_trap = "CPL=0" in monitor and "HLT=1" in monitor and receipt == b"\0\0"
        record = {"name": name, "status_marker_hex": receipt.hex(), "halt_registers": monitor,
                  "fixture": file_record(binary)}
        if name == "data_segment_limit":
            record.update({"status": "observed_trap" if observed_trap else "observed_no_trap",
                           "protection_qualified": observed_trap,
                           "expected": "DS load at offset 0x200000 raises #GP beyond configured limit 0x1fffff",
                           "included_in_functional_pass": False})
            if not observed_trap:
                # QMP can sample the unrelated peer loop. A fresh boot with a
                # hardware breakpoint after the MOV proves the main context
                # actually completed this exact out-of-bounds load.
                fixture_symbols = elf_symbols(obj)
                after = fixture_symbols["after_fault"]
                before = fixture_symbols["main"]
                with tempfile.TemporaryDirectory(prefix="basmos-mt-limit-gdb-") as directory, Wire(directory) as wire:
                    with OsifGdb(kernel, wire) as g:
                        gdb_upload(g, wire, kernel_symbols, binary.read_bytes(), ARENA_BASE + after)
                        regs, registers_text = g.registers(), g.monitor("info registers")
                        opcode = g.read(ARENA_BASE + before, after - before)
                completed = (regs["cs"] == 0x1B and regs["eip"] == after and
                             "CPL=3" in registers_text and opcode == b"\xa1\x00\x00\x20\x00")
                record["offending_load_completed"] = completed
                record["post_load_observation"] = {
                    "method": "fresh serial boot; hardware breakpoint immediately after the offending MOV",
                    "load_offset": before, "after_load_offset": after,
                    "load_instruction_hex": opcode.hex(), "registers": regs,
                    "monitor": registers_text, "debugger_memory_writes": False,
                    "debugger_register_writes": False, "guest_instruction_bytes_modified": False}
            diagnostics.append(record)
        else:
            record["pass"] = observed_trap
            cases.append(record)
    return {"pass": all(c["pass"] for c in cases), "cases": cases,
            "diagnostics": diagnostics,
            "memory_boundary_protection_qualified": all(d["protection_qualified"] for d in diagnostics),
            "scope": "Required cases qualify privilege instructions and faults versus normal exit. Segment-boundary enforcement is retained as a separate explicit diagnostic; a functional pass does not qualify memory containment. No process recovery or mutual task isolation is claimed."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-map", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--module-elf", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/osif-mt/evidence")
    parser.add_argument("--abi-only", action="store_true")
    args = parser.parse_args()
    if not args.abi_only and (not args.module or not args.module_elf):
        parser.error("--module and --module-elf required unless --abi-only")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    kernel, kr = snapshot(args.kernel, output / "basmos-mt.bin")
    kernel_map, km = snapshot(args.kernel_map, output / "basmos-mt.map")
    symbols = parse_map(kernel_map)
    report = {"pass": False, "executor": "QEMU TCG", "physical_hardware": False,
              "pass_scope": "functional execution, preemption, IPC and byte budget; not memory containment",
              "memory_protection_qualified": False,
              "artifacts": {"kernel": kr, "kernel_map": km}, "checks": {},
              "profile": "two preempted CPL3 contexts sharing one 2 MiB user arena; two capacity-one named byte mailboxes"}
    try:
        probe, probe_elf = build_probe(output)
        report["artifacts"]["independent_probe"] = file_record(probe)
        ps = elf_symbols(probe_elf)
        module, elf = probe, probe_elf
        if not args.abi_only:
            module, report["artifacts"]["jash"] = snapshot(args.module, output / "jash-basmos-mt.bin")
            elf, report["artifacts"]["jash_elf"] = snapshot(args.module_elf, output / "jash-basmos-mt.elf")
        report["footprint"] = inspect_privileged_footprint(kernel, symbols, elf)
        # The independent negative/ABI probes deliberately contain privileged
        # fault instructions only in separate negative fixtures, never the shell.
        report["checks"]["hard512_footprint"] = report["footprint"]["pass"]
        if not report["footprint"]["pass"]:
            raise RuntimeError("hard 512-byte footprint gate failed")
        report["abi"] = run_probe(kernel, probe, ps, output)
        report["checks"]["native_abi_and_preemption"] = report["abi"]["pass"]
        print("MT ABI/PREEMPTION:", "PASS" if report["abi"]["pass"] else "FAIL", flush=True)
        report["loader"] = loader_bounds(kernel, symbols)
        report["checks"]["loader_bounds"] = report["loader"]["pass"]
        print("MT LOADER:", "PASS" if report["loader"]["pass"] else "FAIL", flush=True)
        ms = elf_symbols(elf)
        report["contexts"] = observe_contexts(kernel, symbols, module.read_bytes(),
                None if args.abi_only else ms["jash_basmos_prompt"])
        report["checks"]["both_native_cpl3_contexts"] = report["contexts"]["pass"]
        print("MT CPL3 CONTEXTS:", "PASS" if report["contexts"]["pass"] else "FAIL", flush=True)
        report["faults"] = protection_faults(kernel, output, symbols)
        report["checks"]["faults_not_normal_exit"] = report["faults"]["pass"]
        report["memory_protection_qualified"] = report["faults"]["memory_boundary_protection_qualified"]
        print("MT FAULTS:", "PASS" if report["faults"]["pass"] else "FAIL", flush=True)
        if not args.abi_only:
            report["shell"] = run_shell(kernel, module.read_bytes(), ms, output)
            report["checks"]["real_jash_and_peer"] = report["shell"]["pass"]
            print("MT JASH/PEER:", "PASS" if report["shell"]["pass"] else "FAIL", flush=True)
        report["pass"] = all(report["checks"].values())
    except Exception as exc:
        report["error"] = repr(exc)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pass": report["pass"], "error": report.get("error"), "report": str(output / "report.json")}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
