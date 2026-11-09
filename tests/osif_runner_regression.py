#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
"""Prove the terminal runner distinguishes real exit zero from a CPL3 fault.

The negative module emits the Jash prompt and executes UD2 with EAX=4/EBX=0.
Its non-error-code exception leaves the same CPL0 stack shape as int 0x80.
Only the kernel-written exit marker reliably distinguishes that fault from
normal exit zero. The ABI 2 variant provides a harmless peer at offset 4 and
uses EAX=0, the post-dispatch exit value. All modules enter through the real
serial loader in QEMU. A positive legacy-prompt fixture waits for the first
command byte before exit zero, while the real Jash requires its ANSI prompt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from osif_basmos_qemu import OsifQmp, Wire, PROMPT, VISIBLE_PROMPT, halt_state, plain, upload

ROOT = Path(__file__).resolve().parents[1]
FAULT_SOURCE = r'''/* SPDX-License-Identifier: BSD-3-Clause */
.section .text
.code32
.global _start
_start:
    cld
    movl $prompt, %esi
next:
    lodsb
    testb %al, %al
    jz fault
    movzbl %al, %ebx
retry:
    movl $1, %eax
    int $0x80
    cmpl $-11, %eax
    je retry
    jmp next
fault:
    xorl %ebx, %ebx
    movl $4, %eax
    ud2
    jmp fault
prompt:
    .asciz "jash[basmos]> "
.section .note.GNU-stack,"",@progbits
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha(data)}


def fault_source(abi):
    if abi == 1:
        return FAULT_SOURCE
    return (FAULT_SOURCE.replace("_start:\n    cld", "_start:\n    jmp main\n    .org 4\npeer:\n    jmp peer\nmain:\n    cld")
            .replace("int $0x80", "int $0x21")
            .replace("movl $4, %eax", "xorl %eax, %eax"))


def legacy_prompt_source(abi):
    """A real legacy-prompt guest that must receive input before exit zero."""
    source = fault_source(abi)
    trap = "int $0x80" if abi == 1 else "int $0x21"
    return (source.split("fault:\n", 1)[0] + f'''fault:
    movl $2, %eax
    {trap}
    cmpl $-11, %eax
    je fault
    cmpl $101, %eax
    jne bad_input
    xorl %ebx, %ebx
    jmp do_exit
bad_input:
    movl $99, %ebx
do_exit:
    movl $4, %eax
    {trap}
    jmp do_exit
prompt:
''' + source.split("prompt:\n", 1)[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--abi", type=int, choices=(1, 2), default=1)
    parser.add_argument("--runner", type=Path, default=ROOT / "tools/run_osif_jash.py")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/osif/runner-validation")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"pass": False, "abi": args.abi, "executor": "QEMU TCG", "physical_hardware": False,
              "checks": {}, "artifacts": {}, "runs": {}}
    try:
        kernel_bytes, module_bytes = args.kernel.read_bytes(), args.module.read_bytes()
        runner = args.runner.resolve()
        report["artifacts"] = {"kernel": record(args.kernel.resolve()),
                               "jash": record(args.module.resolve()), "runner": record(runner)}
        with tempfile.TemporaryDirectory(prefix="osif-runner-regression-") as directory:
            temporary = Path(directory)
            # Every child receives the same byte snapshots.
            kernel, module = temporary / "kernel.bin", temporary / "jash.bin"
            kernel.write_bytes(kernel_bytes)
            module.write_bytes(module_bytes)
            source, obj, fault = (temporary / ("fault." + s) for s in ("S", "o", "bin"))
            source.write_text(fault_source(args.abi))
            subprocess.run(["as", "--32", "-o", str(obj), str(source)], check=True)
            subprocess.run(["ld", "-m", "elf_i386", "-Ttext", "0", "--oformat", "binary",
                            "-o", str(fault), str(obj)], check=True)
            report["fault_fixture_sha256"] = sha(fault.read_bytes())
            (output / "fault-exit-collision.S").write_text(fault_source(args.abi))
            (output / "fault-exit-collision.bin").write_bytes(fault.read_bytes())
            legacy_source, legacy_obj, legacy = (temporary / ("legacy." + s) for s in ("S", "o", "bin"))
            legacy_source.write_text(legacy_prompt_source(args.abi))
            subprocess.run(["as", "--32", "-o", str(legacy_obj), str(legacy_source)], check=True)
            subprocess.run(["ld", "-m", "elf_i386", "-Ttext", "0", "--oformat", "binary",
                            "-o", str(legacy), str(legacy_obj)], check=True)
            report["legacy_fixture_sha256"] = sha(legacy.read_bytes())
            (output / "legacy-prompt-input.S").write_text(legacy_prompt_source(args.abi))
            (output / "legacy-prompt-input.bin").write_bytes(legacy.read_bytes())
            commands0, commands7 = temporary / "exit0.txt", temporary / "exit7.txt"
            commands0.write_text("exit 0\n")
            commands7.write_text("echo OSIF marker ready\njson '{\"demo\":\"BasmOS\",\"n\":0,\"ok\":true}'\nexit 7\n")
            cases = (("real_exit0", module, commands0), ("real_exit7", module, commands7),
                     ("legacy_prompt_input", legacy, commands0), ("ud2_collision", fault, commands0))
            for name, image, commands in cases:
                command = [sys.executable, str(runner), "--kernel", str(kernel),
                           "--abi", str(args.abi),
                           "--module", str(image), "--commands", str(commands),
                           "--timeout", str(args.timeout)]
                result = subprocess.run(command, capture_output=True, timeout=args.timeout + 10)
                (output / (name + ".stdout")).write_bytes(result.stdout)
                (output / (name + ".stderr")).write_bytes(result.stderr)
                report["runs"][name] = {"returncode": result.returncode,
                    "stdout": result.stdout.decode("utf-8", "backslashreplace"),
                    "stderr": result.stderr.decode("utf-8", "backslashreplace")}

            zero, seven, negative = (report["runs"][k] for k in ("real_exit0", "real_exit7", "ud2_collision"))
            legacy_run = report["runs"]["legacy_prompt_input"]
            report["checks"].update({
                "real_module_emits_colour_prompt": PROMPT.decode("ascii") in zero["stdout"],
                "real_module_visible_identity": VISIBLE_PROMPT in plain(zero["stdout"].encode()),
                "real_exit0_returns0": zero["returncode"] == 0,
                "real_exit0_marker4": "memory[0xB08]=0; exit_marker=4; halted=yes." in zero["stderr"],
                "real_exit7_returns7": seven["returncode"] == 7,
                "real_exit7_marker4": "memory[0xB08]=7; exit_marker=4; halted=yes." in seven["stderr"],
                "echo_executed": "\nOSIF marker ready\n" in seven["stdout"],
                "json_executed": '\n{"demo":"BasmOS","n":0,"ok":true}\n' in seven["stdout"],
                "legacy_prompt_still_receives_input": legacy_run["returncode"] == 0 and
                    "jash[basmos]> " in legacy_run["stdout"] and
                    "memory[0xB08]=0; exit_marker=4; halted=yes." in legacy_run["stderr"],
                "ud2_not_reported_exit0": negative["returncode"] == 125,
                "ud2_marker0_abnormal": "abnormal guest halt: memory[0xB08]=0; exit_marker=0; verified OSIF exit absent." in negative["stderr"],
                "ud2_fixture_reached_prompt": "jash[basmos]> " in negative["stdout"],
            })
            # Confirm that the negative fixture really collides with the old
            # register-only detector. The debugger never writes guest state.
            with tempfile.TemporaryDirectory(prefix="osif-exit-state-") as wire_dir, Wire(wire_dir) as wire:
                with OsifQmp(kernel, wire) as qemu:
                    upload(wire, fault.read_bytes())
                    monitor = halt_state(qemu)
                    state = qemu.read(0xB08, 2)
            report["fault_registers"] = monitor
            report["fault_status_marker_hex"] = state.hex()
            eax = "EAX=00000004" if args.abi == 1 else "EAX=00000000"
            stack = "ESP=00000fec" if args.abi == 1 else "ESP=000017ec"
            report["checks"]["fault_matches_exit_register_signature"] = (
                all(token in monitor for token in (eax, "EBX=00000000", stack, "CPL=0", "HLT=1"))
                and state == b"\0\0")
        report["checks"]["runner_unchanged_during_test"] = record(runner)["sha256"] == report["artifacts"]["runner"]["sha256"]
        report["pass"] = all(report["checks"].values())
    except Exception as error:
        report["error"] = repr(error)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("RUNNER EXIT REGRESSION:", "PASS" if report["pass"] else "FAIL")
    print(json.dumps({"pass": report["pass"], "error": report.get("error"),
                      "checks": report["checks"], "report": str(output / "report.json")}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
