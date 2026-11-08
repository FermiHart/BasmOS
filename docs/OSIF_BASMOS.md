<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Native Jash through OSIF BasmOS

For the subsequent 512-byte profile with two preempted contexts and byte
mailboxes, see [OSIF ABI 2](OSIF_BASMOS_MT.md). This page records the separate
ABI 1 implementation and its original qualification.

The experimental `basmos-osif` profile boots a freestanding i386 Jash module
in CPL3 and offers a versioned console/timer/exit interface. The complete BIOS
sector is 512 bytes: 509 bytes of payload, 1 padding byte and the boot
signature. The Jash program is loaded separately through COM1.

This is an additive profile. `basmos.bin`, `basmos-vm.bin`, `basmos-sh.bin`
and the original JASH256 capsule retain their existing contracts. The OSIF
profile does not contain the scheduler or IPC of the separate two-task
experiments. It currently runs one user task.

## Build and reproduce

Use the matching Jash `c/osif/basmos` backend and native profile. Jash's
reused editor, key decoder, argv and JSON sources were taken unchanged from
`FermiHart/jash` revision `082ab18b1770ae32c54ab34acf87666935416090`.

From this repository, with the Jash OSIF checkout available:

```sh
make -f Makefile.osif osif
make -f Makefile.osif osif-verify JASH_ROOT=/path/to/jash
```

For an interactive terminal:

```sh
make -f Makefile.osif osif-run JASH_ROOT=/path/to/jash
```

Ctrl-] detaches the host terminal. `exit N` exits the guest and returns its
status from the runner. The runner also accepts `--commands FILE` for a
deterministic command file ending in `exit N`, and reports timeouts and abnormal
halts separately. It restores terminal settings when the interactive session
ends. The kernel's exit record includes a marker, so a fault with an untouched
zero status byte is not reported as a successful exit.

Requirements are GCC with freestanding `-m32` support, GNU binutils, Make,
Python 3 and QEMU's i386 system emulator with BIOS firmware. No host 32-bit libc
is linked. Tests use QEMU TCG, filesystem FIFOs and QMP/GDB stdio; no KVM device
or socket listener is required. `BASMOS_QEMU=/path/to/wrapper` can select a
configured QEMU installation. The native report and exact tested artifacts
are written to `build/osif/evidence/`.

To test the kernel independently of Jash:

```sh
make -f Makefile.osif osif-abi
```

The independent assembly client uses the kernel's real interrupt gateway.
The complete Jash run separately exercises the actual OSIF C adapter.

## What runs where

| User mode, CPL3 | Kernel, CPL0 |
| --- | --- |
| Canonical Jash editor and key decoder | COM1 access |
| Quoted argv tokenizer | PIT/IRQ0 service |
| Strict JSON AST parser and writer | TSS and privilege transitions |
| Target command dispatch and bounded memory arenas | Version/capability query |
| Console waiting/retry loop | Single-task exit and fail-stop faults |

The syscall gate is a DPL3 interrupt gate. Console calls inspect readiness once
and return; they do not wait inside the kernel. The shell retries in user
mode, permitting timer progress. The kernel uses byte arguments and never
dereferences a user-supplied pointer. See the exact
[kernel ABI](../experiments/osif/KERNEL_ABI.md) for register and loader contracts.

## Verified behavior

The native run observed CPL3 both at module entry and at the real Jash prompt,
using hardware breakpoints without modifying instructions. CS was `0x1B`,
DS/ES/SS `0x23`, and IOPL zero. The 13,679-byte module matched the bytes read
back from guest memory. The kernel's unused TSS fields and page-directory
entries were explicitly zero and checked.

The run passed 15 independent ABI checks, five loader boundary cases,
16 CPU/TSS/page-directory checks and 28 Jash command cases. The Jash project
also passed 69 hosted adapter assertions and its static ELF/load-contract gate.
These sets have different scopes; the hosted assertions do not substitute for
the native execution.

Command cases cover quoted and empty arguments, JSON scalar/container types,
escaped NUL, duplicate-key/trailing-content rejection, capabilities, unsupported
services, status, literal operators, editor actions, CRLF handling, input
overflow rejection, real NUL output and `exit 7`. The independent client also
received a serial NUL as value zero and then observed `-EAGAIN` when empty.

The prompt's idle loop allowed the timer to advance. That verifies interrupts
while the shell waits; it is not a demonstration of a second scheduled task.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `basmos-osif.bin` | 512 | `bc03b8f742a5eb7d04080f52d662fcf7947685fd73c0f88fa0be52493584d62a` |
| `jash-basmos.bin` | 13,679 | `0795b5be663d7f691fed3ee3b41b1acfe4e5bffb912a89ad7d090043e9fffc0e` |
| Combined boot artifacts | 14,191 | Two separate images |

Jash BSS is 133,188 bytes; allocated static storage ends at relative address
146,884. The user arena is 2 MiB. File size, used static storage, reserved stack
space and addressable memory are distinct measurements.

## Coverage limits and evolution

The maximum loader length is accepted at the header boundary and invalid
lengths are rejected before payload stores. A complete maximum-size padding
fixture previously exceeded a 30-second debugger timeout; that full transfer
is not qualified. The actual Jash image and independent ABI client were fully
transferred and executed.

This result is QEMU TCG execution, not a physical-hardware or KVM qualification.
The profile shares writable code/data in one segmented arena; it does not
provide separate process address spaces or write-versus-execute protection.
Faults and exit halt this profile. Filesystems, network, process creation,
multitasking and kernel IPC are not advertised or emulated as successful calls.

The next integration boundary is an ABI with kernel-owned task/IPC state and
context preservation suitable for C. It must preserve this console contract,
make scheduling behavior observable and measure the combined kernel again.
No size is promised for that combined profile before it exists.

The demonstrable engineering claim is **a native Jash profile executing in
CPL3 over a complete 512-byte BasmOS boot sector**. A world-smallest claim
would additionally require defined comparison criteria and independent evidence.

## Recorded evidence

The [native report](osif/evidence/2026-11-08/native-report.json), [runner regression](osif/evidence/2026-11-08/runner-report.json), [ELF contract](osif/evidence/2026-11-08/artifact-report.json), [adapter assertions](osif/evidence/2026-11-08/adapter-report.json) and [source provenance](osif/evidence/2026-11-08/PROVENANCE.json) bind the recorded run to exact inputs. The [serial session](osif/evidence/2026-11-08/jash-session.txt) is a readable copy with ANSI controls removed and NUL escaped. Reproduction retains the original serial bytes.

Matching Jash checkpoint: [`a33d057`](https://github.com/FermiHart/jash/commit/a33d057504b52f43cc645c3d562c4aadbc16fc87). The runner regression passed 11 checks, including normal exit 0/7 and a deliberately colliding fault that must return runner error 125.
