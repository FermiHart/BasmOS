<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com> -->

# Ring 3 Shell Architecture

## Artifact Scope

BasmOS has two separate 512-byte boot-sector artifacts:

- `basmos.bin` is the CPL0 record artifact. Its 401-byte payload contains the
  protected-mode and paging setup, two preempted tasks with bounded private DS
  windows (see `DOMAINS.md`), and SPSC IPC. Both tasks run in CPL0; segment
  limits contain ordinary DS-default accesses, but flat SS and shared CR3 mean
  there is no hostile-code boundary between them.
- `basmos-sh.bin` is the CPL3 shell artifact. Its 498-byte payload replaces the
  two-task scheduler and IPC with a CPL3 serial monitor, a bounded module arena,
  a syscall boundary, a TSS, and user segments. Twelve padding bytes and the
  `55 aa` boot signature complete the sector.

The shell artifact is an independent design, not an extension or security mode
of `basmos.bin`.

## Boot And Privilege Setup

The BIOS loads `basmos-sh.bin` at physical address `0x7c00`. The sector installs
its GDT, enables 32-bit protected mode, builds an IDT at `0x0500`, enables PSE,
and installs one 4 MiB identity-mapped page at `0x00000000`. PDE0 is present,
writable, and user-accessible.

Paging therefore does not separate user memory from kernel memory. Isolation
inside the guest depends on IA-32 privilege checks and segment bases and limits.

The GDT defines these selectors:

| Selector | Descriptor | Base | Extent |
|---|---|---:|---:|
| `0x08` | CPL0 code | `0x00000000` | 4 GiB |
| `0x10` | CPL0 data and stack | `0x00000000` | 4 GiB |
| `0x1b` | CPL3 monitor code | `capsule` | 100 bytes |
| `0x23` | CPL3 arena data and stack | `0x00008000` | 4096 bytes |
| `0x2b` | CPL3 module code | `0x00008000` | 256 bytes |
| `0x30` | 32-bit available TSS | `0x00000a00` | 104 bytes |

The monitor starts through `iretd` with `CS=0x1b`, `SS=DS=ES=0x23`,
`ESP=0x0ffc`, IF set, and IOPL 0. `FS` and `GS` are null. A loaded module uses
the same data and stack segment but executes with `CS=0x2b` and `EIP=0`.

The TSS contains `SS0=0x10`, `ESP0=0x1000`, and an I/O-map offset of `0x68`,
immediately beyond the TSS limit. CPL3 port I/O is consequently denied while
IOPL remains zero. On a CPL3 interrupt or syscall, the processor switches to
the CPL0 stack before saving the user return frame.

## Interrupt And Syscall Boundaries

The IDT contains 129 gates covering vectors `0x00` through `0x80`:

- vectors `0x00` through `0x7f` are DPL0 interrupt gates (`0x8e`);
- vector `0x20` is the IRQ0 timer handler;
- vector `0x80` is a DPL3 trap gate (`0xef`).

Gate DPL prevents CPL3 software from invoking the DPL0 gates. Hardware
exceptions and IRQs may still enter them. The timer acknowledges the PIC,
writes `.` to COM1, and returns with `iretd`. Other installed exception paths
halt in CPL0 with interrupts disabled; there is no user exception delivery or
recovery.

The `int 0x80` ABI is:

| `EAX` | Operation |
|---:|---|
| `1` | Write `BL` to COM1 |
| `2` | Read one COM1 byte into `AL` |
| `3` | Replace the return `CS:EIP` with `0x2b:0` |
| `4` | Replace the return `CS:EIP` with the monitor resume point |

Unknown syscall numbers return without an operation. Because `0x80` is a trap
gate, IRQ0 remains enabled during serial polling in a syscall. The timer and
syscall paths can therefore interleave their serial output.

## Monitor Protocol

The parent monitor uses a byte-oriented COM1 protocol:

- `?` writes `3`;
- `r`, followed by one length byte and the payload, writes a module at arena
  offset zero; a zero length byte represents 256 bytes;
- `x` requests syscall 3 and enters the module;
- a module requests syscall 4 to return, after which the monitor writes `>`.

The protocol provides no authentication, confidentiality, framing recovery, or
module format validation. Its one-byte length limits native module loading to
256 bytes.

## JASH Module

`jash/jash.bin` is a separate 256-byte module loaded through this protocol and
executed at CPL3 under selector `0x2b`. It receives `jash/jash-pack.bin` into the
arena at data offset `0x200` (linear address `0x8200`). The Pack is outside the
module code-segment limit, so it cannot be fetched as native code through
`CS=0x2b`.

The nucleus uses 255 bytes and reserves byte `0xff`. It relocates ESP to `0x200`,
so calls grow below the Pack while the Pack may occupy the complete
`0x200..0xfff` remainder: exactly 3,584 bytes. The current Pack fills that bound.
It provides 14 exact commands without one-letter aliases. After CR processing,
all other C0 control bytes are no-op input, including BS (`0x08`); DEL (`0x7f`)
is the sole destructive edit. Embedded NUL therefore cannot turn a longer word
into a valid prefix, and CRLF does not dispatch an empty command.

At startup, `NK-SIGIL/1` renders the first 16 bytes of
`SHA256(basmos-sh.bin || jash.bin)` as Unicode braille, one visible dot per bit.
The binary `SIG1` manifest and `proofctl` independently bind the same root. This
is an artifact identity, not a measured-boot or runtime-attestation claim.

This is a segmentation property, not an NX page-table property. The arena is
writable, JASH updates the Pack's CPUID vendor field, and arbitrary CPL3 module
code can modify arena data. JASH Decks, Surfaces, command tables, and PRF1 text
are application-level data and policy; they do not create an additional
hardware protection domain.

## Negative Tests

`make verify-shell` exercises the boundary in two environments:

- `verify_shell_qemu.py` boots the sector with QEMU, loads a module that writes
  `Z`, returns to the monitor, observes an IRQ0 marker, and reads back IDT, TSS,
  and PDE0 bytes through QMP.
- `bemu-nano` runs the load, execute, and return sequence through KVM and records
  user return frames containing monitor selector `0x1b` and module selector
  `0x2b`.
- `verify_shell_faults.py` loads modules containing `cli`, `out dx,al`, and
  `mov ds,0x10`. Each case is expected to take the privilege-fault path, halt
  with saved module `CS=0x2b`, and avoid a triple fault.

`make verify-jash` separately checks the JASH serial contract, selector
observations, loaded module and Pack bytes, command parsing, and return to the
parent monitor under QEMU and KVM. `make verify-jash-capture` recaptures the
published ANSI session and requires its normalized transcript and SVG rendering
to agree with the current artifacts. These tests cover specific paths and inputs;
they are not exhaustive validation of IA-32 behavior or a security proof.

## Limitations

- All of the first 4 MiB is user-accessible and writable at the paging level.
  There are no per-process page tables, guard pages, or page-level NX controls.
- The monitor and module share the arena. They do not provide confidentiality or
  integrity against each other, and module code is writable through `DS=0x23`.
- Other DPL3 code selectors are reachable by CPL3 control transfers. Segment
  limits protect CPL0 memory, not the monitor from a hostile module.
- Syscalls do not authenticate callers, enforce capabilities, or limit CPU and
  serial use. A module can spin, poll indefinitely, flood output, or deliberately
  trigger fail-stop behavior.
- Exceptions halt the guest. There is no process termination, restart, fault
  report, or resource cleanup.
- The implementation has one shared CPL0 stack and minimal interrupt handling.
  It is not designed for nested faults, SMP, DMA-capable devices, or hostile
  physical hardware.
- The hostile-module suite covers three instructions only. Untested instruction,
  descriptor, exception, and microarchitectural behavior remains possible.
- QEMU and `bemu-nano` provide different and incomplete hardware models. Results
  in either environment do not establish behavior on all IA-32 systems.
