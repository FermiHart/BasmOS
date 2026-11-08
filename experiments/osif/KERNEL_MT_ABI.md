# BasmOS OSIF ABI 2 — one-sector preemption and byte mailboxes

Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>

SPDX-License-Identifier: BSD-3-Clause

This is an opt-in profile implemented by `basmos-mt.basm`. It contains the
complete boot loader and supervisor in **507 payload bytes, three padding
bytes, and the two-byte BIOS signature: 512 bytes total**. No supervisor
extension is loaded with the application. The source retains
`times 510 - ($ - $$) db 0`; a larger payload must fail assembly.

ABI 1 in `basmos-osif.basm` remains a separate profile. The change of interrupt
vector, boot limits, capabilities and scheduling model requires a distinct
ABI version. This profile has two preempted execution contexts sharing one
user arena. It has no process isolation, task creation, filesystem, network,
or 255-byte FIFO. Its two IPC queues each have **capacity one byte**.

## Serial boot and entry points

The BIOS loads the 512-byte sector at physical `0x7C00`. The sector enables
A20, enters 32-bit protected mode, initializes descriptors, IRQ0 and COM1,
and emits ASCII `B` through COM1 at 115200 baud, 8 data bits, no parity,
one stop bit. UART interrupts are disabled.

The host sends a little-endian unsigned 32-bit length followed by exactly
that many flat-module bytes. Valid lengths are **1 through `0x1B0000`**.
Zero and larger lengths halt before the first payload write. A valid length
does not prove that the supplied bytes form a runnable program. The module
must provide both entry points and respect the shared memory layout below.

The payload is copied to physical `0x100000`, with its addresses linked
relative to zero. The length limit leaves the peer's initial stack below
the application arena ceiling with room below its entry stack pointer.
The application linker must separately keep static storage and heaps below
both stacks; the loader cannot infer BSS size from a flat binary.

| Property | Shell context | Peer context |
|---|---:|---:|
| Initial relative EIP | `0` | `4` |
| Initial relative ESP | `0x1FFFF0` | `0x1BFFF0` |
| Initial CS | `0x1B` | `0x1B` |
| Initial DS, ES, SS | `0x23` | `0x23` |
| Initial FS, GS | null | null |
| Initial EFLAGS | `0x202` | `0x202` |
| Ring-0 stack top | `0x1800` | `0x1000` |

Both contexts have CPL 3, IF 1, DF 0, and IOPL 0 at entry. No application
contract is assigned to their initial general register contents. Entry at
offset four is already given its own stack; a bootstrap stack relocation
is not needed. The application must coordinate shared BSS initialization
before its peer accesses shared C state.

## Native calling convention

Invoke **`int 0x21`** with the complete 32-bit operation number in EAX.
Arguments are bytes in EBX as shown below. Returning calls preserve EBX,
ESI, EDI, EBP, ESP and DS/ES/FS/GS. EAX, ECX and EDX are caller-clobbered.
The operation number is not truncated to AL. Unsupported full-width values
return signed `-38` (`ENOSYS`).

| EAX | Operation | Arguments | Return |
|---:|---|---|---|
| 0 | Query | none | EAX `2`, EDX `0x3B`, ECX `0x200000` |
| 1 | Console write | BL = byte | EAX `1` accepted, or `-11` busy |
| 2 | Console poll | none | EAX `0..255`, or `-11` empty |
| 3 | Unsupported | none | EAX `-38`; no raw tick service |
| 4 | Exit the machine | BL = status | Does not return; records exit receipt and halts |
| 5 | Mailbox send | BL = byte; BH bit 0 = channel | EAX `1` accepted, or `-11` full |
| 6 | Mailbox receive | BH bit 0 = channel | EAX `0..255`, or `-11` empty |
| Other | Unsupported | ignored | EAX `-38` |

The query capability bits are RX `1`, TX `2`, EXIT `8`, IPC `16`, and
PREEMPT `32`: total `59` (`0x3B`). ABI 1's raw-ticks bit `4` is absent.
The PIT still supplies preemption; this does not advertise an elapsed-time
API, epoch, or overflow behavior.

All handlers use interrupt gates. Interrupts are disabled for their short,
bounded operation and IRETD restores the caller's flags. Waiting and retry
loops execute in CPL 3, so a waiting shell cannot monopolize the processor.
No returning handler dereferences a user-supplied pointer.

## Two one-byte mailboxes

There are two independent slots. The kernel computes their addresses as
`0xB00 + (((EBX >> 7) & 2))`; only BH bit zero influences the result.
Other argument bits cannot redirect kernel memory access.

Each slot is a 16-bit kernel-owned word. Its low byte is the payload and its
high byte is either zero (empty) or one (full). A successful send changes
an empty slot to `{payload, 1}`. A send to a full slot returns `-11` and
does not change the queued value. Receive exchanges the slot with zero,
then returns the old byte when the full flag was set. An empty receive
returns `-11`. Thus **payload `0x00` returns zero successfully and remains
distinct from an empty slot**.

The kernel owns both payload storage and occupancy state. With capacity
one there are no queue cursors or wraparound indices. A producer must retry
after `-11`; a consumer frees the slot when it receives its current byte.
Interrupt gates make each operation indivisible with respect to IRQ0.

The Jash protocol uses channel zero for shell-to-peer requests and channel
one for peer-to-shell replies. Channel ownership is an application protocol,
not a kernel permission. Both shared-arena contexts may address either
slot. The IPC implementation must not be described as either a protected
process channel or the previous 255-byte ring.

## Preemption and saved context

The master 8259 PIC uses ICW1 `0x13`: single mode, with ICW4 present. ICW2
maps its interrupts to `0x20`; ICW4 selects 8086 mode. The mask `0xFE`
enables IRQ0 alone. Cascaded/slave interrupts are unused and IRQ2 is masked.
This removes an unnecessary cascade configuration word for this profile.

PIT channel zero is initialized in mode 3 with divisor `11932`: nominally
100 Hz (approximately 100.001676 Hz with a 1,193,182 Hz input). Each hardware
IRQ0 sends the master EOI, saves the interrupted context, exchanges ESP
with the parked-context pointer, updates TSS.ESP0 for the selected context,
restores that context and returns to CPL 3. There is no cooperative yield
call and neither task has a reserved general register.

Each parked kernel frame has 68 bytes:

| Offset from parked ESP | Bytes | Content |
|---:|---:|---|
| `0` | 4 | GS slot |
| `4` | 4 | FS slot |
| `8` | 4 | ES slot |
| `12` | 4 | DS slot |
| `16` | 32 | PUSHAD frame: EDI, ESI, EBP, saved ESP, EBX, EDX, ECX, EAX |
| `48` | 4 | User EIP |
| `52` | 4 | User CS |
| `56` | 4 | User EFLAGS |
| `60` | 4 | User ESP |
| `64` | 4 | User SS |

The upper half of a segment slot is not an ABI value. Segment pops restore
its selector. POPAD discards its saved ESP slot, as required by the x86
instruction. The scheduler derives the selected ring-0 stack top as
`parked_esp + 68`. Initial parked peer ESP is `0xFBC`; shell frames park
at `0x17BC`. Syscall frames before temporary pushes are respectively
`0xFEC` and `0x17EC`.

The Jash profile uses soft-float compilation with SSE/MMX disabled.
**FPU, MMX and SIMD state are not saved.** A workload that uses those
registers in both contexts needs a different context contract. Kernel
handlers do not use string instructions after user execution begins, so
they also do not depend on the interrupted task's direction flag.

## Memory and privilege layout

| Physical address | Purpose |
|---|---|
| `0x500..0x60F` | 34 IDT entries: exceptions 0–31, IRQ0 at 32, syscall at 33 |
| `0xA00..0xA67` | TSS; SS0 `0x10`; I/O-map offset `0x68` beyond the TSS limit |
| `0xB00..0xB01` | Channel zero word |
| `0xB02..0xB03` | Channel one word |
| `0xB04..0xB07` | Loaded module length |
| `0xB08` | Exit status byte |
| `0xB09` | Explicit exit-path marker, value `4` |
| `0xB0A..0xB0B` | Unspecified upper EBX bytes after exit; zero before exit |
| `0xB0C..0xB0F` | Other context's parked kernel ESP |
| Below `0x1000`, below `0x1800` | Peer and shell ring-0 stacks |
| `0x7C00..0x7DFF` | Entire boot sector, supervisor, static descriptor data and signature |
| `0x100000..0x2FFFFF` | Shared 2 MiB user arena |

Boot zeroes 68 dwords at `0xA00..0xB0F`, explicitly initializing all TSS
fields and mutable mailbox/exit/scheduler state before use. IDT entries are
constructed separately. Stack frames are constructed or written by the CPU
and handler instructions before restoration. The implementation does not
assume that uninitialized RAM starts as zero.

The user code and data descriptors share base `0x100000` and effective limit
`0x1FFFFF`. Kernel code/data descriptors are flat DPL 0 segments. The syscall
gate is DPL 3; IRQ0 and exception gates are DPL 0. TSS ring transitions use
kernel SS `0x10`. Paging is not enabled, and there is no page-directory
contract. Segmentation provides the configured user address window; no
comprehensive hostile-code containment claim follows from these descriptors
or from the ordinary runtime tests alone.

### QEMU 8.2.2 segment-limit diagnostic

The retained negative diagnostic executes bytes `A1 00 00 20 00`, a 32-bit
`MOV EAX, DS:[0x200000]`. QEMU TCG continues in CPL 3 with DS base
`0x100000`, DS limit `0x1FFFFF`, and no exit marker. This access is beyond
the configured limit. Intel's [MOV protected-mode exception contract in
SDM Volume 2B](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
requires a general-protection fault for an operand outside the DS limit.
The diagnostic is therefore **not a protection pass**.

The observed behavior is explained by the upstream QEMU 8.2.2 translator,
whose release tag resolves to commit
`11aa0b1ff115b86160c4d37e7c37e6a6b13b77ea`. In
[`target/i386/tcg/translate.c`](https://github.com/qemu/qemu/blob/11aa0b1ff115b86160c4d37e7c37e6a6b13b77ea/target/i386/tcg/translate.c),
the `0xA1` path calls `gen_add_A0_ds_seg`, then `gen_op_ld_v`.
`gen_lea_v_seg` adds the selected segment base and truncates the resulting
address for this 32-bit mode; it emits no comparison with the segment limit.
`gen_op_ld_v` directly emits the QEMU memory load from that linear address.
In contrast,
[`helper_load_seg` in `seg_helper.c`](https://github.com/qemu/qemu/blob/11aa0b1ff115b86160c4d37e7c37e6a6b13b77ea/target/i386/tcg/seg_helper.c)
does check selector privilege while loading a segment and caches the
descriptor's limit. That separate path explains why loading the kernel's
data selector faults while the ordinary out-of-limit memory access does
not in this runtime.

This source-level finding concerns the tested TCG implementation and the
specific ordinary load path. It does not qualify physical hardware, KVM,
other QEMU versions, or all possible memory instructions. The test reports
retain `protection_qualified: false`, and the profile remains a demonstration
of CPL 3 execution, scheduling and IPC without a validated memory-containment
claim.

## Exit, faults, and observation

Operation four writes BL to `0xB08` and explicitly writes marker four to
`0xB09`, then enters the halt loop. It terminates the whole two-context
session; there is no individual thread destruction or scheduler recovery.
The dispatch chain has reduced EAX to zero on this path. Exit may modify
BH, since this operation never returns.

Unhandled exceptions enter the same halt loop without writing the exit
receipt. An observer must require the explicit marker rather than infer
success from a halted CPU or register values alone. A normal exit has
CPL 0, HLT set, EAX zero, BL equal to the recorded status, marker four,
and ESP `0x17EC` for the shell or `0xFEC` for the peer. Faults may resemble
those register values, but the initialized exit marker remains zero.

The native validation harness uses hardware breakpoints and read-only
observations to inspect both CPL 3 contexts, their registers, the exact
loaded module, IPC results and scheduler progress. The reproducible test
reports define the qualified scope; the byte count alone does not establish
correct scheduling, IPC, or a world-record claim.
