<!-- SPDX-License-Identifier: BSD-3-Clause -->

# BasmOS Byte Budget And Optimizations

This document describes the current 512-byte record artifact. Historical
experiments and removed variants are intentionally omitted from the public
release.

## Current Result

| Artifact | Total | Payload | Free before signature |
|---|---:|---:|---:|
| `basmos.bin` | 512 B | 401 B | 109 B |

The payload contains boot entry, PM32 transition, PSE paging, IDT, PIC/PIT,
timer-driven switching of a CPU-bound and a sleeping task, bounded data and
code segments, SPSC IPC, a tick heartbeat and VGA output.

The expected VGA evidence is:

| Address | Value | Meaning |
|---|---|---|
| `0xB8000` | white `3` | task 0 executed |
| `0xB8002` | white `6` | task 1 ran after IRQ0 preempted the CPU-bound task 0 |
| `0xB8004` | green `9` | task 1 received the byte sent by task 0 |
| `0x6FC` | increasing | every serviced IRQ0 increments the heartbeat byte |

Task 0 displays `3` but sends `9`; task 1 is the only code path that displays
the received byte. This makes `9` evidence of queue transfer rather than a
shared display constant. Task 0's loop contains no `hlt` and no yield, and the
heartbeat must keep advancing, so the observable state requires asynchronous
timer preemption of a task that was mid-computation.

## Current Techniques

### Stack-built IDT

ESP starts above the 35-entry IDT region. Three service gates and 32 fail-stop
exception gates are pushed backwards into their final layout, avoiding a static
280-byte table. Vector 13 is then pointed at a distinct handler so the negative
domain probe can prove `#GP` specifically.

### GDT overlap

The six-byte GDTR overlaps the null descriptor. A base adjustment makes selectors
`0x08` and `0x10` address the code and data descriptors without storing a full
eight-byte null entry. Additional selectors bound task 0 to `0x800..0x8FF`,
task 1 to `0x900..0x9FF`, and GS to the VGA page. Two label-computed code
descriptors (0x30/0x38, 32-bit, byte granular) bound each task's fetch to its
own bytes; their limits track the layout automatically, including probe builds.

### Segment-capability context

SS remains flat so interrupt frames and overlapping task stacks retain their
absolute offsets. EBP carries each task's DS selector through `pushad`/`popad`.
Kernel handlers use explicit ES overrides for the ring, heartbeat and scheduler
cell; task display writes use the VGA-only GS descriptor. Task 0 enters its code
window through a five-byte `push 0x30 / push 5 / retf` prologue and task 1's
baked frame ships `CS=0x38`. The positive proof reads each private byte and the
live descriptors; separately assembled `DS:[0x100]` and `jmp task1` probes must
enter the dedicated `#GP13` gate before task 1 can start or execute.

### Single PSE mapping

One 4 MiB identity-mapped PDE covers all code, stacks, tables, IPC memory and
VGA used by the artifact. The design enables paging without allocating a full
page-table hierarchy.

### One-cell context switch

`xchg esp,[es:other_sp]` atomically saves one task stack and restores the other.
`popad`, `mov ds,bp` and `iretd` restore the integer, segment and interrupt state.

### CPU-bound producer and tick heartbeat

The producer's loop is `int 33; jmp` — no `hlt`, no yield. It is CPU-bound, so
every task-1 slice is an asynchronous IRQ0 preemption of a task that was
mid-computation, which is strictly stronger evidence than waking a sleeping
task. The timer handler additionally executes `inc byte [0x6FC]` (6 bytes,
emitted through `db`/`dd` because `basm-nano` has no `inc` with a memory
operand yet), leaving a trace of every serviced tick; verifiers require the
byte to keep advancing. The bEMU contract keeps the sleeping-producer timing
model and supplies the same five-entry GDT as machine state.

### Context-owned IPC cursors

Producer and consumer cursors live in each endpoint's saved ECX. The opposite
task frame exposes the peer cursor at offset `+24` in the `pushad` image,
removing global head/tail cells. Eight-bit cursor increments provide modulo-256
wrapping. The queue has 255 usable slots; a full queue drops the new byte
without corrupting state.

`make verify-ipc` explores both transitions from all 65,536 cursor pairs with
symbolic queue contents, checks the complete emitted handler bodies that bind
the model to the artifact, then boots a temporary layout-preserving KVM probe. The
probe consumes one byte and freezes the consumer; the flooded producer must
stabilize at `head=1, tail=0`, exercising the full check across the wrap.

### Reused initialization storage

The initial task-1 frame and its steady-state stack reuse bytes that are dead
after initialization. This is safe only under the documented fixed task count
and shallow interrupt paths.

### Purpose-built assembler

`basm-nano` implements only the source forms used by BasmOS. Rare encodings not
supported as mnemonics are emitted explicitly with `db`/`dd`. `make verify-nasm`
assembles the same five artifacts with NASM and requires byte identity.

## Byte-Sensitivity Map

`make verify-sensitivity` flips every byte of the record sector (XOR 0xFF),
boots the mutant in QEMU and classifies the observable effect on the
demonstrated contract (3/6/9, liveness, heartbeat). Current result over the
401-byte payload: 279 payload bytes are DEAD when flipped, 33 visibly ALTER
the contract, 3 freeze only the timer evidence, and 86 are observably intact
under normal operation. Three complete successful runs of the current artifact
produced byte-identical JSON and Markdown maps. The full map is committed in
`evidence/byte-sensitivity.md`.

## Measured Symbol Map

Run:

```sh
make map
```

The map is generated by the same assembler that emits the artifact. Any guest
change should report the old and new symbol budgets and regenerate
`ARTIFACTS.manifest` and `SHA256SUMS` with `make manifest`.

## Trade-Offs

- Both record tasks run in CPL0. Segment limits contain ordinary DS-default
  accesses, not EBP/ESP operands through flat SS or hostile CPL0 code capable
  of loading selectors or replacing descriptor tables.
- Only integer register state is switched; FPU/SIMD state is outside scope.
- The system is fixed to two record tasks.
- The identity map covers only the first 4 MiB.
- Exceptions are fail-stop rather than recoverable.
- Hardware coverage is narrower than QEMU/KVM coverage.
- PSE is required, so the target is Pentium-class IA-32 or compatible rather
  than an original 80386.
- The heartbeat counter starts from uninitialized RAM; its liveness proof is
  the delta between two reads, not an absolute value.

The separate `basmos-sh.bin` artifact explores CPL3/TSS boundaries without
changing the byte budget or feature set of `basmos.bin`.
