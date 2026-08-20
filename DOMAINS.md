<!-- SPDX-License-Identifier: BSD-3-Clause -->

# BasmOS Task Data Domains

The 512-byte record artifact uses IA-32 segmentation to contain ordinary data
accesses and instruction fetches by its two trusted CPL0 tasks:

| Selector | Base | Limit | Purpose |
|---|---:|---:|---|
| `0x08` | `0` | `0xffffffff` | kernel code (IDT gates) |
| `0x10` | `0` | `0xffffffff` | kernel data and task stacks |
| `0x18` | `0x800` | `0xff` | task 0 private data |
| `0x20` | `0x900` | `0xff` | task 1 private data |
| `0x28` | `0xb8000` | `0xfff` | VGA text page |
| `0x30` | `task0` | `task0_size-1` | task 0 code window (32-bit, byte granular) |
| `0x38` | `task1` | `task1_size-1` | task 1 code window (32-bit, byte granular) |

The code-window bases and limits are assembled from labels, so they track any
layout change automatically. task0 enters its window through a five-byte
`push 0x30 / push 5 / retf` prologue; task1's baked frame ships `CS=0x38`
directly, and every preemption returns the interrupted task's own selector
through the iretd frame. Handlers always re-enter through the flat `0x08`
gate selector.

SS deliberately remains flat. The initial task-1 frame overlaps initialization
bytes and both interrupt paths use absolute stack offsets; rebasing SS would
make those offsets incorrect during a switch. EBP instead carries each task's
DS selector through `pushad`/`popad`. After the stack exchange, `mov ds,bp`
activates the incoming data window.

Interrupt handlers use explicit ES overrides to reach the kernel-owned ring,
heartbeat and `other_sp`. Task display writes use GS. Consequently, an ordinary
task operand whose architectural default is DS cannot reach the ring, peer
window or VGA page. EBP/ESP-based operands default to the deliberately flat SS
and are outside this containment claim.

Code windows bound the instruction fetch: a runaway jump or linear execution
past a task's own bytes raises #GP13 at the fetch instead of executing foreign
code. The negative probe jumps from task0 to task1's first byte; KVM must
report vector 13 with error code zero, the saved EIP on the jump itself, and
task1's code must never run.

## Proof

Run:

```sh
make verify-domains
```

The gate performs six executions:

1. The shipped artifact writes `0x33` through task 0 DS and the received IPC
   byte `0x39` through task 1 DS. QMP reads both physical private bytes, the
   five live fixed descriptors (flat kernel code/data, the two data windows
   and VGA) and both live code-window descriptors (computed from the symbol
   map, not hardcoded).
2. A temporary `DOMAIN_FAULT_PROBE` build executes `mov al,[0x100]` while task
   0 has DS base `0x800`, limit `0xff`. KVM-backed QEMU must stop in the distinct
   vector-13 handler with error code zero and the faulting EIP on that opcode;
   task 1's private byte must remain untouched.

2b. A temporary `DOMAIN_CODE_FAULT_PROBE` build executes `jmp task1` from inside
   task 0. The fetch lands beyond task 0's code window, so KVM-backed QEMU must
   stop in the vector-13 handler with error code zero and the saved EIP on the
   jump itself, while the live descriptor's limit proves the target offset lies
   beyond it and task 1's code never executes.
3. A normal `BEMU_CONTRACT` run requires private markers at physical `0x800`
   and `0x900`, proving both machine-owned descriptor bases.
4. The task-0 negative probe is assembled with `BEMU_CONTRACT`; `bemu-nano`
   must produce the identical `#GP13` frame from the machine-owned GDT.
5. A task-1 contract probe addresses offset `0x100`, the first byte beyond its
   advertised limit; it must also produce `#GP13`.

The browser interpreter independently models descriptor bases and limits,
fetches through the code segment with limit checks, runs both positive markers
and repeats the task-0 data and code negative frame checks. Plain QEMU TCG is
retained for the portable boot/liveness gate, but is not used as the domain
oracle: the tested TCG version exposes correct descriptor caches while failing
to enforce either this data-segment limit or the code-window limit on fetch
(an out-of-window near jump executes without #GP). KVM enforces both.

## Security Boundary

This design contains accidental DS-default accesses and runaway fetches by
trusted task code. It is not protection against hostile CPL0 code: ring 0 can
address through flat SS, load selector `0x10`, perform a far transfer to the
peer's DPL0 code selector, alter the GDT, disable protected mode or otherwise
bypass the convention. Use the
separate `basmos-sh.bin` CPL3 artifact when the executed module is untrusted.
