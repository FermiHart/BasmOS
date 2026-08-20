<!-- SPDX-License-Identifier: BSD-3-Clause -->

# BasmOS Task Data Domains

The 512-byte record artifact uses IA-32 segmentation to contain ordinary data
accesses by its two trusted CPL0 tasks:

| Selector | Base | Limit | Purpose |
|---|---:|---:|---|
| `0x08` | `0` | `0xffffffff` | kernel/task code |
| `0x10` | `0` | `0xffffffff` | kernel data and task stacks |
| `0x18` | `0x800` | `0xff` | task 0 private data |
| `0x20` | `0x900` | `0xff` | task 1 private data |
| `0x28` | `0xb8000` | `0xfff` | VGA text page |

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

## Proof

Run:

```sh
make verify-domains
```

The gate performs five executions:

1. The shipped artifact writes `0x33` through task 0 DS and the received IPC
   byte `0x39` through task 1 DS. QMP reads both physical private bytes and the
   five live GDT descriptors.
2. A temporary `DOMAIN_FAULT_PROBE` build executes `mov al,[0x100]` while task
   0 has DS base `0x800`, limit `0xff`. KVM-backed QEMU must stop in the distinct
   vector-13 handler with error code zero and the faulting EIP on that opcode;
   task 1's private byte must remain untouched.
3. A normal `BEMU_CONTRACT` run requires private markers at physical `0x800`
   and `0x900`, proving both machine-owned descriptor bases.
4. The task-0 negative probe is assembled with `BEMU_CONTRACT`; `bemu-nano`
   must produce the identical `#GP13` frame from the machine-owned GDT.
5. A task-1 contract probe addresses offset `0x100`, the first byte beyond its
   advertised limit; it must also produce `#GP13`.

The browser interpreter independently models descriptor bases and limits, runs
both positive markers and repeats the task-0 negative frame check. Plain QEMU TCG is retained for the
portable boot/liveness gate, but is not used as the domain oracle because the
tested TCG version exposes the correct DS cache while failing to enforce this
data-segment limit. KVM enforces the architectural fault.

## Security Boundary

This design contains accidental DS-default accesses by trusted task code. It is
not protection against hostile CPL0 code: ring 0 can address through flat SS,
load selector `0x10`, alter the GDT, disable protected mode or otherwise bypass
the convention. Use the
separate `basmos-sh.bin` CPL3 artifact when the executed module is untrusted.
