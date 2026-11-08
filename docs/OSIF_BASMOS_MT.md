<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Native Jash, preemption and IPC within one 512-byte kernel

The opt-in **OSIF ABI 2** profile combines the real, reduced Jash C shell,
two preempted CPL3 execution contexts and kernel-owned byte IPC. The complete
boot loader and nanokernel remain in **one 512-byte BIOS sector**, including
the boot signature. The separately loaded application contains no additional
supervisor stage.

The kernel is `experiments/osif/basmos-mt.basm`. Its exact calling convention,
saved-frame layout, memory map and hardware setup are specified in
[KERNEL_MT_ABI.md](../experiments/osif/KERNEL_MT_ABI.md).

## The byte budget

| Part of the kernel image | Bytes |
| --- | ---: |
| Boot code, kernel handlers and static descriptor data | 507 |
| Zero padding | 3 |
| BIOS signature `55 AA` | 2 |
| **Complete kernel image** | **512** |

The ceiling is enforced in two places. The assembly source uses
`times 510 - ($ - $$) db 0`, so a payload above 510 bytes fails before an image
is published. Every `make -f Makefile.osif-mt osif-mt` also runs
`tests/sector_budget.py`. It rebuilds the actual source, checks exact bytes,
size, padding and signature, and attempts a 511-byte payload. That negative
build must fail without overwriting a valid sector or creating a new image.
There is no configurable larger kernel budget in these targets.

The size is the **kernel file size**, not total RAM consumption. IDT entries,
TSS, mailboxes and saved stack frames are initialized in RAM. Jash's code,
data, BSS and stacks occupy its separate user arena.

## What this profile provides

Both application contexts use CPL3 and IOPL zero. The shell begins at relative
EIP 0 with stack `0x1FFFF0`; its peer begins at EIP 4 with stack `0x1BFFF0`.
They share a 2 MiB code/data arena. A hardware timer interrupt switches them;
there is no cooperative yield syscall. The scheduler preserves general
registers, DS, ES, FS, GS and the CPU return frame. It reserves no application
general register for task state or IPC cursors.

The Jash module retains the canonical editor, key decoder, quoted-argument
parser and strict JSON parser/writer. Its peer has its own stack and accesses
only the IPC gateway and its observation counters. An initialized-data
sentinel keeps the peer from touching shared BSS before the main startup code
has cleared it. The peer does not enter the shell allocator, editor, parser
or terminal routines.

The complete selected command list is:

```text
help version echo argv json osif uname ticks status clear true false exit byte peer ipc
```

The two new commands expose the running peer and real message exchanges:

```text
peer
ipc 0
ipc 255
ipc test
```

`ipc 0` prints `ipc sent=0 received=0` after a NUL has crossed a kernel mailbox,
been received by the peer, and returned through a second kernel mailbox.
The observation counters are not the transport for this reply. `ipc test`
checks 32 exchanges, including zero and 255, and verifies that the reply
mailbox is empty after each completed exchange. Waiting stays in user mode.
After a transport failure or exhausted retry budget, the shell disables its
IPC session until reboot to avoid accepting a late reply for a later request.

## Decisions required by the 512-byte ceiling

| Boundary | ABI 2 contract |
| --- | --- |
| Scheduled contexts | Two fixed cooperating contexts in one shared arena |
| IPC storage | Two independent kernel-owned mailboxes, one byte each |
| Full mailbox | Send returns `-EAGAIN` without overwriting its current byte |
| Empty mailbox | Receive returns `-EAGAIN`; a received NUL returns zero |
| Interrupt gateway | `int 0x21`, full operation number in EAX |
| Timer | PIT preemption remains; the raw tick-counter service is absent |
| Paging | Disabled; user segment descriptors define the configured arena |
| Exit and faults | Halt the entire session; no individual task recovery |
| Floating-point context | Not saved; the module uses soft-float, no SSE/MMX |

The IPC slots are **not the earlier 255-byte ring**. They have no cursors or
wraparound indices. The kernel masks the channel selector to one bit; higher
argument bits cannot turn a mailbox operation into an arbitrary kernel
pointer. Both cooperating contexts can select either slot. Direction is the
application protocol, not an endpoint permission system.

The version query returns ABI 2, capabilities `0x3B`, and the 2 MiB arena
size. The `osif` command reports IPC and preemption, and explicitly reports
ticks, filesystem, process creation and networking as unavailable where
appropriate. `ticks` returns an unavailable status. The peer activity counter
is an observation of work, not a clock.

The original [single-context ABI 1 profile](OSIF_BASMOS.md) remains available
through its existing targets. Its kernel and Jash module retain their previous
binary hashes. ABI 1's tick service and `int 0x80` gateway are unchanged.

## Build, verify and run

Use the matching Jash OSIF checkout, GCC with freestanding `-m32` support,
GNU binutils, Make, Python 3 and QEMU's i386 system emulator with BIOS firmware.
No host 32-bit libc is linked.

From this BasmOS repository:

```sh
make -f Makefile.osif-mt osif-mt-verify JASH_ROOT=/path/to/jash
make -f Makefile.osif-mt osif-mt-run JASH_ROOT=/path/to/jash
```

`BASMOS_QEMU=/path/to/qemu-system-i386` can select an emulator installation or
wrapper. The verification target builds both projects and checks the kernel
budget, Jash adapter, ELF contract, actual native execution and terminal exit
regressions. Generated evidence is placed in `build/osif-mt/`.

For the independent ABI client without Jash:

```sh
make -f Makefile.osif-mt osif-mt-abi
```

For a command file ending in `exit N`:

```sh
python3 tools/run_osif_jash.py --abi 2 \
    --kernel build/osif-mt/basmos-mt.bin \
    --module /path/to/jash/build-basmos-mt/jash-basmos.bin \
    --commands commands.txt
```

The runner returns the guest's exit status. Timeout is 124; abnormal halt or
runner failure is 125. An explicit kernel exit marker distinguishes normal
exit zero from a fault that leaves superficially similar register values.
Ctrl-] detaches an interactive terminal and restores its terminal settings.

## Recorded native qualification

The 2026-11-08 QEMU TCG run used these exact artifacts:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `basmos-mt.bin` | 512 | `26cb19b7bebdd0074bd312287f5dc766c0a06d533ceb41043d53b13b6f6fa60a` |
| `jash-basmos.bin`, ABI 2 | 15,252 | `8f860afad0e58a1f4393cc61fac09fe0ff7aa90b4abd1ab0117cdbc851359c93` |
| Combined boot artifacts | 15,764 | Two separately loaded images |

The module has 133,204 BSS bytes; allocated static storage ends at relative
address 148,468. These are different measurements from its file size or its
2 MiB addressable arena.

The independent assembly client passed 19 ABI/preemption checks. It exercised
all 256 byte values on each mailbox, rejection without overwrite, empty/full
recovery, NUL input/output, channel masking and 512 actual request/reply
exchanges between the two contexts. Separate CPU-only loops kept distinct
register and segment sentinels live across timer preemption. Five loader
boundary cases and 21 CPU/TSS/gate checks also passed. The real Jash run passed
26 command cases, with peer activity continuing while the shell waited at
the prompt and while it processed commands.

The hosted adapter passed 86 assertions. The static ELF gate verified the two
entry points, both stack bounds, loaded-data startup sentinel, exact flat
image, selected canonical Jash symbols, no dynamic dependencies and no listed
privileged instructions in the application text. The separate sector gate
passed nine checks; the terminal exit regression passed eleven checks for
ABI 2, with ABI 1 compatibility checked separately. These layers have
different scopes and do not substitute for one another.

## Limits of the result

Six privilege/fault probes halted as expected: invalid opcode, CLI, HLT,
port output, a kernel data-selector load and a forged timer interrupt.
**A seventh diagnostic, an ordinary read beyond the configured DS limit,
did not trap under QEMU 8.2.2 TCG. Its memory-protection result is not
qualified.** The observed opcode and segment registers, plus analysis of the
matching QEMU source, are retained with the evidence. The translator path
for this ordinary MOV adds the segment base without testing its limit; see
the pinned-source explanation in the ABI document.

Functional test success therefore does not establish hostile-code memory
containment. The two contexts already share their arena by design. No
separate process address spaces, page protection or stack guard pages are
provided. Qualification on physical hardware or KVM was not performed.

The maximum allowed module length was accepted at the header boundary, and
invalid lengths were rejected before payload stores. A complete maximum-size
padding transfer is not qualified. The actual Jash module and independent
probe were completely transferred and executed.

This is a reduced native Jash profile with two cooperating contexts, not the
full evaluator, general builtin set, JTV2 pipelines or a complete POSIX
environment. The demonstrated size claim is the complete 512-byte
boot/kernel image with this documented behavior; a world-record claim would
require separate comparison criteria and independent evidence.

## Evidence

Matching Jash checkpoint:
[`5a069316`](https://github.com/FermiHart/jash/commit/5a069316e1330b3a1c9b3508492e7e5a57fbc648).

The reproducible records are in [the MT evidence directory](osif/evidence/2026-11-08-mt/):
[native report](osif/evidence/2026-11-08-mt/native-report.json),
[sector budget](osif/evidence/2026-11-08-mt/budget-report.json),
[terminal regression](osif/evidence/2026-11-08-mt/runner-report.json),
[ELF contract](osif/evidence/2026-11-08-mt/artifact-report.json),
[source provenance](osif/evidence/2026-11-08-mt/PROVENANCE.json),
[QEMU segment-limit analysis](osif/evidence/2026-11-08-mt/qemu-segment-analysis.json),
[Jash transcript](osif/evidence/2026-11-08-mt/jash-session.txt) and
[independent client transcript](osif/evidence/2026-11-08-mt/abi-session.txt).
