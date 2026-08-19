<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Verification Layers

BasmOS verification is layered. No single check is described as a formal proof
or as complete x86 equivalence.

## 1. Reproducible Assembly

- `basm-nano` is rebuilt from source.
- Five guest artifacts are assembled from their `.basm` sources.
- `make verify-nasm` independently assembles all five with NASM and requires
  byte identity.
- `SHA256SUMS` binds the expected release artifacts.

## 2. Native Structural Contracts

`proofctl` checks sizes, boot signatures, JASH boundaries, EVM1 shape, Surface
and Deck manifests, word/cell pointers and fixed aliases. These are structural
contracts, not cryptographic provenance by themselves.

## 3. QEMU Behavior

- The record sector must reach VGA `3/6/9`.
- Task 0 is CPU-bound and never sleeps; the 6, the 9 and a heartbeat byte at
  `0x6FC` that must keep incrementing require asynchronous IRQ0 preemption.
- IDT and PDE bytes are read through QMP.
- The CPL3 sector must demonstrate IRQ0, TSS state, module load, execution and
  return.
- JASH nucleus and Pack bytes are read back from physical memory.

QEMU runs with a read-only image, networking disabled and sandboxing enabled.

## 4. KVM Behavior

`bemu-nano` executes locally built guests through `/dev/kvm`. It checks the
record sector, the documented 171-byte machine contract and the CPL3 serial
protocol. Host-side wall-clock timeouts bound automated runs.

In plain record-boot mode the VMM is an 18.2 Hz periodic PIT: ticks are
delivered through the KVM interrupt-window mechanism, preempting a CPU-bound
guest mid-computation (measured: 64 ticks, 32 of which preempt the producer).
The bEMU contract mode injects one interrupt after guest `HLT`; QEMU is the
stronger test for legacy PIT/PIC behavior.

## 5. Parser And Mutation Gates

- deterministic near-match and random-word fuzzing;
- hostile CPL3 modules for privileged instructions and segment loads;
- mutations of signatures, manifests, aliases, cells and VM metadata that must
  be rejected.

## 6. Browser Interpreter

The static site includes a deliberately limited interpreter for the exact
instruction subset used by `basmos.bin`. It validates control flow and observable
state, but does not model full x86 segmentation, paging or hardware devices.

The Node gate executes the extracted interpreter inside a restricted `vm`
context with a time limit, not in the Node host global context.

## Residual Work

- physical IA-32/BIOS coverage;
- UART behavior on multiple hardware generations;
- broader negative fuzzing of assembler input and third-party Packs;
- signed release provenance tied to tags and CI.

The former "CPU-bound task that never executes HLT" residual was closed on
2026-08-19: the record producer is now CPU-bound on metal, and all three
executors (QEMU, KVM with the periodic-PIT VMM model, and the browser
interpreter) prove asynchronous preemption of a task that never sleeps.
