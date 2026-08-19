<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com> -->

# BasmOS Threat Model

## Scope

BasmOS is a systems-research artifact. This model covers the guest artifacts,
their local build and verification tools, QEMU and KVM execution, and the static
browser demonstration. It does not treat a successful test run as evidence that
the system is suitable for production or for arbitrary untrusted workloads.

Relevant adversarial inputs include a modified boot sector, a hostile CPL3
module, a malformed JASH Pack or serial stream, a compromised repository or
toolchain, and content intended to exploit a host emulator, hypervisor, browser,
or test harness.

## Assets

- Host integrity and availability, including the kernel, user account, files,
  terminal, and processes running build or verification tools.
- Guest CPL0 integrity: kernel code and data, GDT, IDT, TSS, page directory,
  interrupt state, and the CPL0 stack.
- Shell control flow: the CPL3 monitor, module entry and return frames, arena
  bounds, and the serial ABI.
- Artifact integrity: correspondence among reviewed source, generated binaries,
  committed sizes, boot signatures, manifests, and SHA-256 values.
- Verification integrity: test inputs, expected outputs, QMP observations, KVM
  exit handling, and browser-interpreter results.
- Availability of the emulator, VMM, browser tab, and guest serial session.

## Trust Assumptions

- In `basmos.bin`, both tasks and all guest code are trusted. They run in CPL0
  with shared writable memory; there is no security boundary between them.
- In `basmos-sh.bin`, CPL0 code, descriptor tables, the syscall handler, and
  interrupt handlers form the guest trusted computing base. The CPL3 monitor is
  trusted to load modules correctly but is not isolated from those modules.
- A loaded CPL3 module may be hostile. It is expected to remain outside CPL0,
  but it may corrupt the shared arena, misuse syscalls, consume resources, or
  halt the guest through an exception.
- The current JASH nucleus and Pack are trusted application inputs. The Pack is
  data outside the module code limit, but it is writable and is not accepted as
  a safe arbitrary third-party format.
- Local source, build scripts, test scripts, the C compiler, Make, Python, Node,
  NASM when used, QEMU, the host kernel, KVM, firmware, and CPU virtualization
  are trusted for the conclusions drawn from their results.
- SHA-256 checks detect byte changes relative to expected values. They do not
  establish authorship, release provenance, toolchain integrity, or freedom
  from malicious code.

## Trust Boundaries

### CPL3 To CPL0

The shell artifact enters user mode with DPL3 code and data selectors. Segment
bases and limits exclude CPL0 memory from ordinary CPL3 instruction fetches and
data accesses. IOPL 0 and an absent TSS I/O bitmap deny direct port access.
`int 0x80`, hardware interrupts, and exceptions enter CPL0 through the IDT and
use `SS0:ESP0` from the TSS when crossing privilege levels.

This boundary protects CPL0 from the tested CPL3 operations. It does not isolate
the monitor from a module, because both use the same writable arena and can use
available DPL3 descriptors and syscalls.

### Paging And Segmentation

PDE0 maps `0x00000000` through `0x003fffff` as present, writable, and user
accessible. Segment limits, rather than page permissions, provide the guest's
memory boundary. There is no separate user address space and no page-level NX
boundary between the JASH nucleus and Pack.

### Guest To QEMU Host

QEMU executes guest instructions and emulates firmware and devices in a host
process. A malicious CPL0 guest can exercise QEMU's CPU and device-model attack
surface even when the guest has no network device. The verification commands
reduce exposure by using a read-only drive, disabled networking,
no display, no reboot, and QEMU sandbox restrictions on privilege elevation,
process creation, obsolete features, and resource controls.

These options reduce impact but do not make QEMU an infallible security
boundary. Default machine devices and firmware still exist, QMP and serial are
host interfaces, and emulator vulnerabilities may permit denial of service or
guest-to-host compromise. Modified guests should run as an unprivileged user in
an additional host sandbox.

### Guest To KVM Host

`bemu-nano` loads the guest into a private 4 MiB mapping, creates a KVM VM, and
handles KVM exits and a small software model for serial I/O and timer delivery.
It does not pass guest devices through to the host. The guest nevertheless runs
through the host kernel's KVM interface and hardware virtualization, while the
C VMM parses files, arguments, serial streams, and exit data.

A malicious guest may target KVM, CPU virtualization, or defects in
`bemu-nano`. The Make targets use wall-clock timeouts for automated runs and
`bemu-nano` limits handled exits, but neither mechanism guarantees termination
of every guest instruction stream. The VMM has no built-in seccomp, chroot, or
privilege separation. Run modified guests without elevated privileges and with
external process, filesystem, and resource isolation.

The bEMU timer is intentionally simplified. In plain record-boot mode it is a
periodic 18.2 Hz model delivered through the KVM interrupt-window mechanism;
in scripted serial and contract modes it injects IRQ0 after guest `HLT`.
Neither is equivalent to QEMU's PIC/PIT model or physical hardware.

### Browser And Node Execution

The static site contains an inline, limited IA-32 interpreter for the fixed
`basmos.bin` instruction subset. Interpreted guest state is held in JavaScript
arrays and has no designed interface to native execution, files, or devices.
Per-frame instruction budgets limit ordinary browser work.

The interpreter is not a complete x86 model and does not model the CPL3 shell,
full segmentation, paging, or hardware. A defect can produce incorrect results
or consume browser resources. Compromised site JavaScript executes with the
site's browser origin and is outside the guest model; browser and distribution
security remain external dependencies.

`website/test_interpreter.js` extracts known repository code and runs it in a
Node `vm` context with a timeout. A Node `vm` context is a test containment
measure, not a security boundary for attacker-controlled JavaScript.

### Build And Verification

The assembler, compiler, scripts, manifests, and expected output are all host
inputs. Rebuilding `basm-nano`, comparing NASM output, checking signatures and
SHA-256 values, reading guest memory through QMP, fuzzing commands, and mutating
artifacts provide independent checks for specific failure modes. Shared source,
assumptions, or compromised host dependencies can still invalidate multiple
checks at once.

## Defenses In Scope

- IA-32 CPL checks, DPL3 segment limits, IOPL 0, TSS stack switching, and IDT
  gate privilege levels in `basmos-sh.bin`.
- A 256-byte module code limit and a 4096-byte user data arena.
- Fail-stop exception handling instead of continuing after a detected guest
  fault.
- Negative tests for `cli`, `out dx,al`, and loading the CPL0 data selector from
  a module.
- Read-only image execution, disabled networking, and QEMU sandbox options in
  QEMU verification.
- Private guest RAM, no device passthrough, exit limits, and external timeouts
  for automated KVM runs.
- Exact artifact sizes, boot signatures, structural checks, deterministic
  manifests, hashes, mutation tests, and alternate NASM assembly.
- A fixed-subset browser interpreter with instruction budgets and a timed Node
  test context.

These are risk reductions and regression checks, not a complete security
argument.

## Explicit Non-Goals

- Protecting production data or safely hosting arbitrary untrusted guest images.
- Isolation between the two CPL0 tasks in `basmos.bin`.
- Confidentiality or integrity between the CPL3 monitor, modules, JASH, and the
  shared arena.
- Treating JASH Decks, Surfaces, capability cells, manifests, or PRF1 records as
  hardware-enforced or cryptographic security mechanisms.
- Safe admission of arbitrary third-party modules or Packs.
- Guest availability, process recovery, fair scheduling, or resource quotas.
- Protection against side channels, speculative execution, CPU errata, timing
  leakage, or denial of service.
- Secure boot, signed updates, authenticated serial transport, encryption,
  rollback protection, or trusted release provenance.
- SMP, DMA, IOMMU, physical-device isolation, or comprehensive IA-32 hardware
  compatibility.
- Formal verification, exhaustive instruction testing, or full x86 equivalence
  in QEMU, KVM, bEMU, or the browser interpreter.
- Defending the host from a malicious CPL0 guest without an external sandbox and
  maintained host virtualization stack.

## Residual Risks

- The broad user-accessible mapping and writable alias of module code increase
  the impact of CPL3 memory errors and deliberate self-modification.
- A module can enter other DPL3 code, invoke any syscall, corrupt arena data,
  spin indefinitely, block in serial polling, flood output, or trigger a guest
  halt. The current kernel cannot terminate only the offending module.
- The trap-gate syscall path permits timer interruption. The timer and syscall
  handlers share a minimal CPL0 stack and unsynchronized UART output.
- Exception handling is intentionally coarse. The negative suite covers three
  hostile instruction sequences and does not exhaust descriptor, interrupt,
  return-frame, or instruction-decoding edge cases.
- Malformed serial or Pack data may cause application corruption or fail-stop
  behavior even when CPL0 isolation holds.
- QEMU, KVM, the host kernel, the CPU, the C VMM, Python and Node harnesses, and
  the browser may contain exploitable vulnerabilities.
- Exit-count and wall-clock limits may not prevent every host or guest denial of
  service, especially interactive runs without a timeout.
- Emulator, simplified bEMU, browser, and physical-machine behavior may differ.
  Physical IA-32, BIOS, PIC/PIT, UART, and device coverage remains limited.
- Hash and byte-identity checks can reproduce reviewed bytes while still sharing
  a compromised source, compiler, dependency, or expected-value origin.
