<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Proof contract and evidence

> An assertion is a testable claim, not a screenshot or a passing checksum.

BasmOS already has a substantial verification suite. This document maps
existing claims to their **real owners**; it does not introduce a second
heartbeat oracle, an alternate release gate or a new QEMU workflow.

## One authoritative entry point

`make proof` streams and executes the original complete
`Makefile:proof-core` gate. It writes:

- `evidence/PROOF-REPORT.json`: machine-readable exit status, commit, UTC,
  duration, observed image hashes/sizes and tool versions.
- `evidence/PROOF-REPORT.md`: human-readable summary.
- `evidence/PROOF-REPORT.log`: full output of the underlying Make gate.

The reports are uncommitted diagnostic results, excluded by `.gitignore`.
An interruption or nonzero underlying exit must not produce a PASS report.
A PASS means **only** that the recorded full gate returned zero and all five
recorded image sizes and SHA-256 entries matched at the end. It does not imply
independent certification, signed authorship or exhaustive x86 correctness.

## Test ownership

| Claim or contract | Existing authoritative check | What it does not prove |
| --- | --- | --- |
| Five exact compiled guest images | `make all`, `make verify-nasm` | Future versions remain identical |
| Image sizes, hashes, command bounds, manifests | `SHA256SUMS`, `tools/proofctl` | Artifact authorship or correct behavior |
| Record boot, VGA `3/6/9`, live PIT heartbeat, IDT and PDE | `verify_qemu.py` via `make verify-qemu` | General scheduler fairness or hardware portability |
| All 65,536 bounded SPSC cursor states and KVM full-ring behavior | `make verify-ipc` | Arbitrary multicore concurrency |
| Data/code segment limits and `#GP` paths | `make verify-domains` | Isolation of hostile CPL0 code |
| CPL3 module, TSS, IRQ0 and serial return | `make verify-shell` | Full process isolation |
| JASH / J-Pack bytes, vocabulary, Decks, QEMU/KVM and capture | `make verify-jash` | A general-purpose POSIX shell |
| Native KVM guest and machine contract | `make verify-bemu` | Real motherboard/BIOS compatibility |
| Browser interpreter semantics | `make verify-browser` | Complete IA-32 emulation |
| Adversarial parsing and rejection of mutated contracts | `make verify-hardening` | Absence of every vulnerability |
| Sacred C and README geometry reproducibility | `make verify-sacred verify-readme` | An independent security proof |
| Site allowlist and local links | `make verify-site` | Browser accessibility or external DNS availability |

`make -f Makefile.upgrade upgrade-test` checks assembler-upgrade contracts
independently of the full gate. `make verify-sensitivity` performs 512
QEMU mutation boots and is a separately invoked, longer-running analysis.
The Bear compiler comparison remains opt-in with `BEAR=/path/to/bear`;
**SKIP must never be represented as PASS** for that comparison.

## The 3 / 6 / 9 oracle

The record sector's observable output is VGA text memory at `0xB8000`:

- `3`: the CPU-bound producer reached its cell.
- `6`: the second task ran although the producer does not yield.
- `9`: the IPC consumer received and displayed the producer's byte.
- **Heartbeat**: the byte at `0x6FC` must advance after the first match.

`verify_qemu.py` checks these signals, IDT gate bytes and paging directory
state. A frozen `3/6/9` frame is a failure. The report wrapper never
duplicates the QMP oracle or invents stronger architectural observations.

The CPL3 sibling is **`basmos-sh.bin`**, with a TSS/module protocol tested
by `verify_shell_qemu.py` and related KVM checks. Do not conflate its shell
with the 512-byte `basmos.bin` record artifact.

## Fail-closed release conditions

- Any required build, verifier, manifest, image-size, signature-byte,
  runtime heartbeat, IPC, negative-test or site check fails.
- Required NASM, QEMU, or accessible KVM is unavailable in the full gate.
- The full proof times out or is interrupted.
- An output artifact changes without an intentionally reviewed new manifest.

`make verify-ci` is useful without KVM but is **not** a release proof.
A green CI run also requires its separately declared assembler-upgrade,
session-manifest and generated-file-drift checks. See `../RELEASING.md`.

## Evidence hierarchy and remaining gaps

1. SHA-256: integrity relative to a known manifest, **not authorship**.
2. Toolchain and reproducible NASM/BASM rebuilds: determinism.
3. QEMU, KVM and browser results: distinct behavioral observations.
4. Runtime architectural reads: evidence for tested IDT/PDE/TSS properties.
5. Hardware runs: portability evidence only for the hardware actually tested.
6. Founder-signed annotated tags and GitHub attestation: release provenance
   under the documented trust assumptions.

The release workflow already verifies a founder-signed tag and emits an
attestation. Do **not** replace it with a checksum alone.

Additional future work can include independent CR0/CR3/CR4/SIDT/PIC/PIT
readbacks where not already covered, a dated and reproducible physical-boot
matrix, and byte-to-test coverage maps. None is claimed by this report.

Security scope and non-goals remain in `../SECURITY.md`,
`../THREAT_MODEL.md` and `../WAVES.md`.
