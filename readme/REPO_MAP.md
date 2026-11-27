<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Repository map

**One file, one home.** This map describes the existing BasmOS layout; it does
not move the record artifacts or silently change any release-facing path.

| Content | Canonical location | Rule |
| --- | --- | --- |
| 512-byte record and sibling source | `basmos.basm`, `basmos-sh.basm` | Keep canonical input paths stable |
| Five recorded guest images | root `*.bin`, `jash/*.bin` | Version exact bytes; never hand-edit |
| Basm assembler and its own tests | `basm-nano/` | Build code and assembler-specific checks stay together |
| KVM executor and machine contract | `bemu/` | No host binaries in Git |
| CPL3 nucleus, Pack and contracts | `jash/` | Preserve signed-off image size and manifest contracts |
| Measurement and content-generation tools | `tools/` | Host utilities, native proofctl and README renderer |
| Orchestration, capture and new harnesses | `scripts/` | Executables, not prose |
| New unit/regression test inputs | `tests/` | Add explicit Makefile verification targets |
| Reader guidance and claim boundaries | `readme/` | Supporting docs, diagrams and this map |
| Assembler-upgrade research | `docs/upgrade/` | Preserve scoped upgrade notes |
| Committed reference evidence | `evidence/` | Retain provenance and committed manifests |
| Generated proof-run reports | `evidence/PROOF-REPORT.*` | Ignored by Git; attach through CI instead |
| Browser interpreter and site | `website/` | Presentation is verified, never a new source of truth |
| CI, Pages, signed releases | `.github/workflows/` | Reuse existing workflows, do not add competing QEMU jobs |

## Root stability contract

The root is **stable, not arbitrarily frozen**. These entry points have external
links, release meaning or Make dependencies and should not be relocated just
to make a directory listing shorter:

- `Makefile` and `Makefile.upgrade`: canonical build, proof and research targets.
- `basmos.basm`, `basmos-sh.basm`: canonical guest input paths.
- `basmos.bin`, `basmos-vm.bin`, `basmos-sh.bin`: committed byte records.
- `SHA256SUMS` and `ARTIFACTS.manifest`: integrity and expected-size contracts.
- `README.md`, `RESEARCH.md`, `RELEASING.md`, `SECURITY.md` and other
  existing root documents: stable public links and governance.
- Ten existing `verify_*.py` programs: compatibility entry points used by
  Make, CI and documentation. **New** harnesses go to `scripts/` or `tests/`.

Do not batch-move historical verifiers. A future migration may preserve thin
wrappers at their current paths, update every caller and verify both old and
new entry points before removing any compatibility layer.

## Sources, outputs and evidence

The five versioned guest images are **outputs whose exact bytes are the
research subject**, not alternate hand-edited source files. The sources live
in `basmos.basm`, `basmos-sh.basm` and `jash/`. A manifest matches a byte
stream; it is not an author's signature and does not verify guest execution.

`make proof` is the **one full release gate**. It delegates unchanged tests
to `Makefile:proof-core`, streams their output and writes ignored diagnostic
reports in `evidence/`. `make verify-ci` is a useful KVM-free subset, but it
is not a substitute for `make proof`.

The CI workflow uploads diagnostic reports, including failed runs. The signed
tag/release and attestation rules continue to live in `RELEASING.md` and the
existing `release.yml`. Do not describe a CI report as signed provenance.

## Adding a file in one minute

1. **Executes or orchestrates?** `scripts/`; a test input goes to `tests/`.
2. **Measures or builds?** `tools/` or the existing subsystem directory.
3. **Explains scope or limits?** `readme/`.
4. **Ships an immutable record?** Follow `RELEASING.md`; no manual byte edits.
5. **Changes a verified claim?** Link a named Makefile target and update
   `readme/PROOF.md`, `CONTRIBUTING.md` or the applicable canonical document.

Keep the research exploratory locally. Make public claims only from validated
inputs and successful, recorded tests.
