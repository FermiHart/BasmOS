<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com> -->

# BasmOS

BasmOS is a 512-byte IA-32 nanokernel engineering artifact. The complete
bare-metal image includes the BIOS entry path, 32-bit protected mode, active PSE
paging, IDT, PIC/PIT timer handling, two timer-preempted tasks (one CPU-bound,
one sleeping), bounded per-task data and code segments, an SPSC IPC queue, a per-tick
heartbeat and VGA evidence output.

The project is open source under the BSD-3-Clause license.

## Record Scope

The comparison category requires every candidate to provide all of these
features in a functional bare-metal artifact:

1. IA-32 protected mode.
2. Active paging.
3. IDT and a hardware timer source.
4. At least two timer-preempted tasks.
5. Functional inter-task IPC.

Additional features are allowed. The ranking metric is the total number of
bytes required from BIOS entry to the demonstrated behavior, including every
boot stage.

In the documented public survey completed on 2026-08-19, BasmOS is the smallest
verified artifact found in this category: 512 bytes total, with a 399-byte
payload. This is a reproducible research result, not certification by an
external record authority. See [`RESEARCH.md`](RESEARCH.md).

## Artifacts

| Artifact | Purpose |
|---|---|
| `basmos.bin` | 512-byte bare-metal record artifact |
| `basmos-vm.bin` | 232-byte guest for the documented bEMU machine contract |
| `basmos-sh.bin` | 512-byte kernel with a separate CPL3 monitor/module boundary |
| `jash/jash.bin` | 256-byte CPL3 JASH nucleus |
| `jash/jash-pack.bin` | JASH presentation, tables and manifests |

Expected sizes and hashes are committed in `ARTIFACTS.manifest` and
`SHA256SUMS`. The five guest binaries are intentionally versioned because exact
bytes are the subject of the project. Host executables are never versioned.

## Build

Required for the basic build:

- a C compiler (`cc`);
- GNU Make;
- Linux UAPI headers for `<linux/kvm.h>` when building `bemu-nano`.

Required for the full verification suite:

- Python 3;
- Node.js;
- QEMU `qemu-system-i386`;
- Linux KVM with access to `/dev/kvm`;
- GNU coreutils, including `sha256sum` and `timeout`.

Build all guest artifacts:

```sh
make all
```

Run the complete local gate:

```sh
make proof
```

The gate checks committed SHA-256 values, native structural contracts, an
independent NASM re-assembly when NASM is installed, QEMU, the sandboxed
JavaScript interpreter, KVM, CPL3 behavior, parser fuzzing and artifact
mutations. At the end it reports exactly which gates ran. The optional
sovereign-compiler gate (`make verify-bear BEAR=...`) never claims to have run
when the Bear compiler is not supplied.

Useful focused commands:

```sh
make verify-qemu
make verify-domains
make verify-browser
make verify-shell
make verify-jash
make verify-nasm
make verify-bear BEAR=/path/to/bear
make verify-sensitivity
make map
make size
```

## Architecture Notes

`basmos.bin` runs both record tasks in CPL0 and one shared paged address space.
Ordinary DS accesses are bounded to separate 256-byte windows and each task's
instruction fetch is bounded to its own code bytes; handlers use a flat ES
capability, stacks use flat SS, and task VGA writes use a VGA-only GS. This
contains accidental data accesses and runaway execution, but it is not a
hostile-code boundary: CPL0 code can load another selector or replace the GDT. The separate
`basmos-sh.bin` artifact demonstrates the CPL3/TSS boundary for hostile modules.

This is an engineering proof and research artifact, not a production operating
system. See [`DOMAINS.md`](DOMAINS.md) for the segment contract and proof, and
read [`THREAT_MODEL.md`](THREAT_MODEL.md) before executing untrusted guest images
or modules.

## Website

The static site lives in `website/` and is deployed by the GitHub Pages workflow.
It contains the exact 512-byte record artifact and a deliberately limited IA-32
interpreter for its instruction subset.

Maintainers should follow [`RELEASING.md`](RELEASING.md) for the clean-room
verification, GitHub publication, Pages and signed-release procedure.

## Security

Report security issues privately as described in [`SECURITY.md`](SECURITY.md).
Do not attach secrets or exploit payloads to public issues.

## License And Names

Original source code in this repository is BSD-3-Clause. External tools and
system headers are dependencies, not vendored source. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

The code license does not grant trademark or endorsement rights. See
[`TRADEMARKS.md`](TRADEMARKS.md).

## Author

**F E R M I ∞ H A R T**<br>
<contact@fermihart.com>
