<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Third-Party Notices And Provenance

## Repository License

Original BasmOS source code is licensed under BSD-3-Clause by
**F E R M I ∞ H A R T**.

No third-party source code is vendored in the public repository.

## Project Lineage

`bemu/bemu_nano.c` is a purpose-reduced KVM runner derived from bEMU in Beyond,
another project by the same author and copyright holder. `basm-nano/basm_nano.c`
is a purpose-built assembler informed by the author's BearBasm work. The author
has relicensed the original code contributed to this repository under
BSD-3-Clause.

This lineage statement documents provenance; it does not import the licenses or
source trees of those separate projects into BasmOS.

## External Build And Test Dependencies

The following are external dependencies and are not redistributed here:

- Linux KVM UAPI headers, included as `<linux/kvm.h>`. Linux UAPI headers carry
  their own SPDX terms, commonly `GPL-2.0 WITH Linux-syscall-note`.
- QEMU, used as an external emulator in verification.
- Python, Node.js, a C compiler, GNU Make and coreutils.
- NASM, used only as an optional independent assembler comparison.

Their licenses govern those tools and installed headers. They do not change the
BSD-3-Clause license of original BasmOS source code.

## Research References

Projects cited in `RESEARCH.md` are prior-art references. Their source code is
not copied into BasmOS.
