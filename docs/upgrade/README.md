<!-- SPDX-License-Identifier: BSD-3-Clause -->

# BASM-NANO validation and optimization

The assembler update fixes instruction widths, signed immediates, symbol
identity and input validation, and optimizes parsing without changing any of
the five published guest images. It also provides reproducible host tests and
a bounded model of the assembled IPC handler bytes. The existing NASM, QEMU,
KVM and browser gates remain the native verification path.

## Requirements and commands

Use a POSIX host with a 64-bit `long`, GCC, Clang, Python 3 and GNU binutils
(`as`, `objcopy`). No Python packages are required. CI runs the complete host
compiler/sanitizer matrix. Bear remains an optional diversity check.

```sh
make all
make -f Makefile.upgrade upgrade-test
make -f Makefile.upgrade upgrade-reproduce
make -f Makefile.upgrade upgrade-bench
make -f Makefile.upgrade upgrade-receipt
python3 tools/upgrade/receipt.py --verify build/upgrade/release/receipt.json
```

After editing the canonical assembler, refresh the generated sacred source
before running native verification:

```sh
make -f Makefile.upgrade upgrade-integrate
make -f Makefile.upgrade upgrade-native
```

The native gate requires NASM, Node.js, QEMU and read/write access to `/dev/kvm`.
It checks generated-source freshness and runs independent NASM assembly plus
the repository's full `make proof`. Missing prerequisites produce `BLOCKED`,
not a successful boot claim.

## What the host gate checks

- Instruction encodings, 16/32-bit prefixes, signed immediates and stable
  two-pass layout, including an independent GNU assembler oracle.
- Exact symbol names, duplicate definitions, expression overflow and depth,
  operand arity, conditional balance, line/input/image bounds.
- Decimal/hex literals, register/mnemonic spellings, quoted comments and
  word/dword emission at the output boundary.
- Invalid hexadecimal digits, MOV immediate boundaries and forward references,
  deliberate byte-immediate truncation, and worst-case symbol hash collisions.
- Output/source aliases, late write failure and preservation of prior output.
- All five guest image sizes, committed bytes and SHA-256 identities, including
  the exact 512-byte size and `55 AA` signature of both boot sectors.
- Deterministic malformed-input mutations under GCC and Clang, with and
  without ASan/UBSan.
- A bounded interpreter of send/receive handler bytes: 393,216 transitions
  per image variant and seven required semantic mutation counterexamples.

The IPC model is not a complete x86 emulator and does not model IRQ delivery,
paging or interrupt-return semantics. It complements the existing native gates.

## Numeric and symbol contracts

Hexadecimal literals accept only `0` through `9`, `a` through `f`, and `A`
through `F` after the `0x` or `0X` prefix. Invalid characters must fail assembly
without replacing an existing binary or map.

MOV immediates for 16-bit registers and memory must be in `-32768..65535`;
32-bit forms must be in `-2147483648..4294967295`. Both signed values and their
unsigned bit patterns are accepted. An unresolved forward expression is checked
after resolution, so a provisional pass-one value cannot reject valid code.
Byte-immediate MOV, TEST, CMP, OR, INT, IN and OUT retain their existing low-byte
extraction contract. Data directives `db/dw/dd` and `times ... db` also retain
deliberate low-bit extraction. Range checks belong to instruction operands,
not the shared byte-emission primitives.

The symbol vector accepts at most 256 definitions; its 512-slot index is at
most half full even when every name has the same starting hash. Compile-time
guards preserve the power-of-two table size, load bound and index width.
The 257th definition fails with `too many symbols`; hash collisions do not
lower the supported symbol count.

## Boot sector publication

`basm-nano --boot-sector` requires exactly 512 output bytes with `55 AA` in the
last two positions. Both checks run after final assembly and before any binary
or map is published, including map output to stdout. An oversized, undersized
or incorrectly signed sector leaves existing output files intact.

The main Makefile uses this mode for `basmos.bin`, `basmos-sh.bin`, `make map`
and `make shell-map`. The source-level `times 510-($-$$) db 0` padding remains
an additional budget check; the explicit mode also catches bytes appended
after the signature. General assembly keeps its 65,536-byte output limit,
which permits the separate 3,584-byte JASH Pack.

## Output publication contract

Inputs are regular files up to 1 MiB. Binary/map destinations must be distinct
from the input and each other, including existing hard-link aliases; output
symlinks and devices are rejected. Both output streams are staged and checked
before publication. Each rename is atomic, but the pair is not a filesystem
transaction. There is no `fsync`/power-loss durability promise, concurrent
filesystem sandbox, or preservation of old ACLs and permissions. Temporary
files use restricted permissions; abrupt termination may leave them behind.

## Benchmarks and receipts

The benchmark measures two assembly passes, excluding CLI startup, file I/O,
publication and guest runtime. It compares both versions on the same CPU,
alternates order, calibrates sample duration and records source/workload
hashes, raw samples and CPU/wall medians. For an exact historical source:

```sh
python3 tools/upgrade/benchmark.py --baseline /path/to/original.c \
  --min-sample-ms 50 --out build/upgrade/comparison
```

The default baseline is the frozen source in `tests/upgrade/reference/`.
See [OPTIMIZATION.md](OPTIMIZATION.md) for measured results, provenance and
the limits of measurements on a shared host.

A host receipt binds current inputs, the completed compiler matrix, assembler,
artifact hashes/sizes and symbol maps. Verification detects changed files;
it is not an authenticated signature. Its `release_status=BLOCKED` describes
the host receipt's limited scope even when a separate native proof has passed.
Native outcomes are recorded separately in `build/upgrade/native/status.json`.

Generated binaries, logs, receipts and raw measurements stay in ignored
`build/upgrade/`; they are not source files or release artifacts.
