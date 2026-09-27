<!-- SPDX-License-Identifier: BSD-3-Clause -->

# BASM-NANO: measured parser and encoder optimization

## Scope and provenance

This follow-up was executed on 2026-09-27 after the first Upgrade-2.0
integration. It measures the assembler's two passes, including source parsing,
symbol handling and byte emission. It does not measure CLI startup, file I/O,
atomic publication, boot latency or the runtime speed of the guest.

SHA-256 identities of the three C sources:

| Source | SHA-256 |
|---|---|
| GitHub `8614d096`, original | `786e01cea48cf7c2b60d8c97409aa108439a1ce95df927419795f8f648fdd438` |
| Integrated Upgrade-2.0, before optimization | `0f7f7dd95d62b357dc0c9fec22f1e51b31f375c9469e9107382ba2b85cabb255` |
| Optimized | `4515a4e5f7d4e06ed68e5a0d2ca43aeba4cfa9cfff48ea43657aef6a83f4a43c` |

## Engineering changes

The initial gprof run on the sector source identified line parsing and register
recognition as major costs. Instrumented profiles were used for diagnosis only;
the benchmark binaries do not contain profiling instrumentation.

- Register recognition now decodes the small grammar directly, instead of
  scanning three string tables. Full spelling and width checks remain.
- Mnemonic dispatch partitions on the first character and compares the complete
  remaining spelling, preserving exact opcode identity and operand arity.
- A single bounded scan copies the line and handles quotes/comments. Labels and
  mnemonics are split in that buffer rather than copied and rescanned.
- Decimal/hex conversion checks overflow before accumulating each digit.
  Literal-only expressions bypass recursive descent; compound expressions keep
  the existing precedence, depth limit and checked arithmetic.
- Word/dword emission checks the complete output span once and emits explicit
  little-endian bytes. Both passes still enforce the image limit.
- Global symbol references use their already canonical names without copying
  them into a qualification buffer. Local names remain scoped and bounded.
- Empty symbol indexes need no reset write. Assemblies following one with
  symbols still clear the index before inserting new symbols.
- Cold error paths and a non-inlined large instruction encoder keep the main
  parser smaller. Compiler-specific layout hints have a portable fallback.

No source/result cache survives an assembly; no validation was disabled.

## Benchmark method

Both variants used GCC 13.3, `-std=c11 -O2 -D_XOPEN_SOURCE=700`, on the same
allowed CPU (0) of an Intel Core i5-1235U. Each comparison ran three rounds,
five samples per workload and variant, alternated original/updated order,
and used three warmups in each process: **270 timed observations per
comparison, 540 for both final comparisons**.

The workloads are unchanged from the first benchmark. Loop counts are now
calibrated to target at least 50 ms of CPU time for the faster variant;
each pair uses the same loop count. Source and workload hashes are checked
before and after the run. Every pair checks output length and FNV32; the
five repository artifacts are additionally checked with SHA-256 and NASM.

This is a shared laptop with uncontrolled frequency. Development runs saw
load averages over 50 on 12 logical CPUs; short wall-clock samples were noisy.
The table therefore leads with median **CPU time**, and also reports wall-time
ratios. These are measured medians, not a guarantee for every input, individual
sample, compiler or machine. Small-case ranges overlap. The two comparisons
were run sequentially; compare within a run, not absolute times across runs.

## Final: optimized versus GitHub original

Times are microseconds per complete two-pass assembly. Ratios above 1 mean faster.

| Workload | Original CPU, µs | Optimized CPU, µs | CPU speedup | Wall speedup |
|---|---:|---:|---:|---:|
| Single `nop` | 0.680 | 0.618 | 1.10× | 1.12× |
| Pad 512 bytes | 2.595 | 0.759 | 3.42× | 3.41× |
| Pad 65,536 bytes | 163.152 | 4.120 | 39.60× | 39.66× |
| 4,096 numeric data bytes | 712.190 | 380.050 | 1.87× | 1.87× |
| 256 symbols / 5,000 references | 16,096.585 | 2,441.941 | 6.59× | 6.59× |
| `basmos.basm` | 256.960 | 151.648 | 1.69× | 1.73× |
| `basmos-sh.basm` | 290.630 | 146.064 | 1.99× | 1.93× |
| `jash/jash.basm` | 187.762 | 92.246 | 2.04× | 2.03× |
| `jash/jash-pack.basm` | 234.412 | 146.667 | 1.60× | 1.52× |

All nine median CPU and wall-time ratios improved. The original regressions
in numeric data, the main sector and the shell sector are gone in this run.

## Final: additional gain over the unoptimized upgrade

| Workload | CPU speedup | Wall speedup |
|---|---:|---:|
| Single `nop` | 1.72× | 1.67× |
| Pad 512 bytes | 1.79× | 1.79× |
| Pad 65,536 bytes | 1.15× | 1.16× |
| Numeric data | 2.01× | 2.01× |
| Symbol references | 1.13× | 1.13× |
| Main sector | 1.75× | 1.75× |
| Shell sector | 1.93× | 1.93× |
| JASH | 1.89× | 1.84× |
| J-Pack | 1.30× | 1.32× |

All nine median CPU and wall-time ratios improved in this comparison too.
The original upgrade already provided most of the padding and symbol gains;
the second table isolates the additional benefit of this optimization work.

## Verification and size cost

- Four compiler/sanitizer variants: GCC, Clang, GCC+ASan/UBSan and
  Clang+ASan/UBSan; each passed 10 methods and 544 subcases, zero failures/skips.
- Added boundary coverage for literals, precedence, depth, register/mnemonic
  spelling, quoted semicolons, exact line limits and batched writes at 64 KiB.
- The 2,676-statement GNU assembler oracle, 400 input mutations and bounded
  IPC byte-model checks passed in every variant.
- All 14 original/updated bug reproductions and the host receipt passed.
- Regenerated sacred source, NASM identity and full `make proof` passed,
  including QEMU, KVM, JASH, browser, fuzz/mutation and site checks.
- All five committed guest binaries still match `SHA256SUMS` exactly.
- Optional Bear compiler diversity was not run.

With identical compiler flags, host text/data/BSS totals are 130,659 bytes
(GitHub), 137,359 bytes (upgrade), and 139,325 bytes (optimized). The optimized
executable is 44,640 bytes, 424 bytes larger on disk than the unoptimized
upgrade. Guest images do not grow. These sizes are not measured RSS.

## Reproduction and evidence

Recover the GitHub source with `git show 8614d096:basm-nano/basm_nano.c` into
a separate file, then run:

```sh
python3 tools/upgrade/benchmark.py --baseline /path/to/original.c \
  --min-sample-ms 50 --out build/upgrade/optimized-vs-github
make -f Makefile.upgrade upgrade-receipt upgrade-reproduce
make -f Makefile.upgrade upgrade-integrate upgrade-native
```

For the second comparison use the exact pre-optimization source identified
above (the production C produced by the original Upgrade-2.0 patch).
Local evidence, including all raw samples and compile logs, is in:

- `build/upgrade/optimized-vs-github/{results,raw}.json`
- `build/upgrade/optimized-vs-upgrade/{results,raw}.json`
- `build/upgrade/gate/gate.json`
- `build/upgrade/native/status.json` and `step-3.log`

`build/` is ignored by Git. Earlier `optimization-round*` runs are retained
locally as development measurements, not the final results above.
