#!/bin/sh
# Deterministic manifest: no timestamps, hostnames or absolute paths.
# SPDX-License-Identifier: BSD-3-Clause
set -eu

printf '%s\n' '# SPDX-License-Identifier: BSD-3-Clause'
printf '%s\n' 'BASMOS-ARTIFACT-MANIFEST-V1'
for artifact in basmos.bin basmos-vm.bin basmos-sh.bin jash/jash.bin jash/jash-pack.bin; do
    bytes=$(wc -c < "$artifact" | tr -d ' ')
    hash=$(sha256sum "$artifact" | cut -d' ' -f1)
    printf 'artifact=%s bytes=%s sha256=%s\n' "$artifact" "$bytes" "$hash"
done
printf 'jash.native=253 jash.reserve=3 jash.cs_limit=256\n'
printf 'epistemic.words=27 capability.cells=15 vm=total-select proof.format=PRF1\n'
printf 'vm.magic=EVM1 vm.version=1 vm.opcodes=4\n'
printf 'surface.magic=SFC1 surface.count=6\n'
printf 'deck.magic=DCK1 deck.count=2 zero.mask=0x1f lab.mask=0x17\n'
printf 'toolchain=BASM proof=artifact-hashes+runtime-contracts\n'
