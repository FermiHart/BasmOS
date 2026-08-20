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
printf 'jash.native=255 jash.reserve=1 jash.cs_limit=255 pack.max=3584\n'
printf 'commands.exact=14 capability.cells=15 vm=total-select proof.format=PRF1\n'
printf 'vm.magic=EVM1 vm.version=1 vm.opcodes=4\n'
printf 'surface.magic=SFC1 surface.count=6\n'
printf 'deck.magic=DCK1 deck.count=2 zero.mask=0x1f lab.mask=0x17\n'
printf 'sigil.magic=SIG1 sigil.version=1 sigil.bytes=16 derivation=sha256(shell||jash)\n'
printf 'toolchain=BASM proof=artifact-hashes+runtime-contracts\n'
