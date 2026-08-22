#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu

out=${1:?usage: scripts/stage_site.sh OUTPUT_DIRECTORY}
if [ -e "$out" ]; then
    printf 'FAIL: staging destination already exists: %s\n' "$out" >&2
    exit 1
fi
mkdir -p "$out/readme" "$out/basm-nano" "$out/bemu" "$out/evidence" \
    "$out/jash" "$out/scripts" "$out/website"

python3 tools/generate_readme_art.py --check

cp website/index.html "$out/index.html"
cp website/jash-live.svg "$out/jash-live.svg"
cp website/jash-live.svg "$out/website/jash-live.svg"
cp readme/hero-proof-geometry.svg readme/hero-proof-geometry-mobile.svg \
   readme/artifact-constellation.svg readme/artifact-constellation-mobile.svg \
   readme/proof-lattice.svg readme/proof-lattice-mobile.svg "$out/readme/"
cp website/CNAME "$out/CNAME"
cp LICENSE README.md AUTHORS.md DOMAINS.md RESEARCH.md RING3.md THREAT_MODEL.md \
   SECURITY.md THIRD_PARTY_NOTICES.md TRADEMARKS.md RELEASING.md WAVES.md \
   OPTIMIZATIONS.md "$out/"
cp ARTIFACTS.manifest SHA256SUMS Makefile basmos.basm basmos-sh.basm \
   basmos.bin basmos-vm.bin basmos-sh.bin "$out/"
cp basm-nano/basm_nano.c basm-nano/basm_sacred.c "$out/basm-nano/"
cp bemu/bemu_nano.c "$out/bemu/"
cp jash/jash.basm jash/jash.bin jash/jash-pack.basm jash/jash-pack.bin "$out/jash/"
cp evidence/jash-session.commands evidence/jash-session.ansi \
   evidence/jash-session.txt evidence/jash-session.manifest "$out/evidence/"
cp scripts/capture_jash.py scripts/toolchain.sh scripts/verify_site.py "$out/scripts/"
cp verify_qemu.py verify_domains.py verify_ipc_model.py verify_jash.py \
   verify_jash_qemu.py verify_jash_fuzz.py website/test_interpreter.js "$out/"
touch "$out/.nojekyll"

(cd "$out" && sha256sum -c SHA256SUMS)
(cd "$out" && sha256sum -c evidence/jash-session.manifest)
python3 scripts/verify_site.py "$out"
