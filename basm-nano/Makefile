# basm-nano — the purpose-built assembler for five BasmOS repository artifacts.
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Werror

.PHONY: all sacred test test-sacred clean
all: basm-nano

sacred: basm-sacred

basm-nano: basm_nano.c
	$(CC) $(CFLAGS) -o $@ basm_nano.c

basm-sacred: basm_sacred.c basm_nano.c
	$(CC) $(CFLAGS) -o $@ basm_sacred.c

# Verify that all five generated artifacts are byte-identical to their
# committed repository counterparts.
test: basm-nano
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	./basm-nano -f bin -o "$$tmp/metal.bin" ../basmos.basm && \
	cmp "$$tmp/metal.bin" ../basmos.bin && echo "metal: BYTE-IDENTICAL" && \
	./basm-nano -f bin -DBEMU_CONTRACT -o "$$tmp/vm.bin" ../basmos.basm && \
	cmp "$$tmp/vm.bin" ../basmos-vm.bin && echo "contract: BYTE-IDENTICAL" && \
	./basm-nano -f bin -o "$$tmp/shell.bin" ../basmos-sh.basm && \
	cmp "$$tmp/shell.bin" ../basmos-sh.bin && echo "ring3: BYTE-IDENTICAL" && \
	./basm-nano -f bin -o "$$tmp/jash.bin" ../jash/jash.basm && \
	cmp "$$tmp/jash.bin" ../jash/jash.bin && echo "jash: BYTE-IDENTICAL" && \
	./basm-nano -f bin -o "$$tmp/jpack.bin" ../jash/jash-pack.basm && \
	cmp "$$tmp/jpack.bin" ../jash/jash-pack.bin && echo "jpack: BYTE-IDENTICAL"

# The generated Metatron edition is a separate translation unit. Its geometry
# must be current, and it must emit all five committed artifacts byte for byte.
test-sacred: test basm-sacred
	@python3 ../tools/generate_sacred_basm.py --check
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	./basm-sacred -f bin -o "$$tmp/metal.bin" ../basmos.basm && \
	cmp "$$tmp/metal.bin" ../basmos.bin && echo "sacred metal: BYTE-IDENTICAL" && \
	./basm-sacred -f bin -DBEMU_CONTRACT -o "$$tmp/vm.bin" ../basmos.basm && \
	cmp "$$tmp/vm.bin" ../basmos-vm.bin && echo "sacred contract: BYTE-IDENTICAL" && \
	./basm-sacred -f bin -o "$$tmp/shell.bin" ../basmos-sh.basm && \
	cmp "$$tmp/shell.bin" ../basmos-sh.bin && echo "sacred ring3: BYTE-IDENTICAL" && \
	./basm-sacred -f bin -o "$$tmp/jash.bin" ../jash/jash.basm && \
	cmp "$$tmp/jash.bin" ../jash/jash.bin && echo "sacred jash: BYTE-IDENTICAL" && \
	./basm-sacred -f bin -o "$$tmp/jpack.bin" ../jash/jash-pack.basm && \
	cmp "$$tmp/jpack.bin" ../jash/jash-pack.bin && echo "sacred jpack: BYTE-IDENTICAL"

clean:
	rm -f basm-nano basm-sacred
