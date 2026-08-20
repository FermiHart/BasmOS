# BasmOS: a nanokernel whose complete record artifact fits in one 512-byte sector.
# Local source builds basm-nano, the guest artifacts, bEMU-NANO and proofctl.
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
#
# Running `make` without a target displays this menu.

BASM   = basm-nano/basm-nano
QEMU   = qemu-system-i386
TIMEOUT ?= timeout
KERNEL = basmos.bin
VMKERN = basmos-vm.bin
SHKERN = basmos-sh.bin
JASH   = jash/jash.bin
JPACK  = jash/jash-pack.bin
PROOFCTL = tools/proofctl
BEMU_RUNNER = bemu/bemu-nano
SHELL_INPUT = 3f7210b35ab801000000cd80b804000000cd8078
# Optional sovereign-compiler gate. Set BEAR to a non-interactive Bear compiler
# binary to run it. When unset, the gate reports SKIP and no cc-vs-Bear
# byte-identity claim is made anywhere.
BEAR ?=
BEARFLAGS ?=

.DEFAULT_GOAL := help
.PHONY: help all shell jash jash-live bemu bemu-contract verify verify-ci verify-nasm verify-bear verify-sensitivity verify-qemu verify-domains verify-browser verify-bemu verify-shell verify-shell-qemu verify-shell-bemu verify-jash verify-jash-qemu verify-jash-bemu verify-hardening proof manifest clean-room-proof map shell-map jash-map size clean

help: ## display this menu
	@printf '\033[32mBasmOS: a complete record artifact in one 512-byte sector\033[0m\n\n'
	@printf '  \033[1mmake all\033[0m      build the record, machine-contract, ring-3 and JASH artifacts\n'
	@printf '  \033[1mmake shell\033[0m    load and run a module in the ring-3 capsule over serial\n'
	@printf '  \033[1mmake jash\033[0m     demonstrate the CPL3 shell, Decks and typed Surfaces\n'
	@printf '  \033[1mmake jash-live\033[0m\n               enter interactive JASH; type help, finish with bye\n'
	@printf '  \033[1mmake bemu\033[0m     boot the 512-byte sector in bEMU-NANO with terminal display\n'
	@printf '  \033[1mmake bemu-contract\033[0m\n               enter the 232-byte guest directly in PM32 with paging\n'
	@printf '  \033[1mmake verify\033[0m   verify the record with QEMU, the JS interpreter and KVM\n'
	@printf '  \033[1mmake verify-shell\033[0m\n               verify TSS, IRQ0, CPL3 module load, execution and return\n'
	@printf '  \033[1mmake verify-jash\033[0m\n               verify ANSI, commands, Deck switching and CPL3 selectors\n'
	@printf '  \033[1mmake verify-sensitivity\033[0m\n               flip every byte, boot in QEMU, classify the effect (~6 min)\n'
	@printf '  \033[1mmake proof\033[0m    run the full artifact, QEMU, KVM, PTY and browser gate\n'
	@printf '  \033[1mmake verify-bear\033[0m\n               optional cc-vs-Bear byte identity; set BEAR=/path/to/bear\n'
	@printf '  \033[1mmake run\033[0m      boot the record artifact interactively in QEMU\n'
	@printf '  \033[1mmake map\033[0m      print the per-symbol byte budget\n'
	@printf '  \033[1mmake size\033[0m     print artifact sizes\n'
	@printf '  \033[1mmake clean\033[0m    remove generated artifacts\n\n'

all: $(KERNEL) $(VMKERN) $(SHKERN) $(JASH) $(JPACK) ## build kernel and user-space artifacts

$(BASM): basm-nano/basm_nano.c
	$(MAKE) -C basm-nano

$(KERNEL): basmos.basm $(BASM)
	$(BASM) -f bin -o $@ $<

# Machine-contract variant: the same source assembled with -DBEMU_CONTRACT.
# bEMU-NANO enters directly in PM32 with paging; the guest contains only the product.
$(VMKERN): basmos.basm $(BASM)
	$(BASM) -f bin -DBEMU_CONTRACT -o $@ $<

$(SHKERN): basmos-sh.basm $(BASM)
	$(BASM) -f bin -o $@ $<

$(JASH): jash/jash.basm $(BASM)
	$(BASM) -f bin -o $@ $<

$(JPACK): jash/jash-pack.basm $(BASM)
	$(BASM) -f bin -o $@ $<

$(PROOFCTL): tools/proofctl.c
	$(CC) -O2 -Wall -Wextra -Werror -o $@ $<

$(BEMU_RUNNER): bemu/bemu_nano.c
	$(MAKE) -C bemu bemu-nano

shell: $(SHKERN) $(BEMU_RUNNER) ## CPL3 monitor: receive, execute and return from a module
	$(TIMEOUT) 15s bemu/bemu-nano $(SHKERN) --serial-hex $(SHELL_INPUT) --serial-expect 'Z>'

jash: verify-jash ## demonstrate and verify the complete JASH contract

jash-live: ## enter interactive JASH without build noise
	@$(MAKE) -s $(SHKERN) $(JASH) $(JPACK)
	@$(MAKE) -s -C bemu bemu-nano
	@bemu/bemu-nano $(SHKERN) --jash $(JASH) $(JPACK)

run: $(KERNEL) ## boot interactively in QEMU
	$(QEMU) -drive format=raw,if=floppy,readonly=on,file=$(KERNEL) -nic none -no-reboot -no-shutdown

# Boot the 512-byte record in the KVM runner without QEMU or firmware.
# --show renders the VGA page, which is ordinary guest RAM, in the terminal.
bemu: $(KERNEL) $(BEMU_RUNNER) ## boot the 512-byte sector in bEMU-NANO with display
	$(TIMEOUT) 30s bemu/bemu-nano $(KERNEL) --show

# Enter the 232-byte machine-contract guest directly in PM32 with paging.
bemu-contract: $(VMKERN) $(BEMU_RUNNER) ## run the 232-byte machine-contract variant
	$(TIMEOUT) 30s bemu/bemu-nano $(VMKERN) --contract --show

# Automated verification: QEMU, the independent site interpreter and bEMU-NANO/KVM.
verify: verify-qemu verify-domains verify-browser verify-bemu ## verify the record across execution engines

verify-ci: all $(PROOFCTL) verify-qemu verify-browser verify-shell-qemu verify-jash-qemu ## hosted-CI gate without KVM
	@sha256sum -c SHA256SUMS
	@$(PROOFCTL)
	@python3 verify_mutations.py

verify-nasm: all ## independently assemble all five artifacts with NASM
	@command -v nasm >/dev/null || { echo "nasm not found"; exit 1; }
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	nasm -f bin -o "$$tmp/basmos.bin" basmos.basm && \
	nasm -f bin -DBEMU_CONTRACT -o "$$tmp/basmos-vm.bin" basmos.basm && \
	nasm -f bin -o "$$tmp/basmos-sh.bin" basmos-sh.basm && \
	nasm -f bin -o "$$tmp/jash.bin" jash/jash.basm && \
	nasm -f bin -o "$$tmp/jash-pack.bin" jash/jash-pack.basm && \
	cmp "$$tmp/basmos.bin" $(KERNEL) && \
	cmp "$$tmp/basmos-vm.bin" $(VMKERN) && \
	cmp "$$tmp/basmos-sh.bin" $(SHKERN) && \
	cmp "$$tmp/jash.bin" $(JASH) && \
	cmp "$$tmp/jash-pack.bin" $(JPACK) && \
	echo "NASM: 5/5 artifacts are byte-identical"

# Sovereign-compiler diversity gate. It assembles the five guest artifacts with
# a Bear-built basm-nano and requires byte identity with the committed images.
# The gate never claims to have run: without BEAR set it reports SKIP.
verify-bear: all ## optional cc-vs-Bear byte identity (BEAR=/path/to/bear)
	@if [ -z "$(BEAR)" ]; then \
		echo "SKIP: BEAR is not set; no cc-vs-Bear byte-identity claim is made"; \
		exit 0; \
	fi
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	$(BEAR) $(BEARFLAGS) -o "$$tmp/basm-bear" basm-nano/basm_nano.c && \
	"$$tmp/basm-bear" -f bin -o "$$tmp/basmos.bin" basmos.basm && \
	"$$tmp/basm-bear" -f bin -DBEMU_CONTRACT -o "$$tmp/basmos-vm.bin" basmos.basm && \
	"$$tmp/basm-bear" -f bin -o "$$tmp/basmos-sh.bin" basmos-sh.basm && \
	"$$tmp/basm-bear" -f bin -o "$$tmp/jash.bin" jash/jash.basm && \
	"$$tmp/basm-bear" -f bin -o "$$tmp/jash-pack.bin" jash/jash-pack.basm && \
	cmp "$$tmp/basmos.bin" $(KERNEL) && \
	cmp "$$tmp/basmos-vm.bin" $(VMKERN) && \
	cmp "$$tmp/basmos-sh.bin" $(SHKERN) && \
	cmp "$$tmp/jash.bin" $(JASH) && \
	cmp "$$tmp/jash-pack.bin" $(JPACK) && \
	echo "BEAR: 5/5 artifacts are byte-identical between cc and $(BEAR)"

verify-qemu: $(KERNEL)
	python3 verify_qemu.py $(KERNEL)

verify-domains: $(KERNEL) $(VMKERN) $(BASM) $(BEMU_RUNNER) ## prove private DS windows and a cross-domain #GP
	python3 verify_domains.py $(KERNEL) $(VMKERN) $(BASM) bemu/bemu-nano

verify-browser: $(KERNEL)
	node website/test_interpreter.js

# KVM executor with no guest firmware. The same VMM supports a BIOS-style
# real-mode entry contract and direct PM32+paging entry supplied by the machine.
verify-bemu: $(KERNEL) $(VMKERN) $(BEMU_RUNNER)
	$(TIMEOUT) 15s bemu/bemu-nano $(KERNEL)
	$(TIMEOUT) 15s bemu/bemu-nano $(VMKERN) --contract

verify-shell: verify-shell-qemu verify-shell-bemu ## verify ring 3 in QEMU and KVM

verify-shell-qemu: $(SHKERN)
	python3 verify_shell_qemu.py $(SHKERN)

verify-shell-bemu: $(SHKERN) $(BEMU_RUNNER)
	$(TIMEOUT) 15s bemu/bemu-nano $(SHKERN) --serial-hex $(SHELL_INPUT) --serial-expect 'Z>'
	python3 verify_shell_faults.py bemu/bemu-nano $(SHKERN)

verify-jash: verify-jash-qemu verify-jash-bemu ## end-to-end JASH contract in QEMU and KVM

verify-jash-qemu: $(SHKERN) $(JASH) $(JPACK)
	python3 verify_jash_qemu.py $(SHKERN) $(JASH) $(JPACK)

verify-jash-bemu: $(SHKERN) $(JASH) $(JPACK) $(BEMU_RUNNER)
	python3 verify_jash.py bemu/bemu-nano $(SHKERN) $(JASH) $(JPACK)

verify-hardening: all $(PROOFCTL) ## command fuzzing and mutation gate
	python3 verify_jash_fuzz.py bemu/bemu-nano $(SHKERN) $(JASH) $(JPACK)
	python3 verify_mutations.py

# Byte-sensitivity map: every byte of the record sector is flipped once,
# booted in QEMU and classified by its observable effect on the contract.
# Slow (~6 min, 512 boots); writes evidence/byte-sensitivity.{json,md}.
verify-sensitivity: $(KERNEL) $(BASM) ## map every byte's observable effect
	python3 verify_sensitivity.py $(KERNEL)

manifest: all ## generate deterministic hashes and sizes
	@sh scripts/artifact_manifest.sh > ARTIFACTS.manifest
	@sha256sum $(KERNEL) $(VMKERN) $(SHKERN) $(JASH) $(JPACK) > SHA256SUMS
	@cat ARTIFACTS.manifest
	@cat SHA256SUMS

proof: all $(PROOFCTL) ## run the full reproducible gate
	@sha256sum -c SHA256SUMS
	@$(PROOFCTL)
	@if command -v nasm >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory verify-nasm; \
	else echo "SKIP: nasm not found; the independent assembler gate did not run"; fi
	@$(MAKE) verify
	@$(MAKE) verify-shell
	@$(MAKE) verify-jash
	@$(MAKE) verify-hardening
	@printf 'gates executed: SHA256SUMS, proofctl, QEMU, domains, browser, KVM, shell, JASH, fuzz, mutations'
	@command -v nasm >/dev/null 2>&1 && printf ' + NASM' || true
	@printf '\n'
	@if [ -n "$(BEAR)" ]; then \
		$(MAKE) --no-print-directory verify-bear; \
	else \
		echo 'gates skipped: cc-vs-Bear byte identity (run: make verify-bear BEAR=/path/to/bear)'; \
	fi

clean-room-proof: ## remove outputs, rebuild and run the full gate
	@$(MAKE) clean
	@$(MAKE) proof

# Per-symbol byte map: where each byte is spent in the sector.
map: basmos.basm $(BASM) ## record-artifact byte budget by symbol
	$(BASM) -f bin -o $(KERNEL) basmos.basm --map -

shell-map: basmos-sh.basm $(BASM) ## ring-3 sector byte budget
	$(BASM) -f bin -o $(SHKERN) basmos-sh.basm --map -

jash-map: jash/jash.basm $(BASM) ## 256-byte JASH nucleus byte budget
	$(BASM) -f bin -o $(JASH) jash/jash.basm --map -

size: $(KERNEL) $(VMKERN) $(SHKERN) $(JASH) $(JPACK) ## print artifact sizes
	@wc -c < $(KERNEL) | xargs -I{} echo "basmos.bin: {} total bytes = complete bootable record artifact"
	@wc -c < $(VMKERN) | xargs -I{} echo "basmos-vm.bin: {} total bytes = direct PM32+paging machine-contract guest"
	@wc -c < $(SHKERN) | xargs -I{} echo "basmos-sh.bin: {} total bytes = ring-0 kernel, CPL3 monitor and module boundary"
	@wc -c < $(JASH) | xargs -I{} echo "jash.bin: {} bytes = native CPL3 nucleus"
	@wc -c < $(JPACK) | xargs -I{} echo "jash-pack.bin: {} bytes = Decks, colors and Surfaces in NX data"

clean: ## remove generated outputs
	rm -f $(KERNEL) $(VMKERN) $(SHKERN) $(JASH) $(JPACK) $(PROOFCTL)
	$(MAKE) -C basm-nano clean
	$(MAKE) -C bemu clean
