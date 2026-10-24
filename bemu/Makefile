# bEMU-NANO: standalone KVM runner for BasmOS guests.
#
# Supports the record boot path, the bEMU protected-mode contract, the
# shell/CPL3 serial protocol and JASH serial sessions. The runner provides a
# minimal UART and timer model without firmware, BIOS execution or QEMU.
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
# The /dev/kvm ABI comes from the official Linux UAPI headers installed by the
# system header package; those headers are not vendored in this repository.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Werror
BOUNDS_TEST = ../build/tests/bemu-stack-bounds

.PHONY: all test clean
all: bemu-nano

bemu-nano: bemu_nano.c
	$(CC) $(CFLAGS) -o $@ bemu_nano.c

$(BOUNDS_TEST): ../tests/bemu_stack_bounds.c bemu_nano.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $<

test: $(BOUNDS_TEST)
	$(BOUNDS_TEST) ../basmos-vm.bin

clean:
	rm -f bemu-nano $(BOUNDS_TEST)
