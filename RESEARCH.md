<!-- SPDX-License-Identifier: BSD-3-Clause -->
<!-- Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com> -->

# BasmOS Record Research

**Survey date:** 2026-08-19<br>
**Status:** public prior-art survey, reproducible where sources remain available<br>
**License:** BSD-3-Clause for this report; cited projects retain their own licenses

## Claim Under Test

BasmOS claims the smallest publicly verifiable artifact found in this functional
category:

1. x86 IA-32 protected mode.
2. Paging actively enabled.
3. IDT and a hardware timer source.
4. At least two timer-preempted tasks.
5. Functional inter-task IPC.
6. A complete bare-metal artifact, counting every byte needed from BIOS entry to
   the demonstrated behavior.

Features beyond this minimum are allowed. A candidate that omits any required
feature is prior art for a subset, but is not eligible for the record. The
ranking metric is total artifact size; payload size is a secondary measurement.

## Result

No eligible public artifact of 512 bytes or less was found. BasmOS occupies one
512-byte boot sector and has a 378-byte payload.

> In the public survey completed on 2026-08-19, BasmOS is the smallest publicly
> verifiable IA-32 nanokernel found in the category requiring protected mode,
> active paging, IDT and timer, at least two timer-preempted tasks and functional
> IPC. The complete bare-metal artifact is 512 bytes; its payload is 378 bytes.

This wording reports the result and scope of a search. It is not certification
by an external record authority and cannot prove that unpublished or lost code
does not exist.

## BasmOS Evidence

`basmos.bin` contains:

- BIOS entry and real-mode to protected-mode transition;
- flat kernel code/stack segments plus bounded task-data and VGA segments;
- one 4 MiB PSE identity mapping with paging enabled;
- 35 IDT gates, PIC remapping and PIT programming;
- two CPL0 tasks switched by IRQ0: one CPU-bound (its loop never sleeps) and
  one sleeping, so the demonstrated schedule requires asynchronous preemption;
- an SPSC byte queue reached through interrupt gates;
- separate 256-byte DS windows for ordinary task data accesses, with an exact
  cross-domain `#GP13` negative probe;
- a heartbeat byte at 0x6FC incremented by every serviced tick;
- VGA output `3/6/9` demonstrating both tasks and data transfer;
- boot signature `55 aa`.

The two tasks share CPL0 and CR3. Their ordinary DS accesses are bounded, but
CPL0 code can reload descriptors; IPC is therefore logical inter-task
communication and the data windows are not a hostile process boundary.

## Candidate Matrix

| Project | Complete artifact | PM32 | Paging | Timer-preempted tasks | IPC | Eligible? |
|---|---:|---:|---:|---:|---:|---|
| **BasmOS** | **512 B; 378 B payload** | yes | yes, PSE | yes, 2 | SPSC queue | **yes; smallest found** |
| L4/x86 and complete IA-32 microkernels | many KiB or more | yes | yes | yes | yes | yes; functional supersets, larger |
| NanoOS 2.1 | 512 B | no | no | yes, up to 8 | blocking copy | no; lacks PM32 and paging |
| VirtualBox `bootsector-pae` | 512 B | yes | yes, PAE | no | no | no; lacks scheduler and IPC |
| pczero/osca | 1 KiB assembly area; reproduced image 18,060 B | yes | no | yes | none located | no; lacks paging and IPC |
| NanoBoot | 512 B stage 1 + 7,766 B stage 2 | yes | no | yes, 3 | no | no; lacks paging and IPC |
| `nanokernel-x86` | not reproducibly sized | yes | yes | yes | none located | no; lacks IPC |
| `localzet/nano-kernel` | GRUB-loaded, above 1 KiB | yes | yes | yes | planned | no; IPC absent in reviewed revision |
| bootOS | 512 B | no | no | no | synchronous services | no |
| OSle | 512 B | no | no | cooperative only | interrupt services | no |
| 512b-OS | 512 B | no | no | one application | no | no |

## Closest Partial Prior Art

### NanoOS 2.1

Viktor Peter Kovacs published NanoOS 2.1 for the 2004 FASM 512-byte OS
competition. It is a genuine 512-byte real-mode OS with:

- an INT 8 round-robin scheduler;
- up to eight tasks;
- blocking copy-based send/receive;
- console I/O and task lifecycle operations.

It proves that preemption and IPC fit in one sector, but it does not enter
protected mode or enable paging. It is therefore important prior art, but not an
eligible competitor in the BasmOS category.

Primary sources:

- https://board.flatassembler.net/topic.php?t=2164
- https://board.flatassembler.net/download.php?id=1692

Reproduced binary SHA-256:
`5fcc94b62c2b234e80e5bc20dc421702d3da9bed7ad45532ae64f576c81f6cf3`.

### VirtualBox PAE Boot Sector

VirtualBox ships a 512-byte validation boot sector that constructs PAE paging,
enters protected mode and enables paging. It has no functional IDT, scheduler,
tasks or IPC.

Source:

- https://github.com/VirtualBox/virtualbox/blob/master/src/VBox/ValidationKit/bootsectors/bootsector-pae.asm

### pczero

`calint/pczero` contains an IA-32 assembly nucleus for timer-preemptive
multitasking and C++ components. The reviewed assembly does not enable paging
and no IPC mechanism was located. The reproduced functional image was 18,060
bytes.

Sources:

- https://github.com/calint/pczero
- https://raw.githubusercontent.com/calint/pczero/main/src/osca.S

Reproduced image SHA-256:
`c8e8da1839fc8ed200aef50d55b8614559516f90f7b0ce3f452c4519d19fa98e`.

## Other 512-Byte Systems

The survey also reviewed bootOS, OSle, 512b-OS, ByteOS, Nixodria OS, TetrOS,
SectorLISP, SectorForth, SectorC, BlueScreenOS and historical FASM/OSDev contest
entries. These demonstrate substantial functionality in one sector but do not
combine all category requirements.

## Search Coverage

The adversarial search attempted to find a counterexample using:

- GitHub repository and code search;
- GitLab and Codeberg APIs;
- SourceHut;
- OSDev.org and archived OSDev competition pages;
- the FASM forum and 2004 competition attachments;
- Pouet and boot-sector demoscene references;
- Hacker News, Reddit and StackExchange search;
- Internet Archive/Wayback Machine;
- general web search in English and Portuguese.

Representative code queries combined `mov cr3`, `times 510`, `lidt`, `PIT`,
`task`, `iret`, `boot sector`, `preemptive`, `IPC`, `smallest kernel` and
`nanokernel`.

Some services returned rate limits, authentication requirements or anti-bot
responses. APIs, archives and direct attachments were used where possible.

## Limitations

- Private, removed, unindexed or lost artifacts cannot be excluded.
- Some historical candidates no longer build with current toolchains.
- Project terminology is inconsistent; eligibility was decided from behavior
  and source rather than names such as kernel, microkernel or nanokernel.
- Payload comparisons require an explicit boundary. The primary ranking uses
  complete functional artifact size.

## Additional References

- KeyKOS nanokernel architecture:
  https://web.archive.org/web/20180519235359id_/http://cap-lore.com/CapTheory/upenn/NanoKernel/NanoKernel.html
- L4 documentation: https://os.inf.tu-dresden.de/L4/l4doc.html
- Zephyr 1.5 nanokernel services:
  https://docs.zephyrproject.org/1.5.0/kernel/nanokernel/nanokernel.html
- NanoBoot: https://github.com/harrison001/NanoBoot
- bootOS: https://github.com/nanochess/bootOS
- OSle: https://github.com/shikaan/osle
- 512b-OS: https://github.com/notYuriy/512b-OS
