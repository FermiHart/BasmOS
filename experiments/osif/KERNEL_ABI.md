# BasmOS OSIF kernel ABI 1

This experimental single-task profile boots a freestanding i386 C module in
CPL3. It is separate from `basmos-sh.basm` and the two-task IPC experiments.
The BIOS boot sector contains 509 meaningful bytes, 1 padding byte, and the
2-byte `55 AA` signature. The user program is a separate artifact.

## Boot transport and module layout

COM1 is initialized to 115200 baud, 8 data bits, no parity, one stop bit. The
kernel emits one ready byte, ASCII `B` (`0x42`). The host then sends:

1. A 32-bit unsigned little-endian image length.
2. Exactly that many bytes of a flat user image linked at address zero.

Accepted image lengths are 1 through `0x1F0000`, inclusive. Zero and greater
lengths enter the exception halt loop before any user payload byte is stored.
The bytes are loaded at physical address `0x100000`. At least the last 64 KiB
of the arena is left outside the loaded image for initial stack space. The
module's own linker/startup must lay out and initialize BSS and any heap and
prevent its static storage from colliding with the stack.

| Item | Value |
| --- | --- |
| CPU mode | 32-bit protected mode, CPL3, PSE paging |
| Module entry | `CS:EIP = 0x1B:0` |
| User arena | physical `0x100000..0x2FFFFF` |
| C pointer range | relative `0..0x1FFFFF` |
| CS | selector `0x1B`, base `0x100000`, limit `0x1FFFFF` |
| DS, ES, SS | selector `0x23`, same base and limit |
| FS, GS | null |
| Initial stack | `SS:ESP = 0x23:0x1FFFF0` |
| Initial flags | `0x202`: IF set, DF clear, IOPL zero |
| Kernel stack | TSS `SS0=0x10`, `ESP0=0x1000` |

Kernel initialization clears physical `0xA00..0x1FFF`, covering the TSS,
OSIF state, stack backing, and all page-directory entries. It subsequently
installs PDE zero for the first 4 MiB. The IDT's 129 entries are all explicitly
constructed. UART IER is explicitly cleared after DLAB is cleared. Fast A20
is enabled while keeping the port `0x92` reset bit clear.

## Calling convention

Execute `int 0x80` with the call number in **all of EAX**. The IDT entry is a
DPL3 interrupt gate. Returning calls preserve EBX, ESI, EDI, EBP, DS, ES, FS,
and GS. The nonreturning exit call sets BH to its receipt marker.
EAX, ECX, and EDX are caller-clobbered. EFLAGS are restored by `IRETD`.
The kernel never dereferences a pointer supplied by the module.

| EAX input | Operation | Other input | Result |
| ---: | --- | --- | --- |
| 0 | Query ABI | none | EAX=1; EDX=`0xF`; ECX=`0x200000` arena bytes |
| 1 | Polling console write | BL=byte | EAX=1 if written, or -11 if not ready |
| 2 | Polling console read | none | EAX=0..255 for a byte, or -11 if empty |
| 3 | Timer ticks | none | EAX=unsigned 32-bit tick count |
| 4 | Exit sole user task | BL=status | Store status at physical `0xB08`, marker 4 at `0xB09`, halt |
| Any other number | Unsupported operation | ignored | EAX=-38 |

Query EDX capability bits are:

| Bit | Value | Capability |
| ---: | ---: | --- |
| 0 | `0x1` | Nonblocking console read |
| 1 | `0x2` | Nonblocking console write |
| 2 | `0x4` | Timer ticks |
| 3 | `0x8` | Exit/halt |

The byte zero is a valid read result. It is never used as an empty-read marker.
The negative error values use signed 32-bit two's-complement representation.
Tick results are unsigned data even when the high bit is set; a caller must
not run the tick result through a generic signed syscall-error test.

Read and write each inspect the UART once. Blocking console functions belong
in user space and retry the corresponding operation, allowing IRQ0 to run
between calls. The boot loader alone performs a blocking serial read while
interrupts are disabled, before user execution begins.

## Timer, exit, and faults

The PIT channel-zero divisor is 11932 (`0x2E9C`), mode 3. With an input clock
of 1,193,182 Hz this is approximately 100.001676 ticks/second. The OSIF profile
uses 100 Hz as its nominal rate. The counter at physical `0xB00` wraps modulo
2^32. The interrupt handler acknowledges IRQ0, increments the counter through
the kernel SS selector, restores EAX, and returns to the interrupted code.

Exit halts the whole single-task profile. Faults also halt; automatic task
recovery is not provided. A hardware reset starts a fresh session. The symbolic
halt location is `exception_handler`; the loader and exit paths use that same
stable outcome. Use the generated map for its current physical address.

The exit handler stores a 32-bit receipt at physical `0xB08`: the low byte is
the requested status, the next byte is marker 4, and the upper two bytes are
unspecified. Initialization clears the whole receipt to zero. A runner must
require marker 4 before classifying a halted guest as a normal exit. Matching
EAX, EBX, or a zero status alone is insufficient because an unrelated fault can
leave the same register and status values behind.

## Scope

This ABI does not advertise process creation, scheduling, kernel IPC, files,
sockets, or a POSIX environment. A Jash backend must report unsupported
operations honestly and implement portable in-process facilities in user space.

The user code and data descriptors share one writable arena. There are no
separate process address spaces or write-versus-execute page permissions.
The configured privilege boundary uses segmentation over a user-accessible
PSE mapping; observing CPL3 in QEMU is distinct from qualifying every segment
limit behavior on hardware.

## Build

From the BasmOS repository root:

```sh
make -f Makefile.osif osif
```

All branch displacements are assembled from labels; the assembler checks the
supported relative branches. The loader's raw JA uses a label-derived rel8
expression and is independently exercised by the runtime boundary tests.
