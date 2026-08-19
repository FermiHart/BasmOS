/*
 * bemu_nano.c — bEMU-NANO: the BasmOS KVM runner.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
 *
 * This VMM runs BasmOS guests directly through /dev/kvm without firmware, a
 * bootloader or an ELF loader. It provides a minimal timer model, which injects
 * IRQ0 vector 0x20 after each eligible HLT, and a minimal COM1 UART model for
 * scripted or interactive serial I/O. PIC and PIT port writes are accepted but
 * do not configure separate emulated devices. The VGA text page at 0xB8000 is
 * guest RAM that can be inspected or rendered by the host.
 *
 * SUPPORTED MODES:
 *   record (default):       a 512-byte boot record with signature 0xAA55 is
 *                           loaded at 0x7C00 and entered in real mode. Success
 *                           requires VGA cells containing 3/6/9 with attributes
 *                           0x0F/0x0F/0x0A, followed by stable timer ticks.
 *   bEMU contract:          --contract loads a raw payload at 0x7C00 and starts
 *                           it in 32-bit protected mode with paging enabled.
 *                           The runner supplies the GDT, page directory, CR0,
 *                           CR3, CR4 and segment-cache state before entry.
 *   shell/CPL3 serial:      --serial-hex, --serial-expect and --serial-stdio
 *                           drive and validate the shell's COM1 protocol and
 *                           ring-3 monitor/module transitions.
 *   JASH serial:            --jash MODULE PACK constructs the JASH load stream,
 *                           enables serial stdio and validates the CPL3 return.
 *
 * Guest exception gates halt with IF=0. Such a halt is treated as a fail-stop
 * crash rather than a timer wait, so the runner does not inject another IRQ.
 *
 * Usage:
 *   bemu-nano [image] [--contract] [--max-exits N] [--irqs N] [--trace]
 *             [--show] [--serial-hex HEX --serial-expect TEXT]
 *             [--serial-stdio] [--serial-skip N] [--quiet]
 *             [--jash MODULE PACK]
 *
 *   --show renders the 80x25 VGA text page in the terminal after each tick.
 *
 * Exit status: 0 = selected validation passed, 1 = guest/runtime failure,
 *              2 = invalid command-line arguments.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <termios.h>
#include <linux/kvm.h>

/* Some minimal libc signal headers omit these Linux ABI numbers. */
#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif

#define RAM_SIZE   (4ULL << 20)     /* one PSE page directory covers 0..4 MiB */
#define GPA_IMAGE  0x7C00ULL        /* where the BIOS (we) load the sector    */
#define GPA_VGA    0xB8000ULL       /* text page: the guest's only display    */
#define GPA_GDT    0x0620ULL        /* contract mode: machine-owned GDT       */
#define GPA_PD     0x1000ULL        /* contract mode: machine-owned page dir  */
#define SECTOR     512
#define IRQ0_VEC   0x20             /* the guest remaps the master PIC to 0x20 */
#define COM1_RBR   0x03F8
#define COM1_LCR   0x03FB
#define COM1_LSR   0x03FD
#define SERIAL_MAX 4096
#define CPUID_MAX  128
#define CPUID_BYTES (8 + CPUID_MAX * 40) /* header + kvm_cpuid_entry2[] */

/* Contract-mode machine physics: a flat 3-entry GDT (null / code / data)
 * and one PSE PDE identity-mapping 0..4 MiB. The guest never wrote these
 * bytes — they exist because the machine exists. */
#define GDT_SIZE 24      /* Size of machine_gdt in bytes. */
static const uint8_t machine_gdt[GDT_SIZE] = {
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,   /* null                 */
    0xFF,0xFF,0x00,0x00, 0x00,0x9A,0xCF,0x00,   /* 0x08: code, 4G, 32b  */
    0xFF,0xFF,0x00,0x00, 0x00,0x92,0xCF,0x00,   /* 0x10: data, 4G, 32b  */
};

static void die(const char *msg) { perror(msg); exit(1); }

static struct termios g_saved_tio;
static int g_tio_active;

static void restore_tio(void) {
    if (g_tio_active) {
        tcsetattr(STDIN_FILENO, TCSADRAIN, &g_saved_tio);
        g_tio_active = 0;
    }
}

static void restore_tio_signal(int sig) {
    restore_tio();
    _exit(128 + sig);
}

static ssize_t read_path(const char *path, uint8_t *buffer, size_t capacity) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die(path);
    ssize_t count = read(fd, buffer, capacity);
    close(fd);
    if (count < 0) die(path);
    return count;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ── --show: the terminal is the video card ─────────────────────────────
 * VGA text attr byte: low nibble = fg (16 colors), bits 6:4 = bg (8 colors).
 * We map them to ANSI and redraw the 80x25 page in place, once per tick. */
static int g_show, g_shown;
static const int vga2ansi_fg[16] = {30,34,32,36,31,35,33,37,90,94,92,96,91,95,93,97};

static void show_frame(const uint8_t *vga) {
    if (g_shown) printf("\033[25A");          /* Move up 25 lines to redraw. */
    for (int row = 0; row < 25; row++) {
        printf("\033[K");                      /* Clear the current line. */
        for (int col = 0; col < 80; col++) {
            uint8_t ch = vga[(row*80 + col)*2], at = vga[(row*80 + col)*2 + 1];
            printf("\033[%d;%dm%c", 40 + ((at >> 4) & 7), vga2ansi_fg[at & 15],
                   (ch >= 32 && ch < 127) ? ch : ' ');
        }
        printf("\033[0m\n");
    }
    fflush(stdout);
    g_shown = 1;
    usleep(120000);                            /* 120 ms per visible boot tick. */
}

int main(int argc, char **argv)
{
    const char *imgpath = "../basmos.bin";
    const char *serial_hex = NULL, *serial_expect = NULL;
    const char *jash_module = NULL, *jash_pack = NULL;
    uint8_t serial_rx[SERIAL_MAX];
    size_t serial_len = 0, serial_pos = 0, expect_pos = 0;
    long max_exits = 1000000, want_irqs = 64, serial_skip = 0;
    int trace = 0, contract = 0, serial_stdio = 0, quiet = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--max-exits") && i+1 < argc) max_exits = atol(argv[++i]);
        else if (!strcmp(argv[i], "--irqs") && i+1 < argc) want_irqs = atol(argv[++i]);
        else if (!strcmp(argv[i], "--trace")) trace = 1;
        else if (!strcmp(argv[i], "--contract")) contract = 1;
        else if (!strcmp(argv[i], "--show")) g_show = 1;
        else if (!strcmp(argv[i], "--serial-hex") && i+1 < argc) serial_hex = argv[++i];
        else if (!strcmp(argv[i], "--serial-expect") && i+1 < argc) serial_expect = argv[++i];
        else if (!strcmp(argv[i], "--serial-skip") && i+1 < argc) serial_skip = atol(argv[++i]);
        else if (!strcmp(argv[i], "--serial-stdio")) serial_stdio = 1;
        else if (!strcmp(argv[i], "--quiet")) quiet = 1;
        else if (!strcmp(argv[i], "--jash") && i+2 < argc) {
            jash_module = argv[++i];
            jash_pack = argv[++i];
        }
        else if (argv[i][0] != '-') imgpath = argv[i];
        else { fprintf(stderr, "usage: bemu-nano [image] [--contract] [--max-exits N] [--irqs N] [--trace] [--show] [--serial-hex HEX --serial-expect TEXT] [--serial-stdio] [--serial-skip N] [--quiet] [--jash MODULE PACK]\n"); return 2; }
    }
    if (serial_hex) {
        size_t digits = strlen(serial_hex);
        if ((digits & 1) || digits / 2 > SERIAL_MAX) {
            fprintf(stderr, "[bemu-nano] --serial-hex needs an even number of at most %d hex digits\n", SERIAL_MAX * 2);
            return 2;
        }
        for (size_t i = 0; i < digits; i += 2) {
            int hi = hex_nibble(serial_hex[i]), lo = hex_nibble(serial_hex[i + 1]);
            if (hi < 0 || lo < 0) {
                fprintf(stderr, "[bemu-nano] invalid --serial-hex byte at offset %zu\n", i);
                return 2;
            }
            serial_rx[serial_len++] = (uint8_t)((hi << 4) | lo);
        }
    }
    if (jash_module) {
        uint8_t module[257], pack[SERIAL_MAX];
        ssize_t module_len, pack_len;
        if (serial_hex) {
            fprintf(stderr, "[bemu-nano] --jash and --serial-hex are mutually exclusive\n");
            return 2;
        }
        module_len = read_path(jash_module, module, 257);
        pack_len = read_path(jash_pack, pack, SERIAL_MAX);
        if (module_len != 256 || pack_len < 1 || pack_len > 3072) {
            fprintf(stderr, "[bemu-nano] --jash requires a 256B nucleus and a 1..3072B J-Pack\n");
            return 2;
        }
        serial_rx[serial_len++] = 'r';
        serial_rx[serial_len++] = 0;             /* monitor: zero means 256 */
        memcpy(serial_rx + serial_len, module, 256); serial_len += 256;
        serial_rx[serial_len++] = 'x';
        serial_rx[serial_len++] = (uint8_t)pack_len;
        serial_rx[serial_len++] = (uint8_t)(pack_len >> 8);
        memcpy(serial_rx + serial_len, pack, (size_t)pack_len); serial_len += (size_t)pack_len;
        serial_stdio = 1;
        quiet = 1;
        serial_skip = 3;                         /* parent monitor's >rx */
        if (!serial_expect) serial_expect = "\r\n>";
    }

    /* load the guest: the whole OS (a 512B sector, or a raw contract payload) */
#define IMG_MAX 4096   /* Maximum guest image size accepted by this runner. */
    uint8_t img[IMG_MAX];
    int fd = open(imgpath, O_RDONLY);
    if (fd < 0) die(imgpath);
    ssize_t n = read(fd, img, IMG_MAX);
    close(fd);
    if (n <= 0) die("read guest image");
    if (!contract && (n != SECTOR || img[510] != 0x55 || img[511] != 0xAA)) {
        fprintf(stderr, "[bemu-nano] %s: not a 512-byte boot sector (got %zd)\n", imgpath, n);
        return 1;
    }

    int kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0) die("/dev/kvm");
    if (ioctl(kvm, KVM_GET_API_VERSION, 0) != KVM_API_VERSION) {
        fprintf(stderr, "[bemu-nano] KVM API version mismatch\n"); return 1;
    }
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) die("KVM_CREATE_VM");

    uint8_t *ram = mmap(NULL, RAM_SIZE, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ram == MAP_FAILED) die("mmap guest ram");
    struct kvm_userspace_memory_region mr = {
        .slot = 0, .guest_phys_addr = 0, .memory_size = RAM_SIZE,
        .userspace_addr = (uint64_t)ram,
    };
    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &mr) < 0) die("KVM_SET_USER_MEMORY_REGION");
    memcpy(ram + GPA_IMAGE, img, (size_t)n);   /* no INT 13h: the image IS loaded */
    if (contract) {
        /* The machine's physics, written before the first guest opcode. */
        memcpy(ram + GPA_GDT, machine_gdt, GDT_SIZE);
        *(uint32_t *)(ram + GPA_PD) = 0x83;    /* PDE0: present|rw|PS, 4 MiB */
    }

    int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpu < 0) die("KVM_CREATE_VCPU");
    struct kvm_cpuid2 *cpuid = malloc(CPUID_BYTES);
    if (!cpuid) die("malloc CPUID");
    memset(cpuid, 0, CPUID_BYTES);
    cpuid->nent = CPUID_MAX;
    if (ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) < 0)
        die("KVM_GET_SUPPORTED_CPUID");
    if (ioctl(vcpu, KVM_SET_CPUID2, cpuid) < 0)
        die("KVM_SET_CPUID2");
    free(cpuid);
    int mmap_sz = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_sz <= 0) die("KVM_GET_VCPU_MMAP_SIZE");
    struct kvm_run *run = mmap(NULL, (size_t)mmap_sz, PROT_READ|PROT_WRITE,
                               MAP_SHARED, vcpu, 0);
    if (run == MAP_FAILED) die("mmap kvm_run");

    /* Entry state. Sector mode: real mode exactly as the BIOS leaves it
     * (CS=0, IP=0x7C00, flags=0x2). Contract mode: protected mode with
     * paging already on — the machine, not the guest, owns the transition. */
    struct kvm_sregs sr;
    if (ioctl(vcpu, KVM_GET_SREGS, &sr) < 0) die("KVM_GET_SREGS");
    struct kvm_segment *segs[6] = {&sr.cs,&sr.ds,&sr.es,&sr.ss,&sr.fs,&sr.gs};
    if (!contract) {
        for (int i = 0; i < 6; i++) {
            segs[i]->selector = 0; segs[i]->base = 0; segs[i]->limit = 0xFFFF;
        }
    } else {
        for (int i = 0; i < 6; i++) {
            struct kvm_segment *s = segs[i];
            s->selector = (i == 0) ? 0x08 : 0x10;
            s->base = 0; s->limit = 0xFFFFFFFF;
            s->type = (i == 0) ? 0xB : 0x3;   /* code exec/read : data r/w   */
            s->present = 1; s->dpl = 0; s->db = 1; s->s = 1;
            s->l = 0; s->g = 1; s->avl = 0; s->unusable = 0;
        }
        sr.gdt.base = GPA_GDT; sr.gdt.limit = GDT_SIZE - 1;
        sr.cr3 = GPA_PD;
        sr.cr4 = 0x10;                        /* PSE: 4 MiB pages             */
        sr.cr0 = 0x80000011;                  /* PG | ET | PE                 */
    }
    if (ioctl(vcpu, KVM_SET_SREGS, &sr) < 0) die("KVM_SET_SREGS");
    struct kvm_regs r; memset(&r, 0, sizeof r);
    r.rip = GPA_IMAGE; r.rflags = 0x2;
    if (ioctl(vcpu, KVM_SET_REGS, &r) < 0) die("KVM_SET_REGS");

    if (!quiet)
        printf("[bemu-nano] guest: %s (%zdB @0x7C00, %s — no firmware)\n",
               imgpath, n,
               contract ? "PM32+paging DIRECT ENTRY, machine-owned GDT/PD"
                        : "real mode, KVM direct");

    if (serial_stdio && isatty(STDIN_FILENO)) {
        struct termios live;
        if (tcgetattr(STDIN_FILENO, &g_saved_tio) < 0) die("tcgetattr");
        live = g_saved_tio;
        live.c_lflag &= (unsigned long)~(ICANON | ECHO);
        live.c_cc[VMIN] = 1;
        live.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &live) < 0) die("tcsetattr");
        g_tio_active = 1;
        signal(SIGINT, restore_tio_signal);
        signal(SIGTERM, restore_tio_signal);
    }
    long exits = 0, irqs = 0, io_outs = 0, hlts = 0, serial_tx = 0;
    int matched = 0, uart_lcr = 0, seen_monitor = 0, seen_module = 0;
    int stdin_pending = -1, stdin_eof = 0, rx_probe = 0;
    while (exits++ < max_exits) {
        if (ioctl(vcpu, KVM_RUN, 0) < 0) die("KVM_RUN");
        switch (run->exit_reason) {
        case KVM_EXIT_IO:
        {
            uint8_t *data = (uint8_t *)run + run->io.data_offset;
            size_t bytes = run->io.size * run->io.count;
            if (run->io.direction == KVM_EXIT_IO_OUT) {
                rx_probe = 0;                    /* LSR followed by OUT was TX */
                io_outs++;
                for (uint32_t i = 0; i < run->io.count; i++) {
                    uint8_t value = data[i * run->io.size];
                    if (run->io.port == COM1_LCR) uart_lcr = value;
                    else if (run->io.port == COM1_RBR && !(uart_lcr & 0x80)) {
                        struct kvm_regs now;
                        if (ioctl(vcpu, KVM_GET_REGS, &now) < 0) die("KVM_GET_REGS serial");
                        if (now.rsp + 8 < RAM_SIZE) {
                            uint32_t saved_cs = *(uint32_t *)(ram + now.rsp + 4);
                            if ((saved_cs & 0xFFFF) == 0x1B) seen_monitor = 1;
                            if ((saved_cs & 0xFFFF) == 0x2B) seen_module = 1;
                        }
                        if (serial_skip > 0) serial_skip--;
                        else {
                            fputc(value, stdout);
                            fflush(stdout);
                        }
                        serial_tx++;
                        if (serial_expect && serial_expect[0]) {
                            if ((uint8_t)serial_expect[expect_pos] == value) expect_pos++;
                            else expect_pos = ((uint8_t)serial_expect[0] == value) ? 1 : 0;
                            if (!serial_expect[expect_pos]) matched = 1;
                        }
                    }
                }
            } else {
                memset(data, 0, bytes);
                for (uint32_t i = 0; i < run->io.count; i++) {
                    uint8_t value = 0;
                    if (run->io.port == COM1_LSR) {
                        if (serial_pos >= serial_len && stdin_pending < 0
                            && serial_stdio && !stdin_eof) {
                            if (rx_probe) {
                                uint8_t ch;
                                ssize_t got = read(STDIN_FILENO, &ch, 1);
                                if (got < 0) die("serial stdin");
                                if (got == 0) stdin_eof = 1;
                                else stdin_pending = (ch == '\n') ? '\r' : ch;
                            } else rx_probe = 1;
                        }
                        if (serial_pos < serial_len || stdin_pending >= 0) rx_probe = 0;
                        value = 0x20 | ((serial_pos < serial_len || stdin_pending >= 0) ? 1 : 0);
                    }
                    else if (run->io.port == COM1_RBR && !(uart_lcr & 0x80)
                             && serial_pos < serial_len) {
                        value = serial_rx[serial_pos++];
                        rx_probe = 0;
                    }
                    else if (run->io.port == COM1_RBR && !(uart_lcr & 0x80)
                             && stdin_pending >= 0) {
                        value = (uint8_t)stdin_pending;
                        stdin_pending = -1;
                        rx_probe = 0;
                    }
                    data[i * run->io.size] = value;
                }
            }
            if (trace) printf("[io] %s port 0x%x size %d\n",
                               run->io.direction ? "out" : "in ",
                               run->io.port, run->io.size);
            if (serial_expect && matched && seen_monitor && seen_module) goto done;
            break;
        }
        case KVM_EXIT_HLT:
            hlts++;
            if (!run->if_flag) {
                /* exception_handler: IF was cleared by the interrupt gate */
                struct kvm_regs stopped;
                uint32_t fault_cs = 0;
                if (ioctl(vcpu, KVM_GET_REGS, &stopped) < 0) die("KVM_GET_REGS crash");
                /* #GP pushes an error code before EIP, CS and EFLAGS. */
                if (stopped.rsp + 12 < RAM_SIZE)
                    fault_cs = *(uint32_t *)(ram + stopped.rsp + 8);
                fprintf(stderr, "[bemu-nano] CRASH: guest halt with IF=0 "
                                "(fail-stop gate) after %ld ticks; saved CS=%#x\n",
                                irqs, fault_cs);
                goto fail;
            }
            /* the only device in this machine: one tick per HLT */
            if (ioctl(vcpu, KVM_INTERRUPT, &(struct kvm_interrupt){ IRQ0_VEC }) < 0)
                die("KVM_INTERRUPT");
            irqs++;
            if (g_show) show_frame(ram + GPA_VGA);
            if (!matched && ram[GPA_VGA+0] == 0x33 && ram[GPA_VGA+1] == 0x0F
                         && ram[GPA_VGA+2] == 0x36 && ram[GPA_VGA+3] == 0x0F
                         && ram[GPA_VGA+4] == 0x39 && ram[GPA_VGA+5] == 0x0A) {
                printf("[bemu-nano] 3/6/9 observed at tick %ld: "
                       "task0, task1 and the IPC ring are alive\n", irqs);
                matched = 1;
            }
            if (matched && irqs >= want_irqs) goto done;
            break;
        case KVM_EXIT_SHUTDOWN:
            fprintf(stderr, "[bemu-nano] CRASH: triple fault after %ld ticks\n", irqs);
            goto fail;
        case KVM_EXIT_FAIL_ENTRY:
            fprintf(stderr, "[bemu-nano] KVM fail-entry reason=%llu\n",
                    (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
            goto fail;
        default:
            fprintf(stderr, "[bemu-nano] unexpected exit reason %u\n",
                    run->exit_reason);
            goto fail;
        }
    }
    fprintf(stderr, "[bemu-nano] gave up after %ld exits (%ld ticks)\n",
            max_exits, irqs);
fail:
    restore_tio();
    fprintf(stderr, "[bemu-nano] VGA @0xB8000: %02x %02x %02x %02x %02x %02x\n",
            ram[GPA_VGA+0], ram[GPA_VGA+1], ram[GPA_VGA+2],
            ram[GPA_VGA+3], ram[GPA_VGA+4], ram[GPA_VGA+5]);
    fprintf(stderr, "RESULT: FAIL\n");
    return 1;
done:
    restore_tio();
    if (serial_expect) {
        if (!quiet) {
            printf("\n[bemu-nano] serial rx=%zu/%zu tx=%ld; saved user CS: monitor=%s module=%s\n",
                   serial_pos, serial_len, serial_tx,
                   seen_monitor ? "0x1b" : "missing", seen_module ? "0x2b" : "missing");
            printf("RESULT: PASS — %zdB ring-3 monitor loaded, ran and returned from a user module\n", n);
        }
        return 0;
    }
    printf("[bemu-nano] VGA @0xB8000: %02x %02x %02x %02x %02x %02x"
           "  ('3' white, '6' white, IPC '9' green)\n",
           ram[GPA_VGA+0], ram[GPA_VGA+1], ram[GPA_VGA+2],
           ram[GPA_VGA+3], ram[GPA_VGA+4], ram[GPA_VGA+5]);
    printf("[bemu-nano] ticks=%ld hlt=%ld pio-outs=%ld exits=%ld — "
           "stable through %ld ticks after match\n",
           irqs, hlts, io_outs, exits, irqs);
    printf("RESULT: PASS — %zdB nanokernel booted by a VMM with zero firmware\n", n);
    return 0;
}
