/* SPDX-License-Identifier: BSD-3-Clause
 * Exercise the real VMM exit handlers with synthetic KVM register snapshots.
 * No /dev/kvm access is needed: only open/ioctl/mmap at the KVM boundary are
 * substituted. Guard pages make out-of-RAM reads fail deterministically.
 */
#include <assert.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

static int fake_open(const char *path, int flags, ...);
static int fake_ioctl(int fd, unsigned long request, ...);
static void *fake_mmap(void *addr, size_t length, int prot, int flags,
                       int fd, off_t offset);

#define main bemu_main
#define open fake_open
#define ioctl fake_ioctl
#define mmap fake_mmap
#include "../bemu/bemu_nano.c"
#undef main
#undef open
#undef ioctl
#undef mmap

static uint8_t *test_ram;
static struct kvm_run *test_run;
static uint64_t test_rsp;
static int test_serial, test_valid, test_step;
static const uint32_t test_frame[] = {
    0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00
};

static int fake_open(const char *path, int flags, ...) {
    return open(!strcmp(path, "/dev/kvm") ? "/dev/null" : path, flags);
}

static void *fake_mmap(void *addr, size_t length, int prot, int flags,
                       int fd, off_t offset) {
    (void)addr; (void)fd; (void)offset;
    if (flags & MAP_ANONYMOUS) {
        size_t page = (size_t)sysconf(_SC_PAGESIZE);
        assert(length == RAM_SIZE);
        uint8_t *mapping = mmap(NULL, length + 2 * page, PROT_NONE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) die("test RAM mmap");
        test_ram = mapping + page;
        if (mprotect(test_ram, length, prot) < 0) die("test RAM mprotect");
        return test_ram;
    }
    test_run = mmap(NULL, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return test_run;
}

static int fake_ioctl(int fd, unsigned long request, ...) {
    (void)fd;
    va_list ap;
    va_start(ap, request);
    switch (request) {
    case KVM_GET_API_VERSION:
        va_end(ap);
        return KVM_API_VERSION;
    case KVM_CREATE_VM:
    case KVM_CREATE_VCPU:
        va_end(ap);
        return 100; /* Fake descriptors are used only by these substitutes. */
    case KVM_GET_VCPU_MMAP_SIZE:
        va_end(ap);
        return sizeof(struct kvm_run) + 1;
    case KVM_GET_SREGS:
        memset(va_arg(ap, struct kvm_sregs *), 0, sizeof(struct kvm_sregs));
        break;
    case KVM_GET_REGS: {
        struct kvm_regs *regs = va_arg(ap, struct kvm_regs *);
        memset(regs, 0, sizeof *regs);
        regs->rsp = test_rsp;
        regs->rip = GPA_IMAGE;
        break;
    }
    case KVM_RUN:
        if (test_serial) {
            uint32_t cs = test_step ? 0x2B : 0x1B;
            test_run->exit_reason = KVM_EXIT_IO;
            test_run->io.direction = KVM_EXIT_IO_OUT;
            test_run->io.port = COM1_RBR;
            test_run->io.size = 1;
            test_run->io.count = 1;
            test_run->io.data_offset = sizeof *test_run;
            ((uint8_t *)test_run)[sizeof *test_run] = test_step ? '>' : 'Z';
            if (test_valid)
                memcpy(test_ram + test_rsp + 4, &cs, sizeof cs);
            else if (test_rsp >= UINT64_MAX - 3) {
                /* A wrapped address can alias RAM instead of a guard page.
                 * Seed that alias so an invalid read produces a false PASS. */
                uint64_t alias = test_rsp + 4;
                memcpy(test_ram + alias, &cs, sizeof cs);
            }
        } else {
            test_run->exit_reason = KVM_EXIT_HLT;
            test_run->if_flag = 0;
            if (test_valid)
                memcpy(test_ram + test_rsp, test_frame, sizeof test_frame);
        }
        test_step++;
        break;
    case KVM_SET_USER_MEMORY_REGION:
    case KVM_GET_SUPPORTED_CPUID:
    case KVM_SET_CPUID2:
    case KVM_SET_SREGS:
    case KVM_SET_REGS:
        break;
    default:
        fprintf(stderr, "unexpected test ioctl: %#lx\n", request);
        abort();
    }
    va_end(ap);
    return 0;
}

static int check_case(const char *image, uint64_t rsp, int serial, int valid) {
    int output[2];
    if (pipe(output) < 0) die("test pipe");
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) die("test fork");
    if (pid == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core) < 0) die("test core limit");
        close(output[0]);
        if (dup2(output[1], STDOUT_FILENO) < 0 ||
            dup2(output[1], STDERR_FILENO) < 0) die("test dup2");
        close(output[1]);
        test_rsp = rsp;
        test_serial = serial;
        test_valid = valid;
        char *args[] = {"bemu-nano", (char *)image, "--contract",
                        "--max-exits", "2", "--serial-expect", "Z>", NULL};
        int rc = bemu_main(7, args);
        fflush(NULL);
        _exit(rc);
    }
    close(output[1]);
    char text[4096];
    size_t used = 0;
    ssize_t n;
    while ((n = read(output[0], text + used, sizeof text - 1 - used)) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            die("test read");
        }
        used += (size_t)n;
        assert(used < sizeof text - 1);
    }
    text[used] = 0;
    close(output[0]);
    int status;
    if (waitpid(pid, &status, 0) < 0) die("test waitpid");
    const char *expected = serial
        ? (valid ? "RESULT: PASS" : "gave up after 2 exits")
        : (valid ? "frame=11223344/55667788/99aabbcc/ddeeff00"
                 : "frame=00000000/00000000/00000000/00000000");
    if (WIFEXITED(status) && WEXITSTATUS(status) == (serial && valid ? 0 : 1)
        && strstr(text, expected)) return 1;
    fprintf(stderr, "FAIL: %s rsp=%#llx valid=%d wait_status=%#x\n%s",
            serial ? "serial" : "halt", (unsigned long long)rsp, valid,
            status, text);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s contract-image\n", argv[0]);
        return 2;
    }
    /* Expected validity is explicit, independent of the production checks. */
    const struct { uint64_t rsp; int serial, halt; } cases[] = {
        {0, 1, 1}, {1, 1, 1}, {0xFE4, 1, 1},
        {RAM_SIZE - 17, 1, 1}, {RAM_SIZE - 16, 1, 1},
        {RAM_SIZE - 15, 1, 0}, {RAM_SIZE - 9, 1, 0},
        {RAM_SIZE - 8, 1, 0}, {RAM_SIZE - 7, 0, 0},
        {RAM_SIZE - 4, 0, 0}, {RAM_SIZE - 1, 0, 0},
        {RAM_SIZE, 0, 0}, {RAM_SIZE + 1, 0, 0},
        {UINT32_MAX, 0, 0}, {1ULL << 32, 0, 0},
        {UINT64_MAX - 16, 0, 0}, {UINT64_MAX - 15, 0, 0},
        {UINT64_MAX - 8, 0, 0}, {UINT64_MAX - 7, 0, 0},
        {UINT64_MAX - 4, 0, 0}, {UINT64_MAX - 3, 0, 0},
        {UINT64_MAX, 0, 0},
    };
    size_t passed = 0, total = 2 * (sizeof cases / sizeof cases[0]);
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        passed += check_case(argv[1], cases[i].rsp, 1, cases[i].serial);
        passed += check_case(argv[1], cases[i].rsp, 0, cases[i].halt);
    }
    printf("bEMU stack bounds: %zu/%zu cases passed (no KVM required)\n", passed, total);
    return passed == total ? 0 : 1;
}
