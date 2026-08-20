/* proofctl.c - native artifact contract checker for BasmOS/JASH.
 * SPDX-License-Identifier: BSD-3-Clause */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t *bytes; size_t size; const char *path; } Image;

/* SHA-256, implemented from FIPS 180-4 so the native checker depends on no
 * external hash tool: the manifest gate is self-contained. */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t ror32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t padded = ((len + 9 + 63) / 64) * 64;
    uint8_t *buf = calloc(padded ? padded : 1, 1);
    if (!buf) { fprintf(stderr, "[FAIL] sha256 alloc\n"); exit(1); }
    memcpy(buf, data, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        buf[padded - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < padded; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[off + 4*i] << 24)
                 | ((uint32_t)buf[off + 4*i + 1] << 16)
                 | ((uint32_t)buf[off + 4*i + 2] << 8)
                 | (uint32_t)buf[off + 4*i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror32(w[i-15], 7) ^ ror32(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror32(w[i-2], 17) ^ ror32(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
            uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[4*i] = (uint8_t)(h[i] >> 24);
        out[4*i + 1] = (uint8_t)(h[i] >> 16);
        out[4*i + 2] = (uint8_t)(h[i] >> 8);
        out[4*i + 3] = (uint8_t)h[i];
    }
    free(buf);
}

static void hexdigest(const uint8_t digest[32], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2*i] = hex[digest[i] >> 4];
        out[2*i + 1] = hex[digest[i] & 15];
    }
    out[64] = 0;
}

static void fail(const char *what, const char *path) {
    fprintf(stderr, "[FAIL] %s: %s\n", what, path);
    exit(1);
}

static void load(Image *image, const char *path) {
    memset(image, 0, sizeof(*image));
    FILE *file = fopen(path, "rb");
    if (!file) fail("open", path);
    if (fseek(file, 0, SEEK_END) || (image->size = (size_t)ftell(file)) == 0
        || fseek(file, 0, SEEK_SET)) fail("size", path);
    image->bytes = malloc(image->size);
    if (!image->bytes || fread(image->bytes, 1, image->size, file) != image->size)
        fail("read", path);
    fclose(file);
    image->path = path;
}

static void check_manifest(const Image *image) {
    /* The committed ARTIFACTS.manifest line must bind this artifact's exact
     * byte count and SHA-256. A mutated binary, a stale manifest or a missing
     * line all fail here before any structural contract runs. */
    char prefix[160];
    snprintf(prefix, sizeof prefix, "artifact=%s bytes=%zu sha256=",
             image->path, image->size);
    FILE *file = fopen("ARTIFACTS.manifest", "rb");
    if (!file) fail("open ARTIFACTS.manifest", "ARTIFACTS.manifest");
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, file)) {
        size_t n = strlen(prefix);
        if (strncmp(line, prefix, n)) continue;
        found = 1;
        uint8_t digest[32];
        char hex[65];
        sha256(image->bytes, image->size, digest);
        hexdigest(digest, hex);
        char tail = line[n + 64];
        if (strncmp(line + n, hex, 64) || (tail != '\n' && tail != '\0'))
            fail("SHA-256 mismatch vs ARTIFACTS.manifest", image->path);
    }
    fclose(file);
    if (!found) fail("artifact missing from ARTIFACTS.manifest", image->path);
    printf("  [PASS] %-22s SHA-256 matches ARTIFACTS.manifest\n", image->path);
}

static void exact_size(const Image *image, size_t expected) {
    if (image->size != expected) fail("unexpected byte count", image->path);
    printf("  [PASS] %-22s %4zu bytes\n", image->path, image->size);
}

static void boot_signature(const Image *image) {
    if (image->size != 512 || image->bytes[510] != 0x55 || image->bytes[511] != 0xAA)
        fail("missing 55 aa", image->path);
}

static size_t last_magic(const Image *image, const char magic[4]) {
    size_t found = image->size;
    for (size_t i = 0; i + 4 <= image->size; i++)
        if (!memcmp(image->bytes + i, magic, 4)) found = i;
    if (found == image->size) fail("manifest magic missing", image->path);
    return found;
}

static int contains(const Image *image, const char *text) {
    size_t length = strlen(text);
    for (size_t i = 0; i + length <= image->size; i++)
        if (!memcmp(image->bytes + i, text, length)) return 1;
    return 0;
}

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void check_surfaces(const Image *pack) {
    size_t at = last_magic(pack, "SFC1");
    if (at + 5 > pack->size || pack->bytes[at + 4] != 6 || at + 5 + 6 * 6 > pack->size)
        fail("SFC1 shape", pack->path);
    const uint8_t expected[6][2] = {{1,3},{2,2},{3,3},{3,5},{4,1},{5,0}};
    const uint16_t extents[6] = {1,1,4096,256,1,0};
    for (size_t i = 0; i < 6; i++) {
        const uint8_t *entry = pack->bytes + at + 5 + i * 6;
        if (entry[0] != expected[i][0] || entry[1] != expected[i][1]
            || le16(entry + 2) != 0 || le16(entry + 4) != extents[i])
            fail("SFC1 entry", pack->path);
    }
    printf("  [PASS] SFC1 6 typed Surfaces, rights/base/extent exact\n");
}

static void check_decks(const Image *pack) {
    size_t at = last_magic(pack, "DCK1");
    const uint8_t expected[8] = {0,1,0,0x1F, 1,2,1,0x17};
    if (at + 13 > pack->size || pack->bytes[at + 4] != 2
        || memcmp(pack->bytes + at + 5, expected, 8))
        fail("DCK1 entries", pack->path);
    printf("  [PASS] DCK1 zero=0x1f lab=0x17 (code.read attenuated)\n");
}

static void check_evidence_vm(const Image *pack) {
    size_t at = last_magic(pack, "EVM1");
    if (at + 6 > pack->size || pack->bytes[at + 4] != 1
        || pack->bytes[at + 5] != 4)
        fail("EVM1 version/opcodes", pack->path);
    printf("  [PASS] EVM1 v1 total opcodes: EMIT/JACK/BYE/SELECT\n");
}

static void check_identity(const Image *pack) {
    const char *records[] = {
        "[RUNTIME] cpu.vendor ????????????",
        "[RUNTIME] privilege cpl=3 cs=002b",
        "[ARTIFACT] iopl=0 limits cs=000000ff ds=00000fff",
        "[ARTIFACT] kernel basmos-sh.bin 512B SEALED",
        "[PROOF] shell.sha256 ", "[PROOF] jash.sha256 ",
        "[PROOF] required BASM+QEMU+KVM+PTY+browser",
        "PRF1|POLICY|MAP|08|1F|ALLOW", "PRF1|POLICY|MAP|08|17|DENY",
        "PRF1|MODEL|MAP|08|1F|ALLOW", "PRF1|MODEL|MAP|08|17|DENY",
        "PRF1|MODEL|DECKDIFF|1F|17|08", "PRF1|EXTERNAL|OUT|3|0|GP13",
        "PRF1|ARTIFACT|JASH|253|3|FF",
    };
    for (size_t i = 0; i < 14; i++)
        if (!contains(pack, records[i])) fail("identity provenance", pack->path);
    printf("  [PASS] epistemic runtime/policy/model/artifact/proof records\n");
}

static int exact_word(const Image *pack, uint32_t address, const char *word) {
    size_t at, length = strlen(word);
    if (address < 0x200) return 0;
    at = address - 0x200;
    return at + length < pack->size
        && !memcmp(pack->bytes + at, word, length) && !pack->bytes[at + length];
}

static void check_capabilities(const Image *pack) {
    const size_t cells = 44, table = 104;
    if (pack->size < table + 28 * 8) fail("capability table shape", pack->path);
    for (size_t i = 1; i < 13; i++) {
        uint32_t output = le32(pack->bytes + cells + i * 4);
        if (output < 0x200 || output - 0x200 >= pack->size)
            fail("capability output range", pack->path);
    }
    for (size_t i = 0; i < 27; i++) {
        uint32_t name = le32(pack->bytes + table + i * 8);
        uint32_t target = le32(pack->bytes + table + i * 8 + 4);
        if (name < 0x200 || name - 0x200 >= pack->size)
            fail("word pointer range", pack->path);
        if (target < 0x200 + cells || target >= 0x200 + table
            || ((target - 0x200 - cells) & 3))
            fail("word capability range", pack->path);
    }
    if (le32(pack->bytes + table + 27 * 8)
        || le32(pack->bytes + table + 27 * 8 + 4))
        fail("word table terminator", pack->path);
    if (!exact_word(pack, le32(pack->bytes + table), "uname -a")
        || !exact_word(pack, le32(pack->bytes + table + 8), "probe")
        || !exact_word(pack, le32(pack->bytes + table + 16), "map")
        || !exact_word(pack, le32(pack->bytes + table + 24), "why map"))
        fail("epistemic word order", pack->path);
    if (le32(pack->bytes + table + 4) != 0x200 + 72
        || le32(pack->bytes + table + 12) != 0x200 + 72
        || le32(pack->bytes + table + 20) != 0x200 + cells
        || le32(pack->bytes + table + 28) != 0x200 + cells)
        fail("shared capability alias", pack->path);
    if (le32(pack->bytes + cells) != 3
        || le32(pack->bytes + 96) != 1 || le32(pack->bytes + 100) != 2)
        fail("Evidence VM opcode", pack->path);
    for (size_t at = 36; at <= 40; at += 4) {
        uint32_t output = le32(pack->bytes + at);
        if (output < 0x200 || output - 0x200 >= pack->size)
            fail("SELECT output range", pack->path);
    }
    printf("  [PASS] 27 words -> 15 immutable cells; total EMIT/JACK/BYE/SELECT VM\n");
}

int main(int argc, char **argv) {
    if (argc != 1) {
        fprintf(stderr, "usage: %s (run from BasmOS root)\n", argv[0]);
        return 2;
    }
    Image metal, direct, shell, jash, pack;
    load(&metal, "basmos.bin"); load(&direct, "basmos-vm.bin");
    load(&shell, "basmos-sh.bin"); load(&jash, "jash/jash.bin");
    load(&pack, "jash/jash-pack.bin");
    check_manifest(&metal); check_manifest(&direct); check_manifest(&shell);
    check_manifest(&jash); check_manifest(&pack);
    exact_size(&metal, 512); boot_signature(&metal);
    exact_size(&direct, 232);
    exact_size(&shell, 512); boot_signature(&shell);
    exact_size(&jash, 256);
    if (jash.bytes[253] || jash.bytes[254] || jash.bytes[255])
        fail("JASH 253+3 boundary", jash.path);
    if (pack.size > 3072) fail("J-Pack exceeds arena budget", pack.path);
    printf("  [PASS] %-22s %4zu bytes (<=3072)\n", pack.path, pack.size);
    check_surfaces(&pack);
    check_decks(&pack);
    check_evidence_vm(&pack);
    check_identity(&pack);
    check_capabilities(&pack);
    printf("RESULT: PASS - manifest SHA-256 and native contracts are consistent\n");
    free(metal.bytes); free(direct.bytes); free(shell.bytes);
    free(jash.bytes); free(pack.bytes);
    return 0;
}
