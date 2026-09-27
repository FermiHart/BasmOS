/*
 * basm_nano.c — BASM-NANO: a purpose-built assembler for BasmOS.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026, F E R M I ∞ H A R T <contact@fermihart.com>
 *
 * This is not a general-purpose assembler. It assembles the five repository
 * artifacts basmos.bin, basmos-vm.bin, basmos-sh.bin, jash.bin, and
 * jash-pack.bin byte for byte. Its instruction set is limited to what those
 * artifacts use:
 *
 *   directives: BITS 16/32 · org · section .text · times N db v · db/dw/dd
 *               db also accepts literal strings without escapes
 *   preprocessor: %ifdef/%ifndef/%else/%endif · -DNAME on the command line
 *   expressions: hex/decimal · labels (including local .x) · $ · $$ · + - *
 *                · parentheses
 *   mnemonics:  cli cld sti hlt nop ret lodsb lodsw xor mov lgdt lidt ltr
 *               inc dec jmp call push pop pushad popad iretd or in out int
 *               test jz je jnz jne jb loop jecxz cmp
 *   memory:     [reg] · [reg±disp] · [abs] · accumulator moffs A0-A3
 *   branches:   rel8 only, with range checking
 *
 *   output:     flat binary · --map FILE|- (byte budget by symbol)
 *
 * Usage: basm-nano -f bin -o out.bin [-DBEMU_CONTRACT] [--map -] in.basm
 */
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#define SYM_MAX   256
#define OUT_MAX   65536
#undef NAME_MAX
#define NAME_MAX  128
#define IF_DEPTH  16
#undef LINE_MAX
#define LINE_MAX  1024   /* Use the named constant rather than sizeof on a local
                          * array. Some constrained compilers report the pointer
                          * size even though the array storage is correct. */
static uint8_t  g_out[OUT_MAX];
static long     g_off;              /* current offset in the image        */
static long     g_org;              /* org (absolute base for labels)     */
static int      g_bits = 32;        /* current mode: 16 or 32             */
static int      g_pass;             /* 1 = measure, 2 = final emission    */
static int      g_line;
static const char *g_file = "<command-line>";
#define SOURCE_MAX (1024 * 1024)
#define EXPR_DEPTH 64
#define SYM_SLOTS 512 /* Fixed upper bound, <= 50% full; no heap allocation. */
static int g_expr_depth, g_unresolved, g_symbolic;
static int g_org_seen;


#if defined(__GNUC__) || defined(__clang__)
#define BASM_COLD __attribute__((cold))
#define BASM_NOINLINE __attribute__((noinline))
#else
#define BASM_COLD
#define BASM_NOINLINE
#endif

static BASM_COLD void die(const char *msg) {
    fprintf(stderr, "basm-nano: %s:%d: %s\n", g_file, g_line, msg);
    exit(1);
}
/* Checked host arithmetic: malformed input must not invoke C signed UB. */
static long add_checked(long a, long b) {
    if ((b > 0 && a > LONG_MAX - b) || (b < 0 && a < LONG_MIN - b))
        die("expression addition overflow");
    return a + b;
}
static long sub_checked(long a, long b) {
    if ((b > 0 && a < LONG_MIN + b) || (b < 0 && a > LONG_MAX + b))
        die("expression subtraction overflow");
    return a - b;
}
static long mul_checked(long a, long b) {
    if ((a > 0 && ((b > 0 && a > LONG_MAX / b) || (b < 0 && b < LONG_MIN / a))) ||
        (a < 0 && ((b > 0 && a < LONG_MIN / b) || (b < 0 && a < LONG_MAX / b))))
        die("expression multiplication overflow");
    return a * b;
}
static int name_start(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.';
}
static int name_part(unsigned char c) { return name_start(c) || (c >= '0' && c <= '9'); }
static size_t check_name(const char *name) {
    if (!name_start((unsigned char)name[0]))
        die("invalid or overlong identifier");
    size_t n = 1;
    for (; name[n]; n++) {
        if (n >= NAME_MAX - 1) die("invalid or overlong identifier");
        if (!name_part((unsigned char)name[n])) die("invalid identifier character");
    }
    return n;
}
/* ── symbols: bounded hash index, source-order vector retained for maps ── */
typedef struct { char name[NAME_MAX]; long off; int is_local, line; } Sym;
static Sym g_syms[SYM_MAX];
static unsigned short g_sym_slots[SYM_SLOTS]; /* index + 1; zero means empty */
static int g_nsyms;
static char g_last_global[NAME_MAX];
static unsigned sym_slot(const char *name) {
    uint32_t hash = UINT32_C(2166136261);
    for (const unsigned char *p = (const unsigned char *)name; *p; p++)
        hash = (hash ^ *p) * UINT32_C(16777619);
    unsigned slot = hash & (SYM_SLOTS - 1);
    for (unsigned probes = 0; probes < SYM_SLOTS; probes++) {
        if (!g_sym_slots[slot] || !strcmp(g_syms[g_sym_slots[slot]-1].name, name))
            return slot;
        slot = (slot + 1) & (SYM_SLOTS - 1);
    }
    die("symbol index exhausted");
    return 0;
}
static const char *qualify(const char *name, char *out) {
    size_t n = check_name(name);
    /* Global references already have their canonical key: do not copy them. */
    if (name[0] != '.') return name;
    size_t prefix = strlen(g_last_global);
    if (!prefix) die("local label has no preceding global label");
    if (prefix + n >= NAME_MAX) die("qualified identifier is too long");
    memcpy(out, g_last_global, prefix);
    memcpy(out + prefix, name, n + 1);
    return out;
}
static void sym_define(const char *name, long off) {
    char storage[NAME_MAX]; const char *q = qualify(name, storage);
    if (name[0] != '.') memcpy(g_last_global, name, strlen(name) + 1);
    unsigned slot = sym_slot(q);
    int index = (int)g_sym_slots[slot] - 1;
    if (g_pass == 2) {
        if (index < 0 || g_syms[index].off != off || g_syms[index].line != g_line)
            die("label changed between passes");
        return;
    }
    if (index >= 0) die("duplicate label");
    if (g_nsyms >= SYM_MAX) die("too many symbols");
    Sym *sym = &g_syms[g_nsyms];
    memcpy(sym->name, q, strlen(q) + 1);
    sym->off = off;
    sym->is_local = name[0] == '.';
    sym->line = g_line;
    g_sym_slots[slot] = (unsigned short)++g_nsyms;
}
static long sym_value(const char *name) {
    char storage[NAME_MAX]; const char *q = qualify(name, storage);
    unsigned slot = sym_slot(q);
    g_symbolic = 1;
    if (g_sym_slots[slot]) return add_checked(g_org, g_syms[g_sym_slots[slot]-1].off);
    if (g_pass == 2) {
        char b[NAME_MAX+32]; snprintf(b, sizeof(b), "undefined label: %s", q); die(b);
    }
    g_unresolved = 1;
    return 0;
}
/* ── emission ─────────────────────────────────────────────────────────── */
static void reserve_bytes(long count) {
    if (count < 0 || g_off < 0 || g_off > OUT_MAX || count > OUT_MAX - g_off)
        die("image exceeds OUT_MAX");
}
static void emit(uint8_t b) {
    reserve_bytes(1); /* Both passes are bounded, not just final emission. */
    if (g_pass == 2) g_out[g_off] = b;
    g_off++;
}
static void emit16(long v) {
    reserve_bytes(2);
    if (g_pass == 2) {
        g_out[g_off] = (uint8_t)v;
        g_out[g_off + 1] = (uint8_t)((uint64_t)v >> 8);
    }
    g_off += 2;
}
static void emit32(long v) {
    reserve_bytes(4);
    if (g_pass == 2) {
        uint32_t bits = (uint32_t)v;
        g_out[g_off] = (uint8_t)bits;
        g_out[g_off + 1] = (uint8_t)(bits >> 8);
        g_out[g_off + 2] = (uint8_t)(bits >> 16);
        g_out[g_off + 3] = (uint8_t)(bits >> 24);
    }
    g_off += 4;
}

/* ── expressions: primary = number | label | $ | $$ | (e) | -e; *; + - ─ */
static long p_expr(const char **p);
static const char *skipsp(const char *p) { while (*p==' '||*p=='\t') p++; return p; }
/* Unsigned spelling of a nonnegative long; unary signs remain expressions. */
static inline long number(const char **pp) {
    const char *p = *pp;
    unsigned long value = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        const char *start = p;
        for (;;) {
            unsigned digit = (unsigned char)*p - (unsigned)'0';
            if (digit > 9) digit = ((unsigned char)*p | 32u) - (unsigned)'a' + 10u;
            if (digit >= 16) break;
            if (value > (unsigned long)LONG_MAX / 16 ||
                (value == (unsigned long)LONG_MAX / 16 && digit > (unsigned)(LONG_MAX % 16)))
                die("numeric literal overflow");
            value = value * 16 + digit;
            p++;
        }
        if (p == start) die("invalid numeric literal");
    } else {
        do {
            unsigned digit = (unsigned char)*p - (unsigned)'0';
            if (value > (unsigned long)LONG_MAX / 10 ||
                (value == (unsigned long)LONG_MAX / 10 && digit > (unsigned)(LONG_MAX % 10)))
                die("numeric literal overflow");
            value = value * 10 + digit;
            p++;
        } while (*p >= '0' && *p <= '9');
    }
    *pp = p;
    return (long)value;
}
static long p_prim(const char **pp) {
    const char *p = skipsp(*pp);
    long v = 0;
    if (++g_expr_depth > EXPR_DEPTH) die("expression nesting limit");
    if (*p == '(') {
        p++; v = p_expr(&p); p = skipsp(p);
        if (*p != ')') die("missing )");
        p++;
    } else if (*p == '-' || *p == '+') {
        int neg = *p++ == '-'; v = p_prim(&p);
        if (neg) v = sub_checked(0, v);
    } else if (*p == '$') {
        if (p[1] == '$') { v = g_org; p += 2; }
        else { v = add_checked(g_org, g_off); p++; }
    } else if (isdigit((unsigned char)*p)) {
        v = number(&p);
    } else if (name_start((unsigned char)*p)) {
        char name[NAME_MAX]; size_t n = 0;
        while (name_part((unsigned char)*p)) {
            if (n == NAME_MAX - 1) die("identifier is too long");
            name[n++] = *p++;
        }
        name[n] = 0;
        v = sym_value(name);
    } else die("invalid expression");
    g_expr_depth--;
    *pp = p;
    return v;
}
static long p_term(const char **p) {
    *p = skipsp(*p);
    long v;
    if (**p >= '0' && **p <= '9') {
        if (g_expr_depth >= EXPR_DEPTH) die("expression nesting limit");
        v = number(p);
    } else v = p_prim(p);
    for (;;) {
        const char *q = skipsp(*p);
        if (*q != '*') { *p = q; return v; }
        q++; v = mul_checked(v, p_prim(&q)); *p = q;
    }
}
static long p_expr(const char **p) {
    long v = p_term(p);
    for (;;) {
        const char *q = skipsp(*p);
        if (*q == '+') { q++; v = add_checked(v, p_term(&q)); *p = q; }
        else if (*q == '-') { q++; v = sub_checked(v, p_term(&q)); *p = q; }
        else { *p = q; return v; }
    }
}
/* Literal-only operands need no recursive expression descent. A following
 * operator takes the general path, which keeps precedence and overflow checks. */
static inline long expression(const char **pp) {
    const char *p = skipsp(*pp);
    if (*p >= '0' && *p <= '9') {
        long v = number(&p);
        p = skipsp(p);
        if (*p != '+' && *p != '-' && *p != '*') { *pp = p; return v; }
    }
    return p_expr(pp);
}
static inline long eval(const char *s) {
    const char *p = s;
    g_expr_depth = g_unresolved = g_symbolic = 0;
    long v = expression(&p);
    if (*skipsp(p)) die("trailing characters in expression");
    return v;
}
/* Resizing immediates must preserve their 32-bit meaning (sign extension). */
static long signed32(long v) {
    if (v < INT32_MIN || v > (long)UINT32_MAX) die("32-bit immediate out of range");
    return v > INT32_MAX ? v - (long)UINT32_MAX - 1 : v;
}
/* ── registers ────────────────────────────────────────────────────────── */
static const char *SRG[] = {"es","cs","ss","ds","fs","gs"};
static int find_in(const char *s, const char **tab, int n) {
    for (int i = 0; i < n; i++) if (!strcmp(s, tab[i])) return i;
    return -1;
}
/* Returns index 0..7 and sets *sz to 1, 2, or 4; otherwise returns -1. */
static int reg_find(const char *s, int *sz) {
    int wide = *s == 'e';
    if (wide) s++;
    if (!s[0] || !s[1] || s[2]) return -1;
    int r;
    switch (s[0]) {
        case 'a': r = 0; break;
        case 'c': r = 1; break;
        case 'd': r = 2; break;
        case 'b': r = 3; break;
        case 's': r = 4; break;
        default: return -1;
    }
    if (r < 4 && s[1] == 'x') { *sz = wide ? 4 : 2; return r; }
    if (!wide && r < 4 && (s[1] == 'l' || s[1] == 'h')) {
        *sz = 1; return r + (s[1] == 'h' ? 4 : 0);
    }
    if (s[1] == 'p' && (r == 4 || r == 3)) {
        *sz = wide ? 4 : 2; return r == 4 ? 4 : 5;
    }
    if (s[1] == 'i' && (r == 4 || r == 2)) {
        *sz = wide ? 4 : 2; return r == 4 ? 6 : 7;
    }
    return -1;
}
/* ── memory operand: [reg ± disp] or [abs] ────────────────────────────── */
typedef struct { int base; long disp; int has_disp, symbolic; } Mem;
static void parse_mem(const char *tok, Mem *m) {
    const char *p = skipsp(tok);
    char inner[NAME_MAX];
    size_t n = 0;
    m->base = -1; m->disp = 0; m->has_disp = m->symbolic = 0;
    if (*p++ != '[') die("memory operand must begin with [");
    while (*p && *p != ']') {
        if (n == NAME_MAX - 1) die("memory expression is too long");
        inner[n++] = *p++;
    }
    inner[n] = 0;
    if (*p++ != ']') die("missing ]");
    if (*skipsp(p)) die("trailing characters after memory operand");
    const char *q = skipsp(inner), *end = q;
    while (name_part((unsigned char)*end)) end++;
    char base[NAME_MAX]; n = (size_t)(end - q);
    memcpy(base, q, n); base[n] = 0;
    int sz = 0;
    int reg = reg_find(base, &sz);
    if (reg >= 0) {
        if (sz != 4) die("address base must be reg32");
        m->base = reg;
        q = skipsp(end);
        if (!*q) return;
        if (*q != '+' && *q != '-') die("expected signed displacement after base");
    }
    m->disp = eval(q);
    m->symbolic = g_symbolic;
    m->has_disp = 1;
    if (m->base >= 0 || g_bits == 32) m->disp = signed32(m->disp);
    else if (m->disp < INT16_MIN || m->disp > UINT16_MAX)
        die("16-bit absolute address out of range");
}
static void address_prefix(const Mem *m) {
    if (g_bits == 16 && m->base >= 0) emit(0x67);
}
/* ModRM + displacement for the subset: reg32 base (without an index; esp gets
 * a SIB byte), or absolute (disp16 in BITS16, disp32 in BITS32). */
static void encode_mem(int regfield, Mem *m) {
    int mod, rm;
    if (m->base >= 0) {
        if (!m->symbolic && (!m->has_disp || m->disp == 0)) { mod = 0; if (m->base == 5) mod = 1; }
        else if (!m->symbolic && m->disp >= -128 && m->disp <= 127) mod = 1;
        else mod = 2;
        rm = m->base;
        emit(((mod << 6) | (regfield << 3) | (rm == 4 ? 4 : rm)) & 0xFF);
        if (rm == 4) emit(0x24);                 /* SIB: [esp] */
        if (mod == 1) emit(m->disp & 0xFF);
        else if (mod == 2) emit32(m->disp);
    } else {
        if (g_bits == 16) { emit(((0 << 6) | (regfield << 3) | 6) & 0xFF); emit16(m->disp); }
        else              { emit(((0 << 6) | (regfield << 3) | 5) & 0xFF); emit32(m->disp); }
    }
}
static int is_mem(const char *t) { return strchr(t, '[') != NULL; }
static void emit66_if(int opsize16) { if ((opsize16 && g_bits==32) || (!opsize16 && g_bits==16)) emit(0x66); }
/* ── branches rel8 ────────────────────────────────────────────────────── */
static void emit_rel8(const char *target) {
    long t = sym_value(target);
    long rel = sub_checked(t, add_checked(g_org, g_off + 1));
    if (g_pass == 2 && (rel < -128 || rel > 127))
        die("branch is outside rel8 range (nano supports short branches only)");
    emit(rel & 0xFF);
}

static void emit_call(const char *target) {
    long t = sym_value(target);
    long rel = sub_checked(t, add_checked(g_org, g_off + g_bits / 8));
    if (g_bits == 16) {
        if (g_pass == 2 && (rel < INT16_MIN || rel > INT16_MAX))
            die("call target is outside rel16 range");
        emit16(rel);
    } else {
        if (g_pass == 2 && (rel < INT32_MIN || rel > INT32_MAX))
            die("call target is outside rel32 range");
        emit32(rel);
    }
}
static int is_control_reg(const char *s) {
    if (s[0] != 'c' || s[1] != 'r' || !isdigit((unsigned char)s[2])) return 0;
    for (size_t i = 3; s[i]; i++) if (!isdigit((unsigned char)s[i])) return 0;
    return 1;
}
static int control_reg(const char *s) {
    if (strlen(s) != 3 || s[0] != 'c' || s[1] != 'r' ||
        (s[2] != '0' && s[2] != '2' && s[2] != '3' && s[2] != '4'))
        die("unsupported control register (expected cr0,cr2,cr3,cr4)");
    return s[2] - '0';
}
/* ── instructions ─────────────────────────────────────────────────────── */
static void asm_mov(const char *dst, const char *src) {
    int dsz, ssz;
    int dr = reg_find(dst, &dsz), sr = reg_find(src, &ssz);
    /* mov <size> [mem], imm */
    if (!strncmp(dst,"byte ",5) || !strncmp(dst,"word ",5) || !strncmp(dst,"dword ",6)) {
        int w = (dst[0]=='b') ? 1 : (dst[0]=='w') ? 2 : 4;
        Mem m; parse_mem(dst + (w == 4 ? 6 : 5), &m);
        long imm = eval(src);
        if (w != 1) emit66_if(w == 2);
        address_prefix(&m);
        emit(w == 1 ? 0xC6 : 0xC7);
        encode_mem(0, &m);
        if (w == 1) emit(imm & 0xFF); else if (w == 2) emit16(imm); else emit32(imm);
        return;
    }
    /* mov r32, crN / mov crN, r32 (no 0x66 even in BITS16) */
    if (dr >= 0 && is_control_reg(src)) {
        if (dsz != 4) die("control-register move requires reg32");
        int cr = control_reg(src);
        emit(0x0F); emit(0x20); emit(0xC0 | (cr << 3) | dr); return;
    }
    if (sr >= 0 && is_control_reg(dst)) {
        if (ssz != 4) die("control-register move requires reg32");
        int cr = control_reg(dst);
        emit(0x0F); emit(0x22); emit(0xC0 | (cr << 3) | sr); return;
    }
    /* mov sreg, r16 */
    int sg = find_in(dst, SRG, 6);
    if (sg >= 0 && sr >= 0) {
        if (sg == 1 || ssz != 2) die("mov segment form requires non-CS segment and reg16");
        emit(0x8E); emit(0xC0 | (sg << 3) | sr); return;
    }
    /* mov reg, [mem] */
    if (dr >= 0 && is_mem(src)) {
        Mem m; parse_mem(src, &m);
        if (dr == 0 && m.base < 0) {                 /* moffs A0/A1 */
            if (dsz != 1) emit66_if(dsz == 2);
            emit(dsz == 1 ? 0xA0 : 0xA1);
            if (g_bits == 16) emit16(m.disp); else emit32(m.disp);
            return;
        }
        if (dsz != 1) emit66_if(dsz == 2);
        address_prefix(&m);
        emit(dsz == 1 ? 0x8A : 0x8B);
        encode_mem(dr, &m);
        return;
    }
    /* mov [mem], reg */
    if (is_mem(dst) && sr >= 0) {
        Mem m; parse_mem(dst, &m);
        if (sr == 0 && m.base < 0) {                 /* moffs A2/A3 */
            if (ssz != 1) emit66_if(ssz == 2);
            emit(ssz == 1 ? 0xA2 : 0xA3);
            if (g_bits == 16) emit16(m.disp); else emit32(m.disp);
            return;
        }
        if (ssz != 1) emit66_if(ssz == 2);
        address_prefix(&m);
        emit(ssz == 1 ? 0x88 : 0x89);
        encode_mem(sr, &m);
        return;
    }
    /* mov reg, reg */
    if (dr >= 0 && sr >= 0) {
        if (dsz != ssz) die("mov operands have different sizes");
        if (dsz != 1) emit66_if(dsz == 2);
        emit(dsz == 1 ? 0x88 : 0x89);
        emit(0xC0 | (sr << 3) | dr);
        return;
    }
    /* mov reg, imm */
    if (dr >= 0) {
        long imm = eval(src);
        if (dsz == 1) { emit(0xB0 + dr); emit(imm & 0xFF); }
        else { emit66_if(dsz == 2); emit(0xB8 + dr);
               if (dsz == 2) emit16(imm); else emit32(imm); }
        return;
    }
    die("unsupported mov form");
}
/* Decode once. Exact string equality is retained; the first-byte guard
 * avoids re-running long strcmp chains for arity and encoding separately. */
typedef enum {
    OP_CLI, OP_CLD, OP_STI, OP_HLT, OP_NOP, OP_PUSHAD, OP_POPAD, OP_IRETD, OP_RET, OP_LODSB, OP_LODSW, OP_MOV, OP_XOR, OP_TEST, OP_CMP, OP_OR, OP_OUT, OP_IN, OP_INC, OP_DEC, OP_PUSH, OP_POP, OP_JMP, OP_CALL, OP_JZ, OP_JE, OP_JNZ, OP_JNE, OP_JB, OP_LOOP, OP_JECXZ, OP_INT, OP_LTR, OP_LGDT, OP_LIDT, OP_COUNT
} Opcode;
typedef struct { const char *name; int arity; } OpcodeInfo;
static const OpcodeInfo opcodes[OP_COUNT] = {
    {"cli",0},
    {"cld",0},
    {"sti",0},
    {"hlt",0},
    {"nop",0},
    {"pushad",0},
    {"popad",0},
    {"iretd",0},
    {"ret",0},
    {"lodsb",0},
    {"lodsw",0},
    {"mov",2},
    {"xor",2},
    {"test",2},
    {"cmp",2},
    {"or",2},
    {"out",2},
    {"in",2},
    {"inc",1},
    {"dec",1},
    {"push",1},
    {"pop",1},
    {"jmp",1},
    {"call",1},
    {"jz",1},
    {"je",1},
    {"jnz",1},
    {"jne",1},
    {"jb",1},
    {"loop",1},
    {"jecxz",1},
    {"int",1},
    {"ltr",1},
    {"lgdt",1},
    {"lidt",1},
};
static Opcode opcode_of(const char *mn) {
    /* Partition by first byte; compare the entire remaining name exactly. */
#define MATCH(name, op) if (!strcmp(mn + 1, &(name)[1])) return op
    switch (*mn) {
        case 'c': MATCH("cli", OP_CLI); MATCH("cld", OP_CLD); MATCH("cmp", OP_CMP); MATCH("call", OP_CALL); break;
        case 'd': MATCH("dec", OP_DEC); break;
        case 'h': MATCH("hlt", OP_HLT); break;
        case 'i': MATCH("in", OP_IN); MATCH("inc", OP_INC); MATCH("int", OP_INT); MATCH("iretd", OP_IRETD); break;
        case 'j': MATCH("jmp", OP_JMP); MATCH("jz", OP_JZ); MATCH("je", OP_JE); MATCH("jnz", OP_JNZ); MATCH("jne", OP_JNE); MATCH("jb", OP_JB); MATCH("jecxz", OP_JECXZ); break;
        case 'l': MATCH("lodsb", OP_LODSB); MATCH("lodsw", OP_LODSW); MATCH("loop", OP_LOOP); MATCH("ltr", OP_LTR); MATCH("lgdt", OP_LGDT); MATCH("lidt", OP_LIDT); break;
        case 'm': MATCH("mov", OP_MOV); break;
        case 'n': MATCH("nop", OP_NOP); break;
        case 'o': MATCH("or", OP_OR); MATCH("out", OP_OUT); break;
        case 'p': MATCH("push", OP_PUSH); MATCH("pop", OP_POP); MATCH("pushad", OP_PUSHAD); MATCH("popad", OP_POPAD); break;
        case 'r': MATCH("ret", OP_RET); break;
        case 's': MATCH("sti", OP_STI); break;
        case 't': MATCH("test", OP_TEST); break;
        case 'x': MATCH("xor", OP_XOR); break;
    }
#undef MATCH
    return OP_COUNT;
}
/* Keep the large encoder out of the line/directive parser's instruction cache. */
static BASM_NOINLINE void asm_insn(char *mn, char *ops) {
    Opcode op = opcode_of(mn);
    int arity = op == OP_COUNT ? -1 : opcodes[op].arity;
    if (arity < 0) die("unsupported mnemonic");
    if (!ops) ops = "";
    ops = (char *)skipsp(ops);
    char *comma = strchr(ops, ',');
    if ((!arity && *ops) || (arity && !*ops) || (arity == 1 && comma) ||
        (arity == 2 && (!comma || strchr(comma + 1, ','))))
        die("wrong operand count");
    /* No operands: explicit sizes still apply in BITS16. */
    if (op == OP_CLI)    { emit(0xFA); return; }
    if (op == OP_CLD)    { emit(0xFC); return; }
    if (op == OP_STI)    { emit(0xFB); return; }
    if (op == OP_HLT)    { emit(0xF4); return; }
    if (op == OP_NOP)    { emit(0x90); return; }
    if (op == OP_PUSHAD) { emit66_if(0); emit(0x60); return; }
    if (op == OP_POPAD)  { emit66_if(0); emit(0x61); return; }
    if (op == OP_IRETD)  { emit66_if(0); emit(0xCF); return; }
    if (op == OP_RET)    { emit(0xC3); return; }
    if (op == OP_LODSB)  { emit(0xAC); return; }
    if (op == OP_LODSW)  { emit66_if(1); emit(0xAD); return; }
    char o1[NAME_MAX], o2[NAME_MAX];
    size_t n = comma ? (size_t)(comma - ops) : strlen(ops);
    while (n && (ops[n-1] == ' ' || ops[n-1] == '\t')) n--;
    if (!n || n >= NAME_MAX) die("invalid or overlong operand");
    memcpy(o1, ops, n); o1[n] = 0; o2[0] = 0;
    if (comma) {
        const char *second = skipsp(comma + 1);
        n = strlen(second);
        while (n && (second[n-1] == ' ' || second[n-1] == '\t')) n--;
        if (!n || n >= NAME_MAX) die("invalid or overlong operand");
        memcpy(o2, second, n); o2[n] = 0;
    }
    int sz, r;
    if (op == OP_MOV) { asm_mov(o1, o2); return; }
    if ((op == OP_XOR) || (op == OP_TEST) || (op == OP_CMP)) {
        int sz2; int dr = reg_find(o1, &sz), sr = reg_find(o2, &sz2);
        int opc = (op == OP_XOR) ? 0x30 : (op == OP_TEST) ? 0x84 : 0x38;
        if (dr >= 0 && sr >= 0) {                    /* reg, reg */
            if (sz != sz2) die("register operands have different sizes");
            if (sz != 1) emit66_if(sz == 2);
            emit(sz == 1 ? opc : opc | 1);
            emit(0xC0 | (sr << 3) | dr);
            return;
        }
        if (dr >= 0 && is_mem(o2)) {                 /* cmp reg, [mem] */
            if ((op != OP_CMP) || (sz != 1 && sz != 4))
                die("nano supports only cmp r8/r32,[mem]");
            Mem m; parse_mem(o2, &m);
            if (sz != 1) emit66_if(sz == 2);
            address_prefix(&m);
            emit(sz == 1 ? 0x3A : 0x3B); encode_mem(dr, &m);
            return;
        }
        /* test/cmp al,imm8 and cmp r32,imm8 */
        if ((op == OP_TEST) && !strcmp(o1,"al")) { emit(0xA8); emit(eval(o2) & 0xFF); return; }
        if ((op == OP_CMP) && !strcmp(o1,"al")) { emit(0x3C); emit(eval(o2) & 0xFF); return; }
        if ((op == OP_CMP) && dr >= 0 && sz == 4) {
            long v = signed32(eval(o2));
            int narrow = !g_symbolic && v >= -128 && v <= 127;
            emit66_if(0);
            if (narrow) { emit(0x83); emit(0xF8 | dr); emit((uint8_t)v); }
            else if (dr == 0) { emit(0x3D); emit32(v); }
            else { emit(0x81); emit(0xF8 | dr); emit32(v); }
            return;
        }
        die("unsupported xor/test/cmp form");
    }
    if (op == OP_OR) {                          /* or al, imm8 */
        if (strcmp(o1,"al")) die("nano supports only or al,imm8");
        emit(0x0C); emit(eval(o2) & 0xFF); return;
    }
    if ((op == OP_INC) || (op == OP_DEC)) {
        r = reg_find(o1, &sz);
        if (r < 0) die("inc/dec operand is not a register");
        if (sz == 1) { emit(0xFE); emit(0xC0 | ((op == OP_DEC) ? 8 : 0) | r); }
        else { emit66_if(sz == 2); emit(((op == OP_INC) ? 0x40 : 0x48) + r); }
        return;
    }
    if (op == OP_PUSH) {
        r = reg_find(o1, &sz);
        if (r >= 0) { if (sz != 4 || g_bits != 32) die("push form is outside the supported subset"); emit(0x50 + r); return; }
        long v = eval(o1);
        if (g_bits == 32) v = signed32(v);
        else {
            if (v < INT16_MIN || v > UINT16_MAX) die("16-bit push immediate out of range");
            if (v > INT16_MAX) v -= 65536;
        }
        if (!g_symbolic && v >= -128 && v <= 127) { emit(0x6A); emit((uint8_t)v); }
        else { emit(0x68); if (g_bits == 16) emit16(v); else emit32(v); }
        return;
    }
    if (op == OP_POP) {
        r = reg_find(o1, &sz);
        if (r < 0 || sz != 4 || g_bits != 32) die("pop form is outside the supported subset");
        emit(0x58 + r); return;
    }
    if (op == OP_JMP) {
        int jr = reg_find(o1, &sz);
        if (jr >= 0) {                               /* jmp r32: FF /4 */
            if (sz != 4 || g_bits != 32) die("nano supports jmp r32 only in BITS32");
            emit(0xFF); emit(0xC0 | (4 << 3) | jr); return;
        }
        char *colon = strchr(o1, ':');
        if (colon) {                                 /* far: sel:off */
            *colon = 0;
            long sel = eval(o1), off = eval(colon + 1);
            if (sel < 0 || sel > UINT16_MAX || off < 0 || off > UINT16_MAX)
                die("far jump selector or offset is outside 16 bits");
            if (g_bits != 16) die("nano supports far jmp only in BITS16");
            emit(0xEA); emit16(off); emit16(sel);
            return;
        }
        emit(0xEB); emit_rel8(o1); return;
    }
    if (op == OP_CALL) { emit(0xE8); emit_call(o1); return; }
    if ((op == OP_JZ) || (op == OP_JE)) { emit(0x74); emit_rel8(o1); return; }
    if ((op == OP_JNZ) || (op == OP_JNE)) { emit(0x75); emit_rel8(o1); return; }
    if (op == OP_JB) { emit(0x72); emit_rel8(o1); return; }
    if (op == OP_LOOP) { emit(0xE2); emit_rel8(o1); return; }
    if (op == OP_JECXZ) { if (g_bits == 16) emit(0x67); emit(0xE3); emit_rel8(o1); return; }
    if (op == OP_INT) { emit(0xCD); emit(eval(o1) & 0xFF); return; }
    if (op == OP_OUT) {                         /* out imm8,al | out dx,al */
        if (!strcmp(o2,"al") && !strcmp(o1,"dx")) { emit(0xEE); return; }
        if (strcmp(o2,"al")) die("nano supports only out imm8,al | out dx,al");
        emit(0xE6); emit(eval(o1) & 0xFF); return;
    }
    if (op == OP_IN) {                          /* in al,imm8 | in al,dx */
        if (!strcmp(o1,"al") && !strcmp(o2,"dx")) { emit(0xEC); return; }
        if (strcmp(o1,"al")) die("nano supports only in al,imm8 | in al,dx");
        emit(0xE4); emit(eval(o2) & 0xFF); return;
    }
    if (op == OP_LTR) {                         /* ltr r16: 0F 00 /3 */
        r = reg_find(o1, &sz);
        if (r < 0 || sz != 2) die("ltr supports only r16");
        emit(0x0F); emit(0x00); emit(0xC0 | (3 << 3) | r); return;
    }
    if ((op == OP_LGDT) || (op == OP_LIDT)) {
        Mem m; parse_mem(o1, &m);
        if (m.base >= 0) die("nano supports only absolute lgdt/lidt operands");
        emit(0x0F); emit(0x01);
        encode_mem((op == OP_LGDT) ? 2 : 3, &m);
        return;
    }
    { char b[NAME_MAX+32]; snprintf(b, NAME_MAX+32, "unsupported mnemonic: %s", mn); die(b); }
}
/* ── data directives ──────────────────────────────────────────────────── */
static void asm_data(const char *dir, char *ops) {
    int w = !strcmp(dir,"db") ? 1 : !strcmp(dir,"dw") ? 2 : 4;
    const char *p = skipsp(ops);
    if (!*p) die("empty data directive");
    for (;;) {
        if (w == 1 && (*p == '\'' || *p == '"')) {
            char quote = *p++;
            const char *end = strchr(p, quote);
            if (!end) die("unterminated db string");
            long count = (long)(end - p);
            reserve_bytes(count);
            if (g_pass == 2) memcpy(g_out + g_off, p, (size_t)count);
            g_off += count;
            p = end + 1;
        } else {
            g_expr_depth = g_unresolved = g_symbolic = 0;
            long v = expression(&p);
            /* db/dw/dd retain deliberate low-bit extraction used by the sector. */
            if (w == 1) emit((uint8_t)v); else if (w == 2) emit16(v); else emit32(v);
        }
        p = skipsp(p);
        if (!*p) break;
        if (*p++ != ',') die("expected comma after data item");
        p = skipsp(p);
        if (!*p || *p == ',') die("empty data item");
    }
}
static void asm_times(char *ops) {
    const char *p = ops;
    g_expr_depth = g_unresolved = g_symbolic = 0;
    long count = expression(&p);
    if (g_unresolved) die("times count requires a resolved expression in pass one");
    p = skipsp(p);
    if (p[0] != 'd' || p[1] != 'b' || (p[2] != ' ' && p[2] != '\t'))
        die("times requires 'db <byte>'");
    long val = eval(p + 2);
    if (count < 0) die("times count is negative");
    reserve_bytes(count);
    if (g_pass == 2) memset(g_out + g_off, (uint8_t)val, (size_t)count);
    g_off += count;
}
/* ── preprocessor: %ifdef/%ifndef/%else/%endif + -D ──────────────────── */
static char g_defs[32][NAME_MAX];
static int g_ndefs;
typedef struct { int parent, condition, seen_else; } IfFrame;
static IfFrame g_if_stack[IF_DEPTH];
static int g_if_sp;
static int is_defined(const char *nm) {
    for (int i = 0; i < g_ndefs; i++) if (!strcmp(g_defs[i], nm)) return 1;
    return 0;
}
static int pp_line(char *line, int *active) {
    if (line[0] != '%') return 1;
    char *arg = line;
    while (*arg && *arg != ' ' && *arg != '\t') arg++;
    if (*arg) *arg++ = 0;
    arg = (char *)skipsp(arg);
    if (!strcmp(line, "%ifdef") || !strcmp(line, "%ifndef")) {
        check_name(arg);
        if (arg[0] == '.') die("preprocessor name cannot be local");
        if (g_if_sp >= IF_DEPTH) die("%ifdef nesting is too deep");
        IfFrame *frame = &g_if_stack[g_if_sp++];
        frame->parent = *active;
        frame->condition = is_defined(arg) ^ !strcmp(line, "%ifndef");
        frame->seen_else = 0;
        *active = frame->parent && frame->condition;
    } else if (!strcmp(line, "%else")) {
        if (*arg || !g_if_sp) die("invalid %else");
        IfFrame *frame = &g_if_stack[g_if_sp - 1];
        if (frame->seen_else) die("duplicate %else");
        frame->seen_else = 1;
        *active = frame->parent && !frame->condition;
    } else if (!strcmp(line, "%endif")) {
        if (*arg || !g_if_sp) die("invalid %endif");
        *active = g_if_stack[--g_if_sp].parent;
    } else die("% directive outside supported subset");
    return 0;
}
/* ── assembly pass ────────────────────────────────────────────────────── */
static void assemble(char *src) {
    g_off = 0; g_line = 0; g_bits = 32; g_org = 0; g_org_seen = 0;
    g_if_sp = 0;
    g_last_global[0] = 0;
    int active = 1;
    if (g_pass == 1) {
        /* No symbol was inserted when the preceding assembly had no labels. */
        if (g_nsyms) memset(g_sym_slots, 0, sizeof(g_sym_slots));
        g_nsyms = 0;
    }
    char *p = src;
    while (*p) {
        g_line++;
        char line[LINE_MAX];
        const char *start = p;
        char *c = line;
        char quote = 0;
        /* Copy and lex once. The comment suffix is skipped without copying,
         * but still counts towards the original full-line length limit. */
        while (*p && *p != '\n') {
            if (!quote && *p == ';') {
                char *eol = strchr(p, '\n');
                p = eol ? eol : p + strlen(p);
                break;
            }
            if (c == line + LINE_MAX - 1) die("line is too long");
            if (quote) { if (*p == quote) quote = 0; }
            else if (*p == '\'' || *p == '"') quote = *p;
            *c++ = *p++;
        }
        if ((size_t)(p - start) >= LINE_MAX) die("line is too long");
        if (*p) p++;
        *c = 0;
        char *trim = c;
        while (trim > line && (trim[-1] == ' ' || trim[-1] == '\t' || trim[-1] == '\r'))
            *--trim = 0;
        char *s = line; while (*s==' '||*s=='\t') s++;
        if (!*s) continue;
        if (!pp_line(s, &active)) continue;
        if (!active) continue;
        /* Split each leading token once, directly in the bounded line buffer. */
        char *mn = s;
        for (;;) {
            mn = s;
            while (*s && *s != ':' && *s != ' ' && *s != '\t') s++;
            if ((size_t)(s - mn) >= NAME_MAX) die("mnemonic or label is too long");
            if (*s != ':') break;
            *s++ = 0;
            sym_define(mn, g_off);
            s = (char *)skipsp(s);
            if (!*s) { mn = s; break; }
        }
        if (!*mn) continue;
        if (*s) *s++ = 0;
        s = (char *)skipsp(s);
        if (!strcmp(mn,"BITS")) {
            long bits = eval(s);
            if (g_unresolved || (bits != 16 && bits != 32)) die("nano supports only BITS 16 or BITS 32");
            g_bits = (int)bits;
        } else if (!strcmp(mn,"org")) {
            if (g_org_seen || g_off || (g_pass == 1 && g_nsyms))
                die("org is allowed once before code or labels");
            long org = eval(s);
            if (g_unresolved || g_symbolic || org < 0 || org > (long)UINT32_MAX - OUT_MAX)
                die("invalid origin");
            g_org = org; g_org_seen = 1;
        } else if (!strcmp(mn,"section")) {
            if (strcmp(s, ".text")) die("only section .text is supported");
        }
        else if (!strcmp(mn,"times"))   { asm_times(s); }
        else if (!strcmp(mn,"db") || !strcmp(mn,"dw") || !strcmp(mn,"dd")) { asm_data(mn, s); }
        else asm_insn(mn, s);
    }
    if (g_if_sp) die("unterminated preprocessor conditional");
}
/* ── --map: byte budget by symbol ─────────────────────────────────────── */
static void emit_map(FILE *f) {
    int idx[SYM_MAX], n = 0;
    for (int i = 0; i < g_nsyms; i++) if (!g_syms[i].is_local) idx[n++] = i;
    for (int k = 0; k < n; k++) {
        long end = (k + 1 < n) ? g_syms[idx[k+1]].off : g_off;
        if (fprintf(f, "%6ld %6ld %s\n", g_syms[idx[k]].off,
                    end - g_syms[idx[k]].off, g_syms[idx[k]].name) < 0)
            die("cannot write map output");
    }
}
/* ── checked input and per-file atomic publication ────────────────────── */
static char *g_staged[2], *g_input_bytes, *g_output_paths[2];
static void cleanup_staged(void) {
    free(g_input_bytes); g_input_bytes = NULL;
    for (int i = 0; i < 2; i++) { free(g_output_paths[i]); g_output_paths[i] = NULL; }
    for (int i = 0; i < 2; i++) if (g_staged[i]) {
        unlink(g_staged[i]); free(g_staged[i]); g_staged[i] = NULL;
    }
}
/* Resolve the existing parent, not the final component: output symlinks are
 * rejected rather than followed. The build directory must be trusted;
 * these checks are not a sandbox against concurrent filesystem attackers. */
static char *output_path(const char *path) {
    char *copy = strdup(path), *parent, *base, *resolved;
    if (!copy) die("out of memory resolving output");
    char *slash = strrchr(copy, '/');
    if (slash) { *slash = 0; parent = *copy ? copy : "/"; base = slash + 1; }
    else { parent = "."; base = copy; }
    if (!*base || !strcmp(base, ".") || !strcmp(base, "..")) {
        free(copy); die("invalid output filename");
    }
    resolved = realpath(parent, NULL);
    if (!resolved) { free(copy); die("output directory does not exist or is inaccessible"); }
    size_t n = strlen(resolved) + strlen(base) + 2;
    char *result = malloc(n);
    if (!result) { free(resolved); free(copy); die("out of memory resolving output"); }
    snprintf(result, n, "%s/%s", resolved, base);
    free(resolved); free(copy);
    return result;
}
static int existing_regular(const char *path, struct stat *st) {
    if (lstat(path, st) == 0) {
        if (!S_ISREG(st->st_mode)) die("output must be a regular file, not a symlink or device");
        return 1;
    }
    if (errno != ENOENT) die("cannot inspect output path");
    return 0;
}
static int same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static FILE *stage_file(const char *path, int slot) {
    size_t n = strlen(path) + sizeof(".tmp.XXXXXX");
    g_staged[slot] = malloc(n);
    if (!g_staged[slot]) die("out of memory preparing output");
    snprintf(g_staged[slot], n, "%s.tmp.XXXXXX", path);
    int fd = mkstemp(g_staged[slot]);
    if (fd < 0) die("cannot create temporary output");
    FILE *f = fdopen(fd, "wb");
    if (!f) { close(fd); die("cannot open temporary output stream"); }
    return f;
}
static void finish_file(FILE *f) {
    int bad = ferror(f);
    if (fflush(f) != 0) bad = 1;
    if (fclose(f) != 0) bad = 1;
    if (bad) die("cannot finish output (write, flush or close failed)");
}
static void publish_file(const char *path, int slot) {
    if (rename(g_staged[slot], path) != 0) die("cannot publish output");
    free(g_staged[slot]); g_staged[slot] = NULL;
}
/* ── main ─────────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    const char *in = NULL, *out = "a.bin", *map = NULL;
    int options = 1;
    if (sizeof(long) < 8) die("this host build requires a 64-bit long");
    if (atexit(cleanup_staged) != 0) die("cannot register output cleanup");
    for (int i = 1; i < argc; i++) {
        if (options && !strcmp(argv[i], "--")) { options = 0; continue; }
        if (options && !strcmp(argv[i], "-f")) {
            if (++i >= argc || strcmp(argv[i], "bin")) die("only -f bin is supported");
        } else if (options && !strcmp(argv[i], "-o")) {
            if (++i >= argc) die("-o requires an argument");
            out = argv[i];
        } else if (options && !strcmp(argv[i], "--map")) {
            if (++i >= argc) die("--map requires an argument");
            map = argv[i];
        } else if (options && !strncmp(argv[i], "-D", 2)) {
            if (g_ndefs >= 32) die("too many -D options");
            check_name(argv[i] + 2);
            memcpy(g_defs[g_ndefs++], argv[i] + 2, strlen(argv[i] + 2) + 1);
        } else {
            if (options && argv[i][0] == '-') die("unknown option");
            if (in) die("exactly one input file is required");
            in = argv[i];
        }
    }
    if (!in) die("usage: basm-nano -f bin -o out.bin [-DNAME] [--map FILE|-] in.basm");
    g_file = in;
    int fd = open(in, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) die("cannot open input");
    struct stat input_st, output_st, map_st;
    if (fstat(fd, &input_st) != 0 || !S_ISREG(input_st.st_mode) ||
        input_st.st_size < 0 || input_st.st_size > SOURCE_MAX) {
        close(fd); die("input must be a regular file of at most SOURCE_MAX bytes");
    }
    size_t size = (size_t)input_st.st_size;
    FILE *f = fdopen(fd, "rb");
    if (!f) { close(fd); die("cannot open input stream"); }
    char *src = g_input_bytes = malloc(size + 1);
    if (!src) { fclose(f); die("out of memory reading input"); }
    size_t got = fread(src, 1, size, f);
    int extra = fgetc(f), bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    if (got != size || extra != EOF || bad) die("input read failed or size changed");
    if (memchr(src, 0, size)) die("embedded NUL in input");
    src[size] = 0;
    char *out_path = g_output_paths[0] = output_path(out);
    char *map_path = g_output_paths[1] = map && strcmp(map, "-") ? output_path(map) : NULL;
    int out_exists = existing_regular(out_path, &output_st);
    int map_exists = map_path ? existing_regular(map_path, &map_st) : 0;
    if ((out_exists && same_file(&input_st, &output_st)) ||
        (map_exists && same_file(&input_st, &map_st)) ||
        (map_path && !strcmp(out_path, map_path)) ||
        (out_exists && map_exists && same_file(&output_st, &map_st)))
        die("input, binary and map must be distinct files");
    g_pass = 1; assemble(src);
    long image_size = g_off;
    g_pass = 2; assemble(src);
    if (g_off != image_size) die("size changed between passes");
    free(src); g_input_bytes = NULL;

    f = stage_file(out_path, 0);
    if (fwrite(g_out, 1, (size_t)g_off, f) != (size_t)g_off) {
        fclose(f); die("cannot write binary output");
    }
    finish_file(f);
    if (map_path) { f = stage_file(map_path, 1); emit_map(f); finish_file(f); }
    else if (map) { emit_map(stdout); if (fflush(stdout) != 0) die("cannot flush map stdout"); }
    /* All streams are complete before either destination is replaced.
     * Each rename is atomic; the binary/map pair is NOT a filesystem
     * transaction and no power-loss durability is claimed. */
    if (map_path) publish_file(map_path, 1);
    publish_file(out_path, 0);
    cleanup_staged();
    return 0;
}
