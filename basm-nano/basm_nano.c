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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define SYM_MAX   256
#define OUT_MAX   65536
#define NAME_MAX  128
#define IF_DEPTH  16
#define LINE_MAX  1024   /* Use the named constant rather than sizeof on a local
                          * array. Some constrained compilers report the pointer
                          * size even though the array storage is correct. */

static uint8_t  g_out[OUT_MAX];
static long     g_off;              /* current offset in the image        */
static long     g_org;              /* org (absolute base for labels)     */
static int      g_bits = 32;        /* current mode: 16 or 32             */
static int      g_pass;             /* 1 = measure, 2 = final emission    */
static int      g_line;
static const char *g_file;

static void die(const char *msg) {
    fprintf(stderr, "basm-nano: %s:%d: %s\n", g_file, g_line, msg);
    exit(1);
}

/* ── symbols ──────────────────────────────────────────────────────────── */
typedef struct { char name[NAME_MAX]; long off; int is_local; } Sym;
static Sym  g_syms[SYM_MAX];
static int  g_nsyms;
static char g_last_global[NAME_MAX];

static void qualify(const char *name, char *out) {
    if (name[0] == '.') {
        if (!g_last_global[0]) die("local label has no preceding global label");
        snprintf(out, NAME_MAX, "%s%s", g_last_global, name);
    } else {
        strncpy(out, name, NAME_MAX - 1); out[NAME_MAX - 1] = 0;
    }
}

static void sym_define(const char *name, long off) {
    char q[NAME_MAX]; qualify(name, q);
    if (name[0] != '.') {   /* Globals update the local-label scope on every pass. */
        strncpy(g_last_global, name, NAME_MAX - 1); g_last_global[NAME_MAX-1] = 0;
    }
    for (int i = 0; i < g_nsyms; i++)
        if (!strcmp(g_syms[i].name, q)) {
            if (g_pass == 2 && g_syms[i].off != off)
                die("label changed between passes");
            g_syms[i].off = off; return;
        }
    if (g_nsyms >= SYM_MAX) die("too many symbols");
    snprintf(g_syms[g_nsyms].name, NAME_MAX, "%s", q);
    g_syms[g_nsyms].off = off;
    g_syms[g_nsyms].is_local = (name[0] == '.');
    g_nsyms++;
}

static long sym_value(const char *name) {
    char q[NAME_MAX]; qualify(name, q);
    for (int i = 0; i < g_nsyms; i++)
        if (!strcmp(g_syms[i].name, q)) return g_org + g_syms[i].off;
    if (g_pass == 2) { char b[NAME_MAX+32]; snprintf(b, NAME_MAX+32, "undefined label: %s", q); die(b); }
    return 0;
}

/* ── emission ─────────────────────────────────────────────────────────── */
static void emit(uint8_t b) {
    if (g_pass == 2) {
        if (g_off >= OUT_MAX) die("image exceeds OUT_MAX");
        g_out[g_off] = b;
    }
    g_off++;
}
static void emit16(long v) { emit(v & 0xFF); emit((v >> 8) & 0xFF); }
static void emit32(long v) { emit16(v); emit16(v >> 16); }

/* ── expressions: primary = number | label | $ | $$ | (e) | -e; *; + - ─ */
static long p_expr(const char **p);

static const char *skipsp(const char *p) { while (*p==' '||*p=='\t') p++; return p; }

static long p_prim(const char **pp) {
    const char *p = skipsp(*pp);
    long v = 0;
    if (*p == '(') { p++; v = p_expr(&p); p = skipsp(p);
        if (*p != ')') die("missing )");
        p++; }
    else if (*p == '-') { p++; v = -p_prim(&p); }
    else if (*p == '$') {
        if (p[1] == '$') { v = g_org; p += 2; } else { v = g_org + g_off; p++; }
    }
    else if (isdigit((unsigned char)*p)) {
        if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) v = strtol(p, (char**)&p, 16);
        else v = strtol(p, (char**)&p, 10);
    }
    else if (isalpha((unsigned char)*p) || *p=='_' || *p=='.') {
        char nm[NAME_MAX]; int n = 0;
        while (isalnum((unsigned char)*p) || *p=='_' || *p=='.' )
            if (n < NAME_MAX-1) nm[n++] = *p++; else p++;
        nm[n] = 0;
        v = sym_value(nm);
    }
    else die("invalid expression");
    *pp = p;
    return v;
}
static long p_term(const char **p) {
    long v = p_prim(p);
    for (;;) { const char *q = skipsp(*p);
        if (*q == '*') { q++; v *= p_prim(&q); *p = q; } else { *p = q; return v; } }
}
static long p_expr(const char **p) {
    long v = p_term(p);
    for (;;) { const char *q = skipsp(*p);
        if (*q=='+') { q++; v += p_term(&q); *p = q; }
        else if (*q=='-') { q++; v -= p_term(&q); *p = q; }
        else { *p = q; return v; } }
}
static long eval(const char *s) { const char *p = s; return p_expr(&p); }

/* ── registers ────────────────────────────────────────────────────────── */
static const char *R8[]  = {"al","cl","dl","bl","ah","ch","dh","bh"};
static const char *R16[] = {"ax","cx","dx","bx","sp","bp","si","di"};
static const char *R32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
static const char *SRG[] = {"es","cs","ss","ds","fs","gs"};

static int find_in(const char *s, const char **tab, int n) {
    for (int i = 0; i < n; i++) if (!strcmp(s, tab[i])) return i;
    return -1;
}
/* Returns index 0..7 and sets *sz to 1, 2, or 4; otherwise returns -1. */
static int reg_find(const char *s, int *sz) {
    int i;
    if ((i = find_in(s, R8, 8))  >= 0) { *sz = 1; return i; }
    if ((i = find_in(s, R16, 8)) >= 0) { *sz = 2; return i; }
    if ((i = find_in(s, R32, 8)) >= 0) { *sz = 4; return i; }
    return -1;
}

/* ── memory operand: [reg ± disp] or [abs] ────────────────────────────── */
typedef struct { int base; long disp; int has_disp; } Mem;   /* base=-1: absolute */

static void parse_mem(const char *tok, Mem *m) {
    m->base = -1; m->disp = 0; m->has_disp = 0;
    const char *p = strchr(tok, '[');
    if (!p) die("expected [");
    p++;
    char inner[NAME_MAX]; int n = 0;
    while (*p && *p != ']' && n < NAME_MAX-1) inner[n++] = *p++;
    inner[n] = 0;
    if (*p != ']') die("missing ]");

    /* Separate the base register from the displacement expression. */
    char rest[NAME_MAX]; int rn = 0;
    const char *q = inner;
    while (*q) {
        while (*q==' ') q++;
        if (!*q) break;
        int neg = 0;
        if (*q=='+') { q++; while(*q==' ')q++; }
        else if (*q=='-') { neg = 1; q++; while(*q==' ')q++; }
        char comp[NAME_MAX]; int ci = 0;
        while (*q && *q!='+' && *q!='-' && ci < NAME_MAX-1) comp[ci++] = *q++;
        comp[ci] = 0; while (ci>0 && comp[ci-1]==' ') comp[--ci] = 0;
        if (!ci) continue;
        int sz;
        int r = reg_find(comp, &sz);
        if (r >= 0) {
            if (sz != 4 || neg) die("base must be a reg32 operand without a leading minus sign");
            if (m->base >= 0) die("two base registers (nano has no index support)");
            m->base = r;
        } else {
            if (rn) rest[rn++] = neg ? '-' : '+';
            else if (neg) rest[rn++] = '-';
            for (int i = 0; comp[i] && rn < NAME_MAX-2; i++) rest[rn++] = comp[i];
        }
    }
    rest[rn] = 0;
    if (rn) { m->disp = eval(rest); m->has_disp = 1; }
}

/* ModRM + displacement for the subset: reg32 base (without an index; esp gets
 * a SIB byte), or absolute (disp16 in BITS16, disp32 in BITS32). */
static void encode_mem(int regfield, Mem *m) {
    int mod, rm;
    if (m->base >= 0) {
        if (!m->has_disp || m->disp == 0) { mod = 0; if (m->base == 5) mod = 1; }
        else if (m->disp >= -128 && m->disp <= 127) mod = 1;
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
    long rel = t - (g_org + g_off + 1);
    if (g_pass == 2 && (rel < -128 || rel > 127))
        die("branch is outside rel8 range (nano supports short branches only)");
    emit(rel & 0xFF);
}

static void emit_rel32(const char *target) {
    long t = sym_value(target);
    long rel = t - (g_org + g_off + 4);
    emit32(rel);
}

/* ── instructions ─────────────────────────────────────────────────────── */
static void asm_mov(const char *dst, const char *src) {
    int dsz, ssz;
    int dr = reg_find(dst, &dsz), sr = reg_find(src, &ssz);

    /* mov <size> [mem], imm */
    if (!strncmp(dst,"byte ",5) || !strncmp(dst,"word ",5) || !strncmp(dst,"dword ",6)) {
        int w = (dst[0]=='b') ? 1 : (dst[0]=='w') ? 2 : 4;
        Mem m; parse_mem(dst, &m);
        long imm = eval(src);
        if (w == 2) emit66_if(1);
        emit(w == 1 ? 0xC6 : 0xC7);
        encode_mem(0, &m);
        if (w == 1) emit(imm & 0xFF); else if (w == 2) emit16(imm); else emit32(imm);
        return;
    }
    /* mov r32, crN / mov crN, r32 (no 0x66 even in BITS16) */
    if (dr >= 0 && !strncmp(src, "cr", 2)) {
        emit(0x0F); emit(0x20); emit(0xC0 | ((src[2]-'0') << 3) | dr); return;
    }
    if (sr >= 0 && !strncmp(dst, "cr", 2)) {
        emit(0x0F); emit(0x22); emit(0xC0 | ((dst[2]-'0') << 3) | sr); return;
    }
    /* mov sreg, r16 */
    int sg = find_in(dst, SRG, 6);
    if (sg >= 0 && sr >= 0) { emit(0x8E); emit(0xC0 | (sg << 3) | sr); return; }
    /* mov reg, [mem] */
    if (dr >= 0 && is_mem(src)) {
        Mem m; parse_mem(src, &m);
        if (dr == 0 && m.base < 0) {                 /* moffs A0/A1 */
            if (dsz == 2) emit66_if(1);
            emit(dsz == 1 ? 0xA0 : 0xA1);
            if (g_bits == 16) emit16(m.disp); else emit32(m.disp);
            return;
        }
        if (dsz == 2) emit66_if(1);
        emit(dsz == 1 ? 0x8A : 0x8B);
        encode_mem(dr, &m);
        return;
    }
    /* mov [mem], reg */
    if (is_mem(dst) && sr >= 0) {
        Mem m; parse_mem(dst, &m);
        if (sr == 0 && m.base < 0) {                 /* moffs A2/A3 */
            if (ssz == 2) emit66_if(1);
            emit(ssz == 1 ? 0xA2 : 0xA3);
            if (g_bits == 16) emit16(m.disp); else emit32(m.disp);
            return;
        }
        if (ssz == 2) emit66_if(1);
        emit(ssz == 1 ? 0x88 : 0x89);
        encode_mem(sr, &m);
        return;
    }
    /* mov reg, reg */
    if (dr >= 0 && sr >= 0) {
        if (dsz != ssz) die("mov operands have different sizes");
        if (dsz == 2) emit66_if(1);
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

static void asm_insn(char *mn, char *ops) {
    /* No operands. */
    if (!strcmp(mn,"cli"))    { emit(0xFA); return; }
    if (!strcmp(mn,"cld"))    { emit(0xFC); return; }
    if (!strcmp(mn,"sti"))    { emit(0xFB); return; }
    if (!strcmp(mn,"hlt"))    { emit(0xF4); return; }
    if (!strcmp(mn,"nop"))    { emit(0x90); return; }
    if (!strcmp(mn,"pushad")) { emit(0x60); return; }
    if (!strcmp(mn,"popad"))  { emit(0x61); return; }
    if (!strcmp(mn,"iretd"))  { emit(0xCF); return; }
    if (!strcmp(mn,"ret"))    { emit(0xC3); return; }
    if (!strcmp(mn,"lodsb"))  { emit(0xAC); return; }
    if (!strcmp(mn,"lodsw"))  { emit66_if(1); emit(0xAD); return; }

    /* Two operands separated by a top-level comma. */
    char *comma = ops ? strchr(ops, ',') : NULL;
    char o1[NAME_MAX], o2[NAME_MAX];
    if (comma) {
        int n = (int)(comma - ops); if (n >= NAME_MAX) die("operand is too long");
        strncpy(o1, ops, n); o1[n] = 0;
        strncpy(o2, comma + 1, NAME_MAX - 1); o2[NAME_MAX-1] = 0;
        /* Trim both ends of both operands. */
        char *e = o1 + strlen(o1); while (e > o1 && e[-1]==' ') *--e = 0;
        char *s = o2; while (*s==' ') s++;
        if (s != o2) memmove(o2, s, strlen(s) + 1);
        e = o2 + strlen(o2); while (e > o2 && (e[-1]==' '||e[-1]=='\t')) *--e = 0;
    } else if (ops) {
        strncpy(o1, ops, NAME_MAX - 1); o1[NAME_MAX-1] = 0; o2[0] = 0;
        char *e = o1 + strlen(o1); while (e > o1 && (e[-1]==' '||e[-1]=='\t')) *--e = 0;
    } else { o1[0] = o2[0] = 0; }

    int sz, r;
    if (!strcmp(mn,"mov")) { asm_mov(o1, o2); return; }
    if (!strcmp(mn,"xor") || !strcmp(mn,"test") || !strcmp(mn,"cmp")) {
        int sz2; int dr = reg_find(o1, &sz), sr = reg_find(o2, &sz2);
        int opc = !strcmp(mn,"xor") ? 0x30 : !strcmp(mn,"test") ? 0x84 : 0x38;
        if (dr >= 0 && sr >= 0) {                    /* reg, reg */
            if (sz == 2) emit66_if(1);
            emit(sz == 1 ? opc : opc | 1);
            emit(0xC0 | (sr << 3) | dr);
            return;
        }
        if (dr >= 0 && is_mem(o2)) {                 /* cmp reg, [mem] */
            if (strcmp(mn,"cmp") || (sz != 1 && sz != 4))
                die("nano supports only cmp r8/r32,[mem]");
            Mem m; parse_mem(o2, &m);
            emit(sz == 1 ? 0x3A : 0x3B); encode_mem(dr, &m);
            return;
        }
        /* test/cmp al,imm8 and cmp r32,imm8 */
        if (!strcmp(mn,"test") && !strcmp(o1,"al")) { emit(0xA8); emit(eval(o2) & 0xFF); return; }
        if (!strcmp(mn,"cmp") && !strcmp(o1,"al")) { emit(0x3C); emit(eval(o2) & 0xFF); return; }
        if (!strcmp(mn,"cmp") && dr >= 0 && sz == 4) {
            emit(0x83); emit(0xC0 | (7 << 3) | dr); emit(eval(o2) & 0xFF); return;
        }
        die("unsupported xor/test/cmp form");
    }
    if (!strcmp(mn,"or")) {                          /* or al, imm8 */
        if (strcmp(o1,"al")) die("nano supports only or al,imm8");
        emit(0x0C); emit(eval(o2) & 0xFF); return;
    }
    if (!strcmp(mn,"inc") || !strcmp(mn,"dec")) {
        r = reg_find(o1, &sz);
        if (r < 0) die("inc/dec operand is not a register");
        if (sz == 1) { emit(0xFE); emit(0xC0 | (!strcmp(mn,"dec") ? 8 : 0) | r); }
        else if (sz == 2 && g_bits == 16) emit((!strcmp(mn,"inc") ? 0x40 : 0x48) + r);
        else if (sz == 4 && g_bits == 32) emit((!strcmp(mn,"inc") ? 0x40 : 0x48) + r);
        else die("inc/dec form is outside the supported subset");
        return;
    }
    if (!strcmp(mn,"push")) {
        r = reg_find(o1, &sz);
        if (r >= 0) { if (sz != 4 || g_bits != 32) die("push form is outside the supported subset"); emit(0x50 + r); return; }
        long v = eval(o1);
        if (v >= -128 && v <= 127) { emit(0x6A); emit(v & 0xFF); }
        else { emit(0x68); emit32(v); }
        return;
    }
    if (!strcmp(mn,"pop")) {
        r = reg_find(o1, &sz);
        if (r < 0 || sz != 4 || g_bits != 32) die("pop form is outside the supported subset");
        emit(0x58 + r); return;
    }
    if (!strcmp(mn,"jmp")) {
        int jr = reg_find(o1, &sz);
        if (jr >= 0) {                               /* jmp r32: FF /4 */
            if (sz != 4 || g_bits != 32) die("nano supports jmp r32 only in BITS32");
            emit(0xFF); emit(0xC0 | (4 << 3) | jr); return;
        }
        char *colon = strchr(o1, ':');
        if (colon) {                                 /* far: sel:off */
            *colon = 0;
            long sel = eval(o1), off = eval(colon + 1);
            if (g_bits != 16) die("nano supports far jmp only in BITS16");
            emit(0xEA); emit16(off); emit16(sel);
            return;
        }
        emit(0xEB); emit_rel8(o1); return;
    }
    if (!strcmp(mn,"call")) { emit(0xE8); emit_rel32(o1); return; }
    if (!strcmp(mn,"jz") || !strcmp(mn,"je")) { emit(0x74); emit_rel8(o1); return; }
    if (!strcmp(mn,"jnz") || !strcmp(mn,"jne")) { emit(0x75); emit_rel8(o1); return; }
    if (!strcmp(mn,"jb")) { emit(0x72); emit_rel8(o1); return; }
    if (!strcmp(mn,"loop")) { emit(0xE2); emit_rel8(o1); return; }
    if (!strcmp(mn,"jecxz")) { emit(0xE3); emit_rel8(o1); return; }
    if (!strcmp(mn,"int")) { emit(0xCD); emit(eval(o1) & 0xFF); return; }
    if (!strcmp(mn,"out")) {                         /* out imm8,al | out dx,al */
        if (!strcmp(o2,"al") && !strcmp(o1,"dx")) { emit(0xEE); return; }
        if (strcmp(o2,"al")) die("nano supports only out imm8,al | out dx,al");
        emit(0xE6); emit(eval(o1) & 0xFF); return;
    }
    if (!strcmp(mn,"in")) {                          /* in al,imm8 | in al,dx */
        if (!strcmp(o1,"al") && !strcmp(o2,"dx")) { emit(0xEC); return; }
        if (strcmp(o1,"al")) die("nano supports only in al,imm8 | in al,dx");
        emit(0xE4); emit(eval(o2) & 0xFF); return;
    }
    if (!strcmp(mn,"ltr")) {                         /* ltr r16: 0F 00 /3 */
        r = reg_find(o1, &sz);
        if (r < 0 || sz != 2) die("ltr supports only r16");
        emit(0x0F); emit(0x00); emit(0xC0 | (3 << 3) | r); return;
    }
    if (!strcmp(mn,"lgdt") || !strcmp(mn,"lidt")) {
        Mem m; parse_mem(o1, &m);
        if (m.base >= 0) die("nano supports only absolute lgdt/lidt operands");
        emit(0x0F); emit(0x01);
        encode_mem(!strcmp(mn,"lgdt") ? 2 : 3, &m);
        return;
    }
    { char b[NAME_MAX+32]; snprintf(b, NAME_MAX+32, "unsupported mnemonic: %s", mn); die(b); }
}

/* ── data directives ──────────────────────────────────────────────────── */
static void asm_data(const char *dir, char *ops) {
    int w = !strcmp(dir,"db") ? 1 : !strcmp(dir,"dw") ? 2 : 4;
    char *p = ops;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        if (w == 1 && (*p == '\'' || *p == '"')) {
            char quote = *p++;
            while (*p && *p != quote) emit((uint8_t)*p++);
            if (*p != quote) die("unterminated db string");
            p++;
            continue;
        }
        char item[NAME_MAX]; int n = 0;
        while (*p && *p != ',' && n < NAME_MAX-1) item[n++] = *p++;
        item[n] = 0; if (*p == ',') p++;
        long v = eval(item);
        if (w == 1) emit(v & 0xFF); else if (w == 2) emit16(v); else emit32(v);
    }
}

static void asm_times(char *ops) {
    /* times <expr> db <expr>: the count is everything before the final " db ". */
    char *dbk = strstr(ops, " db ");
    if (!dbk) die("times requires 'db <byte>'");
    *dbk = 0;
    long count = eval(ops), val = eval(dbk + 4);
    if (count < 0) die("times count is negative");
    for (long k = 0; k < count; k++) emit(val & 0xFF);
}

/* ── preprocessor: %ifdef/%ifndef/%else/%endif + -D ──────────────────── */
static char g_defs[32][NAME_MAX];
static int  g_ndefs;
static int  g_if_stack[IF_DEPTH];   /* 1 = active */
static int  g_if_sp;

static int is_defined(const char *nm) {
    for (int i = 0; i < g_ndefs; i++) if (!strcmp(g_defs[i], nm)) return 1;
    return 0;
}

static int pp_line(char *line, int *active) {
    if (line[0] != '%') return 1;                    /* Normal line. */
    int parent = 1;
    for (int i = 0; i < g_if_sp - 1; i++) if (!g_if_stack[i]) parent = 0;
    if (!strncmp(line, "%ifdef", 6) || !strncmp(line, "%ifndef", 7)) {
        int neg = (line[3] == 'n');
        char *nm = line + (neg ? 7 : 6); while (*nm==' ') nm++;
        if (g_if_sp >= IF_DEPTH) die("%ifdef nesting is too deep");
        int cond = is_defined(nm) ^ neg;
        g_if_stack[g_if_sp++] = *active && cond;
        *active = g_if_stack[g_if_sp - 1];
        return 0;
    }
    if (!strncmp(line, "%else", 5)) {
        if (!g_if_sp) die("%else without %if");
        g_if_stack[g_if_sp - 1] = !g_if_stack[g_if_sp - 1] && parent;
        *active = g_if_stack[g_if_sp - 1];
        return 0;
    }
    if (!strncmp(line, "%endif", 6)) {
        if (!g_if_sp) die("%endif without %if");
        g_if_sp--;
        *active = g_if_sp ? g_if_stack[g_if_sp - 1] : 1;
        return 0;
    }
    if (!*active) return 0;
    die("% directive outside supported subset");
    return 0;
}

/* ── assembly pass ────────────────────────────────────────────────────── */
static void assemble(char *src) {
    g_off = 0; g_line = 0;
    g_last_global[0] = 0;
    int active = 1;
    if (g_pass == 1) { g_nsyms = 0; g_if_sp = 0; }

    char *p = src;
    while (*p) {
        g_line++;
        char *eol = strchr(p, '\n');
        char line[LINE_MAX];
        int len = eol ? (int)(eol - p) : (int)strlen(p);
        if (len >= LINE_MAX) die("line is too long");
        memcpy(line, p, len); line[len] = 0;
        p = eol ? eol + 1 : p + len;

        /* ';' starts a comment only outside a db string. */
        char quote = 0;
        for (char *c = line; *c; c++) {
            if (quote) { if (*c == quote) quote = 0; }
            else if (*c == '\'' || *c == '"') quote = *c;
            else if (*c == ';') { *c = 0; break; }
        }
        char *s = line; while (*s==' '||*s=='\t') s++;
        if (!*s) continue;
        if (!pp_line(s, &active)) continue;
        if (!active) continue;

        /* Labels at the start of a line (possibly more than one). */
        for (;;) {
            char *colon = strchr(s, ':');
            char *sp = s; while (*sp && *sp!=' ' && *sp!='\t') sp++;
            if (!colon || colon > sp) break;         /* Not a label. */
            *colon = 0;
            sym_define(s, g_off);
            s = colon + 1; while (*s==' '||*s=='\t') s++;
            if (!*s) break;
        }
        if (!*s) continue;

        /* Mnemonic and operands. */
        char mn[NAME_MAX]; int n = 0;
        while (*s && *s!=' ' && *s!='\t' && n < NAME_MAX-1) mn[n++] = *s++;
        mn[n] = 0; while (*s==' '||*s=='\t') s++;

        if (!strcmp(mn,"BITS"))         { g_bits = atoi(s); if (g_bits!=16 && g_bits!=32) die("nano supports only BITS 16 or BITS 32"); }
        else if (!strcmp(mn,"org"))     { g_org = eval(s); }
        else if (!strcmp(mn,"section")) { /* One section only: .text. */ }
        else if (!strcmp(mn,"times"))   { asm_times(s); }
        else if (!strcmp(mn,"db") || !strcmp(mn,"dw") || !strcmp(mn,"dd")) { asm_data(mn, s); }
        else asm_insn(mn, s);
    }
}

/* ── --map: byte budget by symbol ─────────────────────────────────────── */
static void emit_map(const char *path) {
    FILE *f = !strcmp(path, "-") ? stdout : fopen(path, "w");
    if (!f) { perror("basm-nano: cannot open map output"); exit(1); }
    int idx[SYM_MAX], n = 0;
    for (int i = 0; i < g_nsyms; i++) if (!g_syms[i].is_local) idx[n++] = i;
    for (int a = 0; a < n; a++)
        for (int b = a + 1; b < n; b++)
            if (g_syms[idx[b]].off < g_syms[idx[a]].off) {
                int t = idx[a]; idx[a] = idx[b]; idx[b] = t;
            }
    for (int k = 0; k < n; k++) {
        long end = (k + 1 < n) ? g_syms[idx[k+1]].off : g_off;
        fprintf(f, "%6ld %6ld %s\n", g_syms[idx[k]].off, end - g_syms[idx[k]].off,
                g_syms[idx[k]].name);
    }
    if (f != stdout) fclose(f);
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    const char *in = NULL, *out = "a.bin", *map = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f")) {
            if (++i >= argc || strcmp(argv[i], "bin")) { fprintf(stderr, "basm-nano: only -f bin is supported\n"); return 1; }
        }
        else if (!strcmp(argv[i], "-o")) { if (++i >= argc) { fprintf(stderr, "basm-nano: -o requires an argument\n"); return 1; } out = argv[i]; }
        else if (!strcmp(argv[i], "--map")) { if (++i >= argc) { fprintf(stderr, "basm-nano: --map requires an argument\n"); return 1; } map = argv[i]; }
        else if (!strncmp(argv[i], "-D", 2)) {
            if (g_ndefs >= 32) { fprintf(stderr, "too many -D options\n"); return 1; }
            strncpy(g_defs[g_ndefs++], argv[i] + 2, NAME_MAX - 1);
        }
        else in = argv[i];
    }
    if (!in) {
        fprintf(stderr, "usage: basm-nano -f bin -o out.bin [-DNAME] [--map -] in.basm\n");
        return 1;
    }
    g_file = in;
    FILE *f = fopen(in, "rb");
    if (!f) { perror("basm-nano: cannot open input"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char *src = malloc((size_t)sz + 1);
    if (!src || fread(src, 1, (size_t)sz, f) != (size_t)sz) { perror("basm-nano: cannot read input"); return 1; }
    src[sz] = 0; fclose(f);

    g_pass = 1; assemble(src);
    long size = g_off;
    g_pass = 2; assemble(src);
    if (g_off != size) die("size changed between passes");

    f = fopen(out, "wb");
    if (!f) { perror("basm-nano: cannot open output"); return 1; }
    fwrite(g_out, 1, (size_t)g_off, f); fclose(f);
    if (map) emit_map(map);
    return 0;
}
