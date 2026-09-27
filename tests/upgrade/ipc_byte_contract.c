/* SPDX-License-Identifier: BSD-3-Clause
 * Bounded executable-byte contract for the BasmOS send/receive handlers.
 * This is NOT an x86 emulator, boot test, segmentation proof or IRQ model.
 * Only the instruction subset below is interpreted; unknown bytes fail closed.
 * ES is modeled as flat, DS as non-flat. ECX cursors start at 0x700..0x7ff.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define FRAME 0xa00u
#define RING 0x700u
#define ORIGIN 0x7c00u

typedef struct {
    uint32_t r[8], other;
    uint8_t ring[256], frame[32];
    unsigned writes, last_write, zf;
} State;
typedef struct { uint8_t code[65536]; size_t size, send, recv, end, other; } Image;
static uint64_t transitions;
static unsigned bad_head, bad_tail, bad_pattern;

static int byte_read(const State *s, uint32_t addr, uint8_t *v) {
    if (addr >= RING && addr < RING + 256) *v = s->ring[addr - RING];
    else if (addr >= FRAME && addr < FRAME + 32) *v = s->frame[addr - FRAME];
    else if (addr >= s->other && addr - s->other < 4)
        *v = (uint8_t)(FRAME >> (8 * (addr - s->other)));
    else return 0;
    return 1;
}
static int read_mem(const State *s, uint32_t addr, unsigned width, uint32_t *v) {
    *v = 0;
    for (unsigned i = 0; i < width; i++) {
        uint8_t b;
        if (!byte_read(s, addr + i, &b)) return 0;
        *v |= (uint32_t)b << (8 * i);
    }
    return 1;
}
static uint8_t reg8(const State *s, unsigned r) { return (uint8_t)(s->r[r & 3] >> (r < 4 ? 0 : 8)); }
static void set8(State *s, unsigned r, uint8_t v) {
    unsigned shift = r < 4 ? 0 : 8;
    s->r[r & 3] = (s->r[r & 3] & ~(UINT32_C(255) << shift)) | ((uint32_t)v << shift);
}
static int next_byte(const Image *im, size_t *pc, size_t end, uint8_t *v) {
    if (*pc >= end || *pc >= im->size) return 0;
    *v = im->code[(*pc)++]; return 1;
}
static int displacement(const Image *im, size_t *pc, size_t end, unsigned n, uint32_t *v) {
    *v = 0;
    for (unsigned i = 0; i < n; i++) {
        uint8_t b; if (!next_byte(im,pc,end,&b)) return 0;
        *v |= (uint32_t)b << (8*i);
    }
    if (n == 1 && (*v & 128)) *v |= UINT32_C(0xffffff00);
    return 1;
}
static int execute(const Image *im, State *s, int recv) {
    size_t begin = recv ? im->recv : im->send;
    size_t end = recv ? im->end : im->recv, pc = begin;
    for (unsigned steps = 0; steps < 32; steps++) {
        uint8_t op, mr; int es = 0;
        if (!next_byte(im,&pc,end,&op)) return 0;
        if (op == 0x26) { es = 1; if (!next_byte(im,&pc,end,&op)) return 0; }
        if (op == 0xcf) return !es && pc == end; /* IRETD boundary, not its CPU semantics. */
        if (op == 0x90 && !es) continue;
        if ((op == 0x74 || op == 0x75) && !es) {
            uint8_t raw; if (!next_byte(im,&pc,end,&raw)) return 0;
            if ((op == 0x74) == !!s->zf) {
                long target = (long)pc + (raw < 128 ? raw : (int)raw - 256);
                if (target < (long)begin || target >= (long)end) return 0;
                pc = (size_t)target;
            }
            continue;
        }
        if (op != 0x89 && op != 0x8b && op != 0x88 && op != 0x8a &&
            op != 0x3b && op != 0x30 && op != 0xfe) return 0;
        if (!next_byte(im,&pc,end,&mr)) return 0;
        unsigned mod = mr >> 6, rg = (mr >> 3) & 7, rm = mr & 7;
        uint32_t addr = 0, disp = 0, value = 0;
        if (mod != 3) {
            if (rm == 4) return 0; /* SIB is outside these handler contracts. */
            if (mod == 0 && rm == 5) {
                if (!displacement(im,&pc,end,4,&addr)) return 0;
            } else {
                addr = s->r[rm];
                if (mod && !displacement(im,&pc,end,mod == 1 ? 1 : 4,&disp)) return 0;
                addr += disp;
            }
            if (!es) addr += UINT32_C(0x10000); /* Do not silently assume DS is flat. */
        }
        if (op == 0xfe) {
            if (mod != 3 || rg != 0 || es) return 0;
            uint8_t v = (uint8_t)(reg8(s,rm)+1); set8(s,rm,v); s->zf = v == 0;
        } else if (op == 0x30) {
            if (mod != 3 || es) return 0;
            uint8_t v = reg8(s,rm)^reg8(s,rg); set8(s,rm,v); s->zf = v == 0;
        } else if (op == 0x89) {
            if (mod != 3 || es) return 0;
            s->r[rm] = s->r[rg];
        } else if (op == 0x88) {
            if (mod == 3) set8(s,rm,reg8(s,rg));
            else {
                if (addr < RING || addr >= RING+256) return 0;
                s->ring[addr-RING] = reg8(s,rg); s->writes++; s->last_write = addr;
            }
        } else if (op == 0x8b || op == 0x3b || op == 0x8a) {
            if (mod == 3) value = op == 0x8a ? reg8(s,rm) : s->r[rm];
            else if (!read_mem(s,addr,op == 0x8a ? 1 : 4,&value)) return 0;
            if (op == 0x8b) s->r[rg] = value;
            else if (op == 0x8a) set8(s,rg,(uint8_t)value);
            else s->zf = s->r[rg] == value;
        }
    }
    return 0;
}
static int case_check(const Image *im, unsigned head, unsigned tail, unsigned pattern, int recv) {
    State s; memset(&s,0,sizeof(s));
    uint8_t payload = (uint8_t[]){0,1,255}[pattern];
    uint8_t before[256];
    for (unsigned i=0;i<256;i++) s.ring[i]=before[i]=(uint8_t)(i*73+pattern*31);
    s.other=(uint32_t)(ORIGIN+im->other);
    for (unsigned i=0;i<8;i++) s.r[i]=UINT32_C(0xcafe0000)+i*0x111;
    s.r[0]=UINT32_C(0xa55a0000)|payload;
    s.r[1]=RING+(recv?tail:head);
    uint32_t opponent=RING+(recv?head:tail);
    for (unsigned i=0;i<4;i++) s.frame[24+i]=(uint8_t)(opponent>>(8*i));
    uint8_t want_al=payload;
    unsigned want_cursor=recv?tail:head, want_writes=0;
    if (recv) {
        want_al=0;
        if (head!=tail) { want_al=before[tail]; want_cursor=(tail+1)&255; }
    } else if (((head+1)&255)!=tail) {
        before[head]=payload; want_cursor=(head+1)&255; want_writes=1;
    }
    transitions++;
    if (!execute(im,&s,recv) || s.r[1] != RING+want_cursor ||
        s.r[0] != (UINT32_C(0xa55a0000)|want_al) ||
        s.writes != want_writes || (want_writes && s.last_write != RING+head) ||
        memcmp(s.ring,before,sizeof(before))) {
        bad_head=head; bad_tail=tail; bad_pattern=pattern; return 0;
    }
    return 1;
}
static int exhaustive(const Image *im) {
    for (unsigned p=0;p<3;p++) for (unsigned h=0;h<256;h++) for (unsigned t=0;t<256;t++)
        for (int r=0;r<2;r++) if (!case_check(im,h,t,p,r)) return 0;
    return 1;
}
static size_t number(const char *s) {
    char *e; errno=0; unsigned long v=strtoul(s,&e,0);
    if (errno || !*s || *e || v>=65536) { fprintf(stderr,"bad offset\n"); exit(2); }
    return (size_t)v;
}
int main(int argc, char **argv) {
    if (argc!=6) { fprintf(stderr,"usage: ipc_byte_contract binary send recv end other_sp\n"); return 2; }
    Image im; memset(&im,0,sizeof(im));
    FILE *f=fopen(argv[1],"rb"); if (!f) return 2;
    im.size=fread(im.code,1,sizeof(im.code),f); int extra=fgetc(f),err=ferror(f); fclose(f);
    if (extra!=EOF || err) return 2;
    im.send=number(argv[2]); im.recv=number(argv[3]); im.end=number(argv[4]); im.other=number(argv[5]);
    if (!(im.send<im.recv && im.recv<im.end && im.end<=im.size && im.other+4<=im.size)) return 2;
    if (!exhaustive(&im)) {
        fprintf(stderr,"counterexample: head=%u tail=%u pattern=%u\n",bad_head,bad_tail,bad_pattern); return 1;
    }
    uint64_t valid=transitions;
    /* Valid subset mutations: branch sense, cursor, payload register and
     * saved-frame displacement. Find them structurally, not by fixed offsets. */
    unsigned mutations=0;
    for (size_t pc=im.send;pc+1<im.end;pc++) {
        uint8_t old=im.code[pc], replacement=old;
        if (old==0x74) replacement=0x75;
        else if ((old==0xc1 || old==0xc2) && pc>im.send && im.code[pc-1]==0xfe)
            replacement=old==0xc1?0xc2:0xc1;
        else if (old==0x01 && im.code[pc-1]==0x88) replacement=0x11;
        else if (old==0x18 && pc>im.send+1 && im.code[pc-2]==0x3b) replacement=0x14;
        if (replacement==old) continue;
        im.code[pc]=replacement;
        if (exhaustive(&im)) { fprintf(stderr,"undetected mutation at %zu\n",pc); return 1; }
        im.code[pc]=old; mutations++;
    }
    if (mutations!=7) { fprintf(stderr,"expected seven recognized mutation sites, got %u\n",mutations); return 1; }
    printf("{\"valid_transitions\":%llu,\"semantic_mutants_detected\":%u,\"native_x86_execution\":false}\n",
           (unsigned long long)valid,mutations);
    return 0;
}
