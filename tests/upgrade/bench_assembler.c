/* SPDX-License-Identifier: BSD-3-Clause
 * Measure the existing assembly passes, excluding CLI/filesystem startup.
 * Compile twice with BASM_SOURCE pointing to original and updated sources.
 */
#define main basm_cli_main
#include BASM_SOURCE
#undef main
#include <time.h>
static volatile uint64_t bench_observer;
static uint64_t now(clockid_t id) {
    struct timespec t;
    if (clock_gettime(id,&t)) exit(2);
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static void iteration(char *text) {
    g_pass=1; assemble(text); long size=g_off;
    g_pass=2; assemble(text);
    if (size!=g_off) exit(3);
    bench_observer+=(uint64_t)g_off+g_out[0]+(g_off?g_out[g_off-1]:0);
}
int main(int argc,char **argv) {
    if (argc!=3) return 2;
    int loops=atoi(argv[1]); if (loops<1 || loops>1000000) return 2;
    FILE *f=fopen(argv[2],"rb"); if (!f) return 2;
    char *text=calloc(1024*1024+1,1); if (!text) return 2;
    size_t n=fread(text,1,1024*1024,f); if (ferror(f)||!feof(f)) return 2;
    text[n]=0; fclose(f); g_file=argv[2];
    for (int i=0;i<3;i++) iteration(text);
    uint64_t wall=now(CLOCK_MONOTONIC),cpu=now(CLOCK_THREAD_CPUTIME_ID);
    for (int i=0;i<loops;i++) iteration(text);
    cpu=now(CLOCK_THREAD_CPUTIME_ID)-cpu; wall=now(CLOCK_MONOTONIC)-wall;
    uint32_t hash=UINT32_C(2166136261);
    for (long i=0;i<g_off;i++) hash=(hash^g_out[i])*UINT32_C(16777619);
    printf("{\"loops\":%d,\"wall_ns\":%llu,\"cpu_ns\":%llu,\"bytes\":%ld,\"output_fnv32\":%u}\n",
        loops,(unsigned long long)wall,(unsigned long long)cpu,g_off,hash);
    free(text); return 0;
}
