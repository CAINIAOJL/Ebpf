#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "cachestat.h"
#include "map.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, u32);
} counters SEC(".maps");

static int __do_count(void *ctx, u32 nf) {
    struct key_t *key;
    key->nf = nf;
    u32 zero = 0;
    u32 *val = bpf_map_lookup_or_try_init(&counters, key, &zero);
    __sync_fetch_and_add(val, 1); //原子操作
    return 0;
}

int do_count_apcl(struct pt_regs *ctx) {
    return __do_count(ctx, NF_APCL);
}

int do_count_mpa(struct pt_regs *ctx) {
    return __do_count(ctx, NF_MPA);
}

int do_count_mbd(struct pt_regs *ctx) {
    return __do_count(ctx, NF_MBD);
}

int do_count_apd(struct pt_regs *ctx) {
    return __do_count(ctx, NF_APD);
}

int do_count_apd_tp(struct pt_regs *ctx) {
    return __do_count(ctx, NF_APD);
}

SEC("kprobe/filemap_add_folio")
int BPF_KPROBE(kprobe_filemap_add_folio) {
    return do_count_apcl(ctx);
}

SEC("kprobe/add_to_page_cache_lru")
int BPF_KPROBE(kprobe_add_to_page_cache_lru) {
    return do_count_apcl(ctx);
}

SEC("kprobe/folio_mark_accessed")
int BPF_KPROBE(kprobe_folio_mark_accessed) {
    return do_count_mpa(ctx);
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(kprobe_mark_page_accessed) {
    return do_count_mpa(ctx);
}
/*# Function account_page_dirtied() is changed to folio_account_dirtied() in 5.15.
# Both folio_account_dirtied() and account_page_dirtied() are
# static functions and they may be gone during compilation and this may
# introduce some inaccuracy, use tracepoint writeback_dirty_{page,folio},
# instead when attaching kprobe fails, and report the running
# error in time.*/

SEC("kprobe/folio_account_dirtied")
int BPF_KPROBE(kprobe_folio_account_dirtied) {
    return do_count_apd(ctx);
}

SEC("kprobe/account_page_dirtied")
int BPF_KPROBE(kprobe_account_page_dirtied) {
    return do_count_apd(ctx);
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(kprobe_mark_buffer_dirty) {
    return do_count_mbd(ctx);
}
//不知道如何处理
SEC("tp/writeback/writeback_dirty_folio")
int do_count_apd_folio(struct pt_regs *ctx) {
    return do_count_apd_tp(ctx);
}

SEC("tp/writeback/writeback_dirty_page")
int do_count_apd_page(struct pt_regs *ctx) {
    return do_count_apd_tp(ctx);
}