#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "map.bpf.h"
#include "slabratetop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static inline void *slab_address(const struct slab *slab) {
    return NULL;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct info_t);
    __type(value, struct val_t);
} counts SEC(".maps");


int kprobe__kmem_cache_alloc(struct pt_regs *ctx) {
    struct kmem_cache *cachep = (struct kmem_cache *)PT_REGS_PARM1(ctx);
    struct info_t info = {};
    //const char *name = BPF_CORE_READ(cachep, name);
    bpf_probe_read_kernel(&info.name, sizeof(info.name), &cachep->name);
    //memcpy(info.name, name, sizeof(info.name));
    struct val_t *valp, zero = {};
    valp = bpf_map_lookup_or_try_init(&counts, &info, &zero);
    unsigned int sz = BPF_CORE_READ(cachep, size);
    //原子操作
    __sync_fetch_and_add(&valp->count, 1);
    __sync_fetch_and_add(&valp->size, sz);
    return 0;
}

SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(kprobe_kmem_cache_alloc) {
    return kprobe__kmem_cache_alloc(ctx);
}
