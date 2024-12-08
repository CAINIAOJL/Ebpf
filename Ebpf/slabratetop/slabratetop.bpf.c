#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include "slabratetop.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

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
    const char *name = cachep->name;
    bpf_probe_read_kernel(&info.name, sizeof(info.name), name);
    struct val_t *valp, zero = {};
    valp = bpf_map_lookup_or_try_init(&counts, &info, &zero);
    if(valp) {
        valp->count++;
        valp->size += cachep->size;
    }
    return 0;
}

SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(kprobe_kmem_cache_alloc) {
    return kprobe__kmem_cache_alloc(ctx);
}
