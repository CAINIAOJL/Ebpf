#ifndef __MAPS_BPF_H__
#define __MAPS_BPF_H__

#include <bpf/bpf_helpers.h>
#include <asm-generic/errno.h>

static __always_inline void*
bpf_map_lookup_or_try_init(void* map, const void* key, const void* init) {
    void* val;
    long err;

    val = bpf_map_lookup_elem(map, key);
    if(val) {
        return val;
    }
    err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);

    if(err && err != -EEXIST) {
        return 0;
    }

    return bpf_map_lookup_elem(map, key);
}


#endif






