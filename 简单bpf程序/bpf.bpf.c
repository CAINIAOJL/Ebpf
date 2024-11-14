/*
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
*/

// filename: trace_bpf.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h> 
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter")
int bpf_prog(void *ctx) {
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&syscall_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";


//clang -O2 -target bpf -g -D__TARGET_ARCH_x86 -c trace_bpf.c -o trace_bpf.o
