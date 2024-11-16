/*#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);        // 定义一个 Array 类型的 BPF Map
    __uint(max_entries, 1);                  // 仅包含一个计数器
    __type(key, u32);
    __type(value, u64);
} syscall_count_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter")
int count_sys_enter(void *ctx) {
    u32 key = 0;
    u64 *value;

    // 获取计数器的指针
    value = bpf_map_lookup_elem(&syscall_count_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);      // 增加系统调用计数
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";       // 指定程序许可证

//clang -O2 -g -target bpf -c trace.c -o trace.o
//bpftool gen skeleton trace.o > trace.skel.h
*/

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter")
int count_sys_enter(void *ctx) {
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&syscall_count_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
