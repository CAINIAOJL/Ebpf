#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// 127.0.0.1
#define LOCALHOST_IPV4 16777343 // 0x7F000001 in network byte order
struct sock_key {
    __u32 saddr;
    __u32 sport;
    __u32 daddr;
    __u32 dport;
    __u32 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535); //max fd number 
    __type(key, struct sock_key);
    __type(value, int);
}sock_ops_map SEC(".maps");