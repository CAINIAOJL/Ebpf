#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include "tcptop.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(value, struct sock *);
    __type(key, u32);
} sock_store SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv4_key_t);
    __type(value, u64);
}ipv4_send_bytes SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv4_key_t);
    __type(value, u64);
}ipv4_recv_bytes SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv6_key_t);
    __type(value, u64);
}ipv6_send_bytes SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv6_key_t);
    __type(value, u64);
}ipv6_recv_bytes SEC(".maps");

const volatile int target_pid = 0;

static  __always_inline bool __filter (u32 pid, u32 target) {
    return pid == target;
}

static int tcp_sendstat(int size) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if(!__filter(pid, target_pid)) {
        return 0;
    }

    struct sock ** sockpp = bpf_map_lookup_elem(&sock_store, &pid);
    if(sockpp == 0) {
        return 0;
    }

    struct sock * sockp = *sockpp;
    u16 dport = 0;
    u16 family = 0;

    bpf_probe_read_kernel(&family, sizeof(family), &sockp->__sk_common.skc_family);
    //family = BPF_CORE_READ(sockp, __sk_common.skc_family);

    if(family == AF_INET) {
        //ipv4
        struct ipv4_key_t ipv4_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr), &sockp->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&ipv4_key.daddr, sizeof(ipv4_key.daddr), &sockp->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&dport, sizeof(dport), &sockp->__sk_common.skc_dport);
        bpf_probe_read_kernel(&ipv4_key.lport, sizeof(ipv4_key.lport), &sockp->__sk_common.skc_num);

        ipv4_key.dport = bpf_ntohs(dport);

        u64 send_bytes = bpf_map_lookup_elem(&ipv4_send_bytes, &ipv4_key) + size;
        bpf_map_elem_update(&ipv4_send_bytes, &ipv4_key, &send_bytes, BPF_ANY);
    } else if(family == AF_INET6) {
        //ipv6
        struct ipv4_key_t ipv6_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr), &sockp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr), &sockp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&dport, sizeof(dport), &sockp->__sk_common.skc_dport);
        bpf_probe_read_kernel(&ipv6_key.lport, sizeof(ipv6_key.lport), &sockp->__sk_common.skc_num);

        ipv6_key.dport = bpf_ntohs(dport);

        u64 send_bytes = bpf_map_lookup_elem(&ipv6_send_bytes, &ipv6_key) + size;
        bpf_map_elem_update(&ipv6_send_bytes, &ipv6_key, &send_bytes, BPF_ANY);
    
    }   

    return 0;
}

int tcp_send_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(!filter(pid, target_pid)) {
        return 0;
    }
    /*这里使用位运算符 & 来提取返回值中的低 32 位。因为 BPF 的返回值是 64 位，所以将其与 32 位的掩码 0xffffffff 进行与运算，可以有效提取出线程组 ID (TGID)。*/
    u32 tgid = bpf_get_current_pid_tgid() & 0xffffffff;
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    bpf_map_update_elem(&sock_store, &pid, &sk, BPF_ANY);
    return 0;
}

int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if(!filter(pid, target_pid)) {
        return 0;
    }
    struct sock * sk = (struct sock *)PT_REGS_PARM1(ctx);
    int copied = PT_REGS_PARM2(ctx);
    u16 dport = 0;
    u16 family = 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u64 *val, zero = 0;

    if(copied <= 0) {
        return 0;
    }

    if (family == AF_INET) {
        //ipv4
        struct ipv4_key_t ipv4_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&ipv4_key.daddr, sizeof(ipv4_key.daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read_kernel(&ipv4_key.lport, sizeof(ipv4_key.lport), &sk->__sk_common.skc_num);

        ipv4_key.dport = bpf_ntohs(dport);

        val = bpf_map_lookup_elem(&ipv4_recv_bytes, &ipv4_key);
        if (val) {
            *val += copied;
        } else {
            val = &zero;
        }
        bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, val, BPF_ANY);
    } else if (family == AF_INET6) {
        //ipv6
        struct ipv6_key_t ipv6_key = {
            .pid = pid
        };
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read_kernel(&ipv6_key.lport, sizeof(ipv6_key.lport), &sk->__sk_common.skc_num);

        ipv6_key.dport = bpf_ntohs(dport);

        val = bpf_map_lookup_elem(&ipv6_recv_bytes, &ipv6_key);
        if (val) {
            *val += copied;
        } else {
            val = &zero;
        }
        bpf_map_update_elem(&ipv6_send_bytes, &ipv6_key, val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg_entry, struct sock *sk) {
    return tcp_send_entry(ctx, sk);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KRETPROBE(kprobe_tcp_sendmsg_return) {
    int size = PT_REGS_RC(ctx);
    if(size > 0) {
        return tcp_sendstat(size);
    } else {
        return 0;
    }
}

SEC("kprobe/tcp_sendpage")
int BPF_KPROBE(kprobe_tcp_sendpage_entry, struct sock *sk) {
    return tcp_send_entry(ctx, sk);
}

SEC("probe/tcp_sendpage")
int BPF_KRETPROBE(kprobe_tcp_sendpage_return) {
    ssize_t size = PT_REGS_RC(ctx);
    if(size > 0) {
        return tcp_sendstat(size);
    } else {
        return 0;
    }
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kprobe_tcp_cleanup_rbuf_entry) {
    return kprobe_tcp_cleanup_rbuf(ctx);
}


