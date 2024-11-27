#define __TARGET_ARCH_x86
#include "bpf_sockmap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *skops) {
    u32 family, op;
    family = skops->family;
    op = skops->op;
    if(op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }
    //实际业务中可以修改，这里使用本地ip:127.0.0.1地址进行测试
    if(skops->remote_ip4 != LOCALHOST_IPV4 || skops->local_ip4 != LOCALHOST_IPV4) {
        return BPF_OK;
    }

    struct sock_key key = {
        .daddr = skops->remote_ip4,
        .dport = skops->remote_port,
        .saddr = skops->local_ip4,
        .sport = bpf_htonl(skops->local_port),
        .family = family,
    };
    //debug
    bpf_printk(">> new connection : OP: %d, PROT : %d -----> %d\n", op, bpf_ntohl(key.sport));

    bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);

    return BPF_OK;
}