#define __TARGET_ARCH_x86
#include "bpf_sockmap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg) {
    //根据业务修改ip地址判断条件
    if(msg->remote_ip4 != LOCALHOST_IPV4 || msg->local_ip4 != LOCALHOST_IPV4) {
        return SK_PASS;
    }

    struct sock_key key = {
        .saddr = msg->remote_ip4,
        .daddr = msg->local_ip4,
        .sport = msg->remote_port,
        .dport = bpf_ntohl(msg->local_port),
        .family = msg->family,
    };

    return bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
}