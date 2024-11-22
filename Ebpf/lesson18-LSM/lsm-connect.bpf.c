#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 16843009; // 1.1.1.1

SEC("Ism/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
    if(ret != 0) {
        return ret;
    }

    if(address->sa_family != AF_INET) {
        return 0;
    }
    struct sockaddr_in *addr = (struct sockaddr_in *)(address);
    __u32 dest = addr->sin_addr.s_addr;
    
    bpf_printk("lsm found connect to %d", dest);

    if(dest == blockme) {
        bpf_printk("lsm blocked connect to %d", dest);
        return -EPERM;
    }
    return 0;
}