#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include "tcptrace.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

//#include <sys/socket.h>
//#include <sys/socket.h>


#define AF_INET 2
#define AF_INET6 10

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv4_tuple_t);
    __type(value, struct pid_comm_t);
} tuple_ipv4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv6_tuple_t);
    __type(value, struct pid_comm_t);
} tuple_ipv6_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct sock*);
}connectsock SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb_ipv6 SEC(".maps");

static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp) {
    u32 net_ns_inum = 0;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    struct inet_sock *sockp = (struct inet_sock *)skp;
    u16 sport = sockp->inet_sport;
    u16 dport = skp->__sk_common.skc_dport;

#ifdef CONFIG_NET_NS
    net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
#endif

    tuple->saddr = saddr;
    tuple->daddr = daddr;
    tuple->sport = sport;
    tuple->dport = dport;
    tuple->netns = net_ns_inum;

    if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
        return 0;
    }
    return 1;
}

static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp) {
    u32 net_ns_inum = 0;
    unsigned __int128 saddr = 0, daddr = 0;
    struct inet_sock *sockp = (struct inet_sock *)skp;
    u16 sport = sockp->inet_sport;
    u16 dport = skp->__sk_common.skc_dport;

#ifdef CONFIG_NET_NS
    net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
#endif

    bpf_probe_read_kernel(&saddr, sizeof(saddr), &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    tuple->saddr = saddr;
    tuple->daddr = daddr;
    tuple->sport = sport;
    tuple->dport = dport;
    tuple->netns = net_ns_inum;

    if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
        return 0;
    }
    return 1;
}

static bool check_family(struct sock *sk, u16 expected_family) {
    u64 zero = 0;
    u16 family = sk->__sk_common.skc_family;
    return family == expected_family;
}

//connect 入口
int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk) {
    //过滤操作
    //。。。。。。
    u64 pid = bpf_get_current_pid_tgid();

    u16 family =sk->__sk_common.skc_family;
    //更新
    bpf_map_update_elem(&connectsock, &pid, &sk, BPF_ANY);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);

    u64 pid = bpf_get_current_pid_tgid();
    struct sock ** skpp = bpf_map_lookup_elem(&connectsock, &pid);
    if (skpp == NULL) {
        return 0;
    }
    bpf_map_delete_elem(&connectsock, &pid);

    if(ret != 0) {
        return 0;
    }

    struct sock *skp = *skpp;
    struct ipv4_tuple_t tuple = {};
    if(!read_ipv4_tuple(&tuple, skp)) {
        return 0;
    }

    struct pid_comm_t p = {};
    p.pid = pid;
    bpf_get_current_comm(&p.comm, sizeof(p.comm));

    bpf_map_update_elem(&tuple_ipv4_map, &tuple, &p, BPF_ANY);

    return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk) { 
    //过滤操作
    //。。。。。。

    u64 pid = bpf_get_current_pid_tgid();

    u16 family =sk->__sk_common.skc_family;

    bpf_map_update_elem(&connectsock, &pid, &sk, BPF_ANY);
    return 0;
}

int trace_connect_v6_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);

    u64 pid = bpf_get_current_pid_tgid();
    struct sock ** skpp = bpf_map_lookup_elem(&connectsock, &pid);
    if (skpp == NULL) {
        return 0;
    }
    bpf_map_delete_elem(&connectsock, &pid);

    if(ret != 0) {
        return 0;
    }

    struct sock *skp = *skpp;
    struct ipv6_tuple_t tuple = {};
    if(!read_ipv6_tuple(&tuple, skp)) {
        return 0;
    }

    struct pid_comm_t p = {};
    p.pid = pid;
    bpf_get_current_comm(&p.comm, sizeof(p.comm));

    bpf_map_update_elem(&tuple_ipv6_map, &tuple, &p, BPF_ANY);

    return 0;
}
//追踪状态改变，每次状态改变，都会调用这个函数
int trace_tcp_set_state_entry(struct pt_regs *ctx, struct sock* sk, int state) {
    if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
        return 0;
    }
    u16 family = sk->__sk_common.skc_family;

    u8 ipver = 0;
    if(check_family(sk, AF_INET)) {
        ipver = 4;
        struct ipv4_tuple_t tuple = {};
        if(!read_ipv4_tuple(&tuple, sk)) {
            return 0;
        }

        if(state == TCP_CLOSE) {
            bpf_map_delete_elem(&tuple_ipv4_map, &tuple);
            return 0;
        }

        struct pid_comm_t *p;
        p = bpf_map_lookup_elem(&tuple_ipv4_map, &tuple);
        if (p == 0) {
            return 0;
        }
        //ipv4事件
        struct tcp_ipv4_event_t *ipv4_event;
        //使用ringbuffer保存数据
        ipv4_event = bpf_ringbuf_reserve(&rb_ipv4, sizeof(*ipv4_event), 0);
        if(!ipv4_event) {
            return 0;
        }
        ipv4_event->pid = p->pid >> 32;
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            ipv4_event->comm[i] = p->comm[i];
        }
        ipv4_event->ts_ns = bpf_ktime_get_ns(); //时间戳
        ipv4_event->saddr = tuple.saddr;
        ipv4_event->daddr = tuple.daddr;
        ipv4_event->sport = bpf_ntohs(tuple.sport);
        ipv4_event->dport = bpf_ntohs(tuple.dport);
        ipv4_event->netns = tuple.netns;
        ipv4_event->ip = ipver;
        ipv4_event->type = TCP_EVENT_TYPE_CONNECT;

        bpf_ringbuf_output(&rb_ipv4, &ipv4_event, sizeof(*ipv4_event), 0);
        bpf_map_delete_elem(&tuple_ipv4_map, &tuple);
    } else if (check_family(sk, AF_INET6)) {
        ipver = 6;
        struct ipv6_tuple_t tuple = {};
        if(!read_ipv6_tuple(&tuple, sk)) {
            return 0;
        }

        if(state == TCP_CLOSE) {
            bpf_map_delete_elem(&tuple_ipv6_map, &tuple);
            return 0;
        }

        struct pid_comm_t *p;
        p = bpf_map_lookup_elem(&tuple_ipv6_map, &tuple);
        if (p == 0) {
            return 0;
        }
        //ipv6事件
        struct tcp_ipv6_event_t *ipv6_event;
        ipv6_event = bpf_ringbuf_reserve(&rb_ipv6, sizeof(*ipv6_event), 0);
        if(!ipv6_event) {
            return 0;
        }
        for(int i = 0; i < TASK_COMM_LEN; i++) {
            ipv6_event->comm[i] = p->comm[i];
        }
        ipv6_event->ts_ns = bpf_ktime_get_ns(); //时间戳
        ipv6_event->saddr = tuple.saddr;
        ipv6_event->daddr = tuple.daddr;
        ipv6_event->sport = bpf_ntohs(tuple.sport);
        ipv6_event->dport = bpf_ntohs(tuple.dport);
        ipv6_event->netns = tuple.netns;
        ipv6_event->ip = ipver;
        ipv6_event->type = TCP_EVENT_TYPE_CONNECT;
        ipv6_event->pid = p->pid >> 32;

        bpf_ringbuf_output(&rb_ipv6, &ipv6_event, sizeof(*ipv6_event), 0);
        bpf_map_delete_elem(&tuple_ipv6_map, &tuple);
    }

    return 0;
}

int trace_close_entry(struct pt_regs *ctx, struct sock *sk) {
    //过滤操作
    //。。。。。。

    u64 pid = bpf_get_current_pid_tgid();

    u16 family =sk->__sk_common.skc_family;

    u8 oldstate = sk->__sk_common.skc_state;
    //close tcp事件
    if(oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
        return 0;
    }

    u8 ipver = 0;
    if(check_family(sk, AF_INET)) {
        ipver = 4;
        struct ipv4_tuple_t tuple = {};
        if(!read_ipv4_tuple(&tuple, sk)) {
            return 0;
        }
        struct tcp_ipv4_event_t *ipv4_event;
        ipv4_event = bpf_ringbuf_reserve(&rb_ipv4, sizeof(*ipv4_event), 0);
        if(!ipv4_event) {
            return 0;
        }
        ipv4_event->ts_ns = bpf_ktime_get_ns(); //时间戳
        ipv4_event->saddr = tuple.saddr;
        ipv4_event->daddr = tuple.daddr;
        ipv4_event->sport = bpf_ntohs(tuple.sport);
        ipv4_event->dport = bpf_ntohs(tuple.dport);
        ipv4_event->netns = tuple.netns;
        ipv4_event->ip = ipver;
        ipv4_event->type = TCP_EVENT_TYPE_CLOSE;
        ipv4_event->pid = pid >> 32;
        bpf_get_current_comm(&ipv4_event->comm, sizeof(ipv4_event->comm));

        bpf_ringbuf_output(&rb_ipv4, &ipv4_event, sizeof(*ipv4_event), 0);
        
    } else if (check_family(sk, AF_INET6)) {
            ipver = 6;
            struct ipv6_tuple_t tuple = {};
            if(!read_ipv6_tuple(&tuple, sk)) {
                return 0;
            }
            struct tcp_ipv6_event_t *ipv6_event;
            ipv6_event = bpf_ringbuf_reserve(&rb_ipv6, sizeof(ipv6_event), 0);
            if(!ipv6_event) {
                return 0;
            }
            ipv6_event->ts_ns = bpf_ktime_get_ns(); //时间戳
            ipv6_event->saddr = tuple.saddr;
            ipv6_event->daddr = tuple.daddr;
            ipv6_event->sport = bpf_ntohs(tuple.sport);
            ipv6_event->dport = bpf_ntohs(tuple.dport);
            ipv6_event->netns = tuple.netns;
            ipv6_event->ip = ipver;
            ipv6_event->type = TCP_EVENT_TYPE_CLOSE;
            ipv6_event->pid = pid >> 32;
            bpf_get_current_comm(&ipv6_event->comm, sizeof(ipv6_event->comm));

            bpf_ringbuf_output(&rb_ipv6, &ipv6_event, sizeof(*ipv6_event), 0);
    }
    return 0;
}

int trace_accept_return(struct pt_regs *ctx) {
    //过滤操作
    //。。。。。。

    struct sock *newsock = (struct sock*)PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();
    
    if(newsock == NULL) {
        return 0;
    }
    u32 net_ns_inum = 0;
    u8 ipver = 0;
    u16 lport = newsock->__sk_common.skc_num;
    u16 dport = newsock->__sk_common.skc_dport;

#ifdef CONFIG_NET_NS
    net_ns_inum = newsock->__sk_common.skc_net.net->ns.inum;
#endif

    u16 family = newsock->__sk_common.skc_family;

    if(check_family(newsock, AF_INET)) {
        ipver = 4;
        struct tcp_ipv4_event_t *ipv4_event;
        ipv4_event = bpf_ringbuf_reserve(&rb_ipv4, sizeof(*ipv4_event), 0);
        
        ipv4_event->ts_ns = bpf_ktime_get_ns(); //时间戳
        ipv4_event->type = TCP_EVENT_TYPE_ACCEPT;
        ipv4_event->pid = pid >> 32;
        ipv4_event->ip = ipver;
        ipv4_event->netns = net_ns_inum;

        ipv4_event->saddr = newsock->__sk_common.skc_rcv_saddr;
        ipv4_event->daddr = newsock->__sk_common.skc_daddr;

        ipv4_event->sport = lport;
        ipv4_event->daddr = bpf_ntohs(dport);

        bpf_get_current_comm(&ipv4_event->comm, sizeof(ipv4_event->comm));

        if(ipv4_event->saddr == 0 || ipv4_event->daddr == 0 || ipv4_event->sport == 0 || ipv4_event->dport == 0) {
            return 0;
        }

        bpf_ringbuf_output(&rb_ipv4, &ipv4_event, sizeof(*ipv4_event), 0);
    } else if (check_family(newsock, AF_INET6)) {
            ipver = 6;
            struct tcp_ipv6_event_t *ipv6_event;
            ipv6_event = bpf_ringbuf_reserve(&rb_ipv6, sizeof(*ipv6_event), 0);
            if(!ipv6_event) {
                return 0;
            }
            ipv6_event->ts_ns = bpf_ktime_get_ns(); //时间戳
            ipv6_event->type = TCP_EVENT_TYPE_ACCEPT;
            ipv6_event->pid = pid >> 32;
            ipv6_event->ip = ipver;
            ipv6_event->netns = net_ns_inum;

            bpf_probe_read_kernel(&ipv6_event->saddr, sizeof(ipv6_event->saddr), newsock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(&ipv6_event->daddr, sizeof(ipv6_event->daddr), newsock->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

            ipv6_event->sport = lport;
            ipv6_event->daddr = bpf_ntohs(dport);

            bpf_get_current_comm(&ipv6_event->comm, sizeof(ipv6_event->comm));

            if(ipv6_event->saddr == 0 || ipv6_event->daddr == 0 || ipv6_event->sport == 0 || ipv6_event->dport == 0) {
                return 0;
            }

            bpf_ringbuf_output(&rb_ipv6, &ipv6_event, sizeof(*ipv6_event), 0);
    }
}
//int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect_entry, struct sock *sk) {
    return trace_connect_v4_entry(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(krpobe_tcp_v4_connect_return) {
    return trace_connect_v4_return(ctx);
}

//static int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect_entry, struct sock *sk) {
    return trace_connect_v6_entry(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kprobe_tcp_v6_connect_return) {
    return trace_connect_v6_return(ctx);
}

//static inline void tcp_set_state(struct sock *sk, int state)
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(kprobe_tcp_set_state_entry, struct sock *sock, int state) {
    return trace_tcp_set_state_entry(ctx, sock, state);
}

//void tcp_close(struct sock *sk, long timeout)
SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close_entry, struct sock *sk) {
    return trace_close_entry(ctx, sk);
}

//struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kprobe_inet_csk_accept_return) {
    return trace_accept_return(ctx);
}
