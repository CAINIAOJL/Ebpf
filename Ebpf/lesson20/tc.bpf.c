#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//#include <linux/if_ether.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
/*
0x0800：IP 协议（Internet Protocol），即 IPv4。
0x86DD：IPv6 协议。
0x0806：ARP 协议（Address Resolution Protocol）。
0x8137：Novell IPX 协议。
*/

/*
//#if __UAPI_DEF_ETHHDR
//struct ethhdr {
	//unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	//unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	//__be16		h_proto;		/* packet type ID field	*/
//} __attribute__((packed));
//#endif
//*/

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {
    void* data_end = (void *)(__u64)ctx->data_end;
    void* data = (void*)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    //
    if(ctx->protocol != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    l2 = data;
    if((void *)(l2 + 1) > data_end) {
        return TC_ACT_OK;
    }

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end) {
        return TC_ACT_OK;
    }

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";