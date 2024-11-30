#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
IPv4: 0x0800

ARP:0x0806

PPPoE:0x8864

802.1Q tag: 0x8100

IPV6: 0x86DD

MPLS Label:0x8847
*/
/*
#define  ETH_P_IP 0x0800 //IP协议
#define  ETH_P_ARP 0x0806  //地址解析协议(Address Resolution Protocol)
#define  ETH_P_RARP 0x8035  //返向地址解析协议(Reverse Address Resolution Protocol)
#define  ETH_P_IPV6 0x86DD  //IPV6协议

*/

// ethhdr 以太网帧的头部
#define ETH_P_IP 0x0800 

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

static bool is_tcp(struct ethhdr *eth, void *data_end) {
    if((void*)(eth + 1) > data_end) {
        return false;
    }

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return false;
    }
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if((void*)(ip + 1) > data_end) {
        return false;
    }

    if(ip->protocol != IPPROTO_TCP) {
        return false;
    }

    return true;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if(!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }

    /*
    struct iphdr *ip = (struct iphdr *)(eth + 1);是通过跳过支架头部来获取IP头部的起始地址。
eth + 1相当于((char *)eth + sizeof(struct ethhdr))，是一种简洁且类型安全的书写方法。
    */
    struct iphdr *ip = (struct iphdr *)(eth + 1); //(struct iphdr *)(eth + 1) = ((char *)eth + sizeof(struct ethhdr))
    int ip_hdr_len = ip->ihl * 4;
    //一般为20个字节，但有选项时可能会更长
    if(ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    if((void*)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (struct tcphdr*)((unsigned char *)ip + ip_hdr_len);

    if((void*)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    const int tcp_header_bytes = 32;

    if((void*)tcp + tcp_header_bytes > data_end) {
        return XDP_PASS;
    }

    void *ringbuf_space = bpf_ringbuf_reserve(&rb, tcp_header_bytes, 0);
    if(!ringbuf_space) {
        return XDP_PASS;
    }

    for(int i = 0; i < tcp_header_bytes; i++) {
        unsigned char byte = *((unsigned char *)tcp + i);
        ((unsigned char *)ringbuf_space)[i] = byte;
    }

    bpf_ringbuf_submit(ringbuf_space, 0);

    bpf_printk("Captured TCP header (%d bytes)", tcp_header_bytes);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
/*
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

// Define the ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB buffer
} rb SEC(".maps");

// Helper function to check if the packet is TCP
static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // Ensure Ethernet header is within bounds
    if ((void *)(eth + 1) > data_end)
        return false;

    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Ensure IP header is within bounds
    if ((void *)(ip + 1) > data_end)
        return false;

    // Check if the protocol is TCP
    if (ip->protocol != IPPROTO_TCP)
        return false;

    return true;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    // Pointers to packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;

    // Check if the packet is a TCP packet
    if (!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }

    // Cast to IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Calculate IP header length
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    // Ensure IP header is within packet bounds
    if ((void *)ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    // Parse TCP header
    struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);

    // Ensure TCP header is within packet bounds
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // Define the number of bytes you want to capture from the TCP header
    // Typically, the TCP header is 20 bytes, but with options, it can be longer
    // Here, we'll capture the first 32 bytes to include possible options
    const int tcp_header_bytes = 32;

    // Ensure that the desired number of bytes does not exceed packet bounds
    if ((void *)tcp + tcp_header_bytes > data_end) {
        return XDP_PASS;
    }

    // Reserve space in the ring buffer
    void *ringbuf_space = bpf_ringbuf_reserve(&rb, tcp_header_bytes, 0);
    if (!ringbuf_space) {
        return XDP_PASS;  // If reservation fails, skip processing
    }

    // Copy the TCP header bytes into the ring buffer
    // Using a loop to ensure compliance with eBPF verifier
    for (int i = 0; i < tcp_header_bytes; i++) {
        // Accessing each byte safely within bounds
        unsigned char byte = *((unsigned char *)tcp + i);
        ((unsigned char *)ringbuf_space)[i] = byte;
    }

    // Submit the data to the ring buffer
    bpf_ringbuf_submit(ringbuf_space, 0);

    // Optional: Print a debug message (will appear in kernel logs)
    bpf_printk("Captured TCP header (%d bytes)", tcp_header_bytes);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
*/