//#include "vmlinux.h"
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>
//#include "sockfilter.h"

/*#include <stddef.h>
#include <linux/bpf.h> // bpf_map_def
#include <linux/if_ether.h> // ETH_P_IP
#include <linux/ip.h> // struct iphdr
#include <linux/socket.h> // struct sock
#include <linux/in.h> // struct in_addr
//#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockfilter.h"

#define IP_MF 0x2000         //这个宏定义了“IP分片标志”（More Fragments），用于指示在IP数据包中是否还有后续分片。其值为0x2000，这个值在IP头部的“标志”字段中使用
#define IP_OFFSET 0x1FFF     //这个宏定义了IP数据包的偏移量掩码。它的作用是从IP头部获取分片的偏移量，值0x1FFF是二进制表示的掩码，用于提取分片的偏移值以确定数据包在原始数据流中的位置。
#define IP_TCP 6             //这个宏定义了TCP协议在IP头部中的协议号。IP协议头的“协议”字段用于标识上层协议类型，6表示该数据包使用的是TCP协议。
#define ETH_HLEN 14          //这个宏定义了以太网帧的头部长度，值为14字节。以太网头部包含目标MAC地址、源MAC地址和类型/长度字段，通常在数据包处理时需要了解这一长度值

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// uapi/linux/tcp.h
struct __tcphdr {
	__be16 source;     //该字段表示源端口，使用 16 位无符号整型，网络字节序（big-endian）表示，指明发送 TCP 数据包的应用程序的端口号
	__be16 dest;       //该字段表示目的端口，同样使用 16 位无符号整型，网络字节序表示，指明接收 TCP 数据包的应用程序的端口号。
	__be32 seq;        //该字段表示序列号，是一个 32 位无符号整型，代表 TCP 数据包的序列号，用于确保数据的顺序和完整性
	__be32 ack_seq;    //该字段表示确认序列号，是一个 32 位无符号整型，指明期望接收的下一个字节的序列号，用于确认对方已经发送的数据。
	__u16 res1: 4;     //该字段保留了 4 位，通常用于未来的扩展或特定的实现，当前未使用。
	__u16 doff: 4;     //该字段表示头部长度（Data Offset），使用 4 位保存，单位为 32 位字，一般用于指明 TCP 头部的长度，从而计算数据部分的开始位置。
	__u16 fin: 1;      //该字段是终止标志位（FIN），表示发送方希望终止连接。
	__u16 syn: 1;      //该字段是同步标志位（SYN），在建立连接时使用，用于初始化序列号。
	__u16 rst: 1;      //该字段是复位标志位（RST），用于重置连接。
	__u16 psh: 1;      //该字段是推送标志位（PSH），告知接收方应立即将数据传递给应用层。
	__u16 ack: 1;      //该字段是确认标志位（ACK），表示序列号字段中的确认序列号是有效的。
	__u16 urg: 1;      //该字段是紧急标志位（URG），指示紧急数据的存在。
	__u16 ece: 1;      //该字段是显式拥塞通知标志位（ECE），用于网络拥塞控制
	__u16 cwr: 1;      //该字段是拥塞窗口减小标志位（CWR），用于指示发送方减小拥塞窗口
	__be16 window;     //该字段表示窗口大小（Window Size），用于流量控制，指明发送方在当前时刻允许接收的数据量。
	__sum16 check;     //该字段是校验和（Checksum），用于检测 TCP 头部和数据部分的错误，以确保数据的完整性。
	__be16 urg_ptr;    //该字段是紧急指针（Urgent Pointer），指示紧急数据在数据部分的位置。
};

// 检查数据包是否为ipv4分片
static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff) {
    __u16 frag_off; //用于存储片偏移字段的值。
    /*这行代码使用bpf_skb_load_bytes函数从数据包中加载IPv4头部的片偏移字段（frag_off），并加载2个字节。nhoff是IPv4头部在数据包中的偏移量，offsetof(struct iphdr, frag_off)用于计算片偏移字段在IPv4头部中的偏移量。*/
    /*bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb) {
    struct so_event *e;
    __u8 verlen;
    __u16 proto;
    __u32 nhoff = ETH_HLEN;
	__u32 ip_proto = 0;
	__u32 tcp_hdr_len = 0;
	__u16 tlen;
	__u32 payload_offset = 0;
	__u32 payload_length = 0;
	__u8 hdr_len;

    bpf_skb_load_bytes(skb, 12, &proto, 2);
    //检查协议类型是否为IPv4
    proto = __bpf_ntohs(proto);
    if(proto != ETH_P_IP) {
        return 0;
    }

    //检查分片
    if(ip_is_fragment(skb, nhoff)) {
        return 0;
    }
    //获取IPv4头部长度
    //在IPv4头部中，头部长度字段的低四位（即长度的4字节数）表示头部的长度，而高四位则未被使用。
    //通过与0x0f进行位与操作，保留低4位的数据，舍弃高4位的数据。
    //这一行代码将提取的头部长度乘以4，因为头部长度的单位是以4字节为基数来表示的。
    bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
    hdr_len &= 0x0f;
    hdr_len *= 4; //一位四字节

    if(hdr_len < sizeof(struct iphdr)) {
        return 0;
    }

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);
    
    if(ip_proto != IPPROTO_TCP) {
        return 0;
    }

    tcp_hdr_len = nhoff + hdr_len;
    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
    //tot_len 表示整个 IP 数据报的长度，包括 IP 头部和 TCP 头部。
    //由于 TCP 头部长度可能大于 40 字节，所以需要先获取 TCP 头部长度，再计算 IP 数据报的长度。
    //获取 TCP 头部长度的方法是从 TCP 头部的“数据偏移”字段中获取。
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

    __u8 doff;
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff));
    doff &= 0xf0;
    doff >>= 4;
    doff *= 4; //一位四字节

    payload_offset = ETH_HLEN + hdr_len + doff;
    payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

    char line_buffer[7];
    if (payload_length < 7 || payload_offset < 0) {
        //加载HTTP请求行的前7个字节
        return 0;
    }
    bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
    bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
    if (    bpf_strncmp(line_buffer, 3, "GET") != 0 &&
            bpf_strncmp(line_buffer, 4, "POST") != 0 &&
            bpf_strncmp(line_buffer, 3, "PUT") != 0 &&
            bpf_strncmp(line_buffer, 6, "DELETE") != 0 &&
            bpf_strncmp(line_buffer, 4, "HTTP") != 0) 
    {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e) {
        return 0;
    }

    e->ip_proto = ip_proto;
    bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->ports), 4);
    e->pkt_type = skb->pkt_type;
    e->ifindex = skb->ifindex;
    e->payload_length = payload_length;
    bpf_skb_load_bytes(skb, payload_offset, e->payload, MAX_BUF_SIZE);

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
    bpf_ringbuf_submit(e, 0);
    
    return skb->len;
}

/*
在这段代码中，主要处理的是网络数据包的处理，特别关注于 TCP/IP 报文的头部信息。以下是各个头部信息的详细内容说明：

以太网头部 (Ethernet Header)：

ETH_HLEN：以太网头部的长度，通常为 14 字节。
包含的信息有：
源 MAC 地址（6 字节）
目的 MAC 地址（6 字节）
协议类型（2 字节，fields like proto 在代码中获取，判断是否为 IPv4）
IPv4 头部 (IP Header)：

由 struct iphdr 定义，头部长度通常包含在前四个字节中，通过低四位表示长度，单位为 4 字节。
协议（protocol）： 通过 ip_proto 获取，判断 UDP、TCP 等。
总长度（tot_len）：整个 IP 数据报的长度，包括 IP 头部和数据。
TCP 头部 (TCP Header)：

由 struct __tcphdr 定义，包括：
源端口（2 字节）
目的端口（2 字节）
序列号（4 字节）
确认号（4 字节）
数据偏移（doff，通常为 4 位，表示 TCP 头部长度，单位为 4 字节）。
TCP 头部中的数据偏移位用于计算 TCP 头部长度，通过位与操作和位右移获取实际的长度。
负载 (Payload)：

负载的计算非常关键，使用以下方法得出：
负载起始偏移：payload_offset，通过以太网头部长度、IPv4 头部长度和 TCP 头部长度来计算。
负载长度：payload_length，通过从 IP 头部的总长度中减去头部的长度获取。
HTTP 请求行 (HTTP Request Line)：

检查从负载中读取的前 7 个字节，判断是否为 HTTP 请求（如 GET、POST、PUT、DELETE、HTTP）。
其他信息：

pkt_type：数据包类型，通常指示数据包的类别。
ifindex：接口索引，表示数据包通过哪个网络接口接收的。
在代码中，各个字段都是通过 bpf_skb_load_bytes() 函数从网络数据包的缓冲区中读取的，确保可以获取到有效的数据用于进一步处理。

 */


// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockfilter.h"

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Taken from uapi/linux/tcp.h
struct __tcphdr
{
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;
	__u32 ip_proto = 0;
	__u32 tcp_hdr_len = 0;
	__u16 tlen;
	__u32 payload_offset = 0;
	__u32 payload_length = 0;
	__u8 hdr_len;

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP)
		return 0;

	if (ip_is_fragment(skb, nhoff))
		return 0;

	// ip4 header lengths are variable
	// access ihl as a u8 (linux/include/linux/skbuff.h)
	bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
	hdr_len &= 0x0f;
	hdr_len *= 4;

	/* verify hlen meets minimum size requirements */
	if (hdr_len < sizeof(struct iphdr))
	{
		return 0;
	}

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

	if (ip_proto != IPPROTO_TCP)
	{
		return 0;
	}

	tcp_hdr_len = nhoff + hdr_len;
	bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

	__u8 doff;
	bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
	doff &= 0xf0;																						// clean-up res1
	doff >>= 4;																							// move the upper 4 bits to low
	doff *= 4;																							// convert to bytes length

	payload_offset = ETH_HLEN + hdr_len + doff;
	payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

	char line_buffer[7];
	if (payload_length < 7 || payload_offset < 0)
	{
		return 0;
	}
	bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
	bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
	if (bpf_strncmp(line_buffer, 3, "GET") != 0 &&
		bpf_strncmp(line_buffer, 4, "POST") != 0 &&
		bpf_strncmp(line_buffer, 3, "PUT") != 0 &&
		bpf_strncmp(line_buffer, 6, "DELETE") != 0 &&
		bpf_strncmp(line_buffer, 4, "HTTP") != 0)
	{
		return 0;
	}

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ip_proto = ip_proto;
	bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->ports), 4);
	e->pkt_type = skb->pkt_type;
	e->ifindex = skb->ifindex;

	e->payload_length = payload_length;
	bpf_skb_load_bytes(skb, payload_offset, e->payload, MAX_BUF_SIZE);

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
	bpf_ringbuf_submit(e, 0);

	return skb->len;
}