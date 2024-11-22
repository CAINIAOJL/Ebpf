#ifndef _SOCKFILTER_H_
#define _SOCKFILTER_H_

#define MAX_BUF_SIZE 64

/*
struct so_event *e;：这是一个指向so_event结构体的指针，用于存储捕获到的事件信息。该结构体的具体定义在程序的其他部分。
*/
struct so_event {
    __be32 src_addr; //这个字段用于存储源地址，类型为 __be32，表示一个32位的网络字节序地址（通常用于IPv4地址）。
    __be32 dst_addr; //这个字段用于存储目标地址，同样是一个32位的网络字节序地址。
    union {
        __be32 ports;  //这是一个32位的网络字节序字段，可以用来存储单个端口值。
        __be32 port16[2]; //这是一个长度为2的数组，用于分别存储两个16位的端口值（例如，源端口和目标端口），提供了更灵活的端口表示方式。
    };

    __u32 ip_proto; //这个字段用于存储IP协议类型，例如TCP或UDP，类型为32位无符号整数
    __u32 pkt_type; //这个字段表示数据包的类型，通常用于区分不同种类的数据包（如ICMP、TCP等）。
    __u32 ifindex; //这个字段用于存储网络接口的索引，以便标识数据包是通过哪个网络接口传输的
    __u32 payload_length; //这个字段表示有效负载的长度，用于指示数据包中实际数据的大小。
    __u8 payload[MAX_BUF_SIZE]; //这是一个最大长度为64（由 MAX_BUF_SIZE 定义）的无符号8位整数数组，用于存储数据包的有效负载部分
};

#endif