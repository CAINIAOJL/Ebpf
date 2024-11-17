#ifndef TCPCONNLAT_H
#define TCPCONNLAT_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 16

struct event {
    //而这选其中一个时，利用unions可以节省空间
    union 
    {   
        __u32 saddr_v4;
        __u8 saddr_v6[16]; // 8 * 2 = 16 bytes
    };

    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16]; // 8 * 2 = 16 bytes
    };
    
    char comm[TASK_COMM_LEN];
    __u64 delta_us;  // 纳秒级时间差
    __u64 ts_us;     // 纳秒级时间戳
    __u32 tgid;      // 线程组ID
    int af;          // 地址族
    __u16 lport;     // 发送端端口
    __u16 dport;     // 接收端端口
};

/*
// #include <inttypes.h>
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 16

struct event {
    union {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
    char comm[TASK_COMM_LEN];
    __u64 delta_us;
    __u64 ts_us;
    __u32 tgid;
    int af;
    __u16 lport;
    __u16 dport;
};
*/

#endif