#pragma once


#define TASK_COMM_LEN 16
#define aAF_INET 2
#define aAF_INET6 10


struct ipv4_key_t {
    __u32 pid;
    char name[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 lport;
    __u16 dport;
};

struct ipv6_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    __u32 pid;
    char name[TASK_COMM_LEN];
    __u16 lport;
    __u16 dport;
    __u64 __pad__;
};