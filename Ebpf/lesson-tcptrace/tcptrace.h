#pragma once

#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT 2
#define TCP_EVENT_TYPE_CLOSE 3
#define TASK_COMM_LEN 16
//ipv4 event
struct tcp_ipv4_event_t {
    __u64 ts_ns;
    __u32 type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u8 ip;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 netns;
};

//ipv6 event
struct tcp_ipv6_event_t {
    __u64 ts_ns;
    __u32 type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    __u16 sport;
    __u16 dport;
    __u32 netns;
    __u8 ip;
};

struct ipv4_tuple_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 netns;
};

struct ipv6_tuple_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    __u16 sport;
    __u16 dport;
    __u32 netns;
};

struct pid_comm_t {
    __u64 pid;
    char comm[TASK_COMM_LEN];
};

