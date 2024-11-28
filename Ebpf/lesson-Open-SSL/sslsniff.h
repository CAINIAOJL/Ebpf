#pragma once

#define MAX_BUF_SIZE 8192
#define TASK_COMM_LEN 16

struct probe_SSL_data_t {
    __u64 timestamp_ns;          // 时间戳（纳秒）
    __u64 delta_ns;              // 函数执行时间
    __u32 pid;                   // 进程 ID
    __u32 tid;                   // 线程 ID
    __u32 uid;                   // 用户 ID
    __u32 len;                   // 读写数据的长度
    int buf_filled;              // 缓冲区是否已满
    int rw;                      // 读写类型
    char comm[TASK_COMM_LEN];    // 进程名
    __u8 buf[MAX_BUF_SIZE];      // 读写数据
    int is_handleshake;          // 是否为握手数据
};