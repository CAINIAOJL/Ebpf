#ifndef _EXECSNOOP_H_
#define _EXECSNOOP_H_

#define TASK_COMM_LEN 16

struct event {
    int pid;                 //进程标识符（PID，Process ID）是系统用来唯一标识每个进程的数字。
    int ppid;                //父进程标识符（PPID，Parent Process ID）是指当前进程的父进程的进程标识符。
    int uid;                 //用户标识符（UID，User ID）是指当前进程的用户ID。
    int retval;
    bool is_exit;
    char comm[TASK_COMM_LEN];
};

#endif