#ifndef TCPSTATES_H
#define TCPSTATES_H

#define TASK_COMM_LEN 16
struct event {
    unsigned __int128 saddr;    //源IP地址
    unsigned __int128 daddr;    //目的IP地址
    __u64 skaddr;       //socket地址
    __u64 ts_us;        //时间戳
    __u64 delta_us;     //时间差
    __u32 pid;          //进程ID
    int oldstate;        //旧状态   
    int newstate;        //新状态
    __u16 family;        //协议族
    __u16 sport;         //源端口
    __u16 dport;         //目的端口

    char task[TASK_COMM_LEN];    //进程名
};




#endif