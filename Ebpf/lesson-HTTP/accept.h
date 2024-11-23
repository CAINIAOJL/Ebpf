#ifndef _ACCEPT_H_
#define _ACCEPT_H_

#define MAX_MSG_SIZE 256

struct socket_data_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    //unsigned long long timestamp_ns;
    //unsigned int pid;
    int fd;
    bool is_connection;
    __u32 msg_size;
    //unsigned int msg_size;
    __u64 pos;
    //unsigned long long pos;
    char msg[MAX_MSG_SIZE];
};
#endif