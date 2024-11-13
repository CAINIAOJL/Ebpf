#ifndef _BOOTSTRAP_H_
#define _BOOTSTRAP_H_

#define MAX_FILENAME_LEN 128
#define MAX_COMM_LEN 16
struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    bool exit_event;
};

#endif /* _BOOTSTRAP_H_ */