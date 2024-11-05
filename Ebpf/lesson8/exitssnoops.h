/*#ifndef _EXITSSNOOPS_H_
#define _EXITSSNOOPS_H_

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

struct event {
    int pid;
    int ppid;
    char comm[TASK_COMM_LEN];
    unsigned long long duration_ns;
    unsigned exit_code;
};

#endif  _EXITSSNOOP_H_ */

#ifndef EXITSSNOOPS_H
#define EXITSSNOOPS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
};

#endif 