#ifndef _PIDHIDE_H_
#define _PIDHIDE_H_

#define TASK_COMM_LEN 16
#define MAX_PID_LEN 16

#define PROG_00 0
#define PROG_01 1
#define PROG_02 2

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

#endif