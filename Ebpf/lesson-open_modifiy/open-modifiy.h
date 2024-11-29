#pragma once

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t) -1)

struct event {
    pid_t pid;
    uid_t uid;
    int ret;
    int flags;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
};

