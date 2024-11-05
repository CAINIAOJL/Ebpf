#ifndef __RUNQLAT_H__
#define __RUNQLAT_H__

#define TASK_COMM_LEN 16
#define MAX_SLOTS 26

struct hist
{
    __u32 slots[MAX_SLOTS];
    char comm[TASK_COMM_LEN];
};



#endif /* __RUNQLAT_H__ */