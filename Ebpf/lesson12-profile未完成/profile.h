#ifndef _PROFILE_H_
#define _PROFILE_H_

/*#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event {
    __u32 pid;                  // process id
    __u32 cpu_id;                // cpu id
    char comm[TASK_COMM_LEN];     // process name
    __s32 kstack_sz;             // kernel stack size
    __s32 ustack_sz;             // user stack size
    stack_trace_t kstack;        // kernel stack trace
    stack_trace_t ustack;        // user stack trace
};*/

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH         128
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event {
	__u32 pid;
	__u32 cpu_id;
	char comm[TASK_COMM_LEN];
	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
};





#endif


