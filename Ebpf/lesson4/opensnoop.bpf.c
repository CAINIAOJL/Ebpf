/*当进程打开一个文件时，它会向内核发出 sys_openat 系统调用，并传递相关参数（例如文件路径、打开模式等）。
内核会处理这个请求，并返回一个文件描述符（file descriptor），这个描述符将在后续的文件操作中用作引用。
通过捕获 sys_openat 系统调用，我们可以了解进程在什么时候以及如何打开文件。*/

/*#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

//volatitle 防止编译器优化，使得数据可以被BPF程序访问
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscalls__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if(pid_target && pid_target != pid) {
        return false;
        bpf_printk("process ID: %d enter sys openat\n", pid);
        return 0;
    }
}

char LICENSE[] SEC("license") = "GPL";*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @description "Process ID to trace"
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;
    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";