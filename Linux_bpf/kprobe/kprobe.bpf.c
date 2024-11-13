#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <asm/types.h>
//#include "vmlinux.h"
#define SEC(NAME) __attribute__((section(NAME), used))
/*
    __x64_sys_execve
    __ia32_sys_execve
    __x64_sys_execveat
    __ia32_sys_execveat
    __ia32_compat_sys_execve
    __x64_compat_sys_execve
    __ia32_compat_sys_execveat
    __x64_compat_sys_execveat
*/
SEC("kprobe/__x64_sys_execve") //跟踪sys_execve
int do_sys_execve(struct pt_regs *ctx) {
    char name[16];
    bpf_get_current_comm(&name, sizeof name);
    bpf_trace_printk(name, sizeof(name));
    return 0;
}

char _license[] SEC("license") = "GPL";
