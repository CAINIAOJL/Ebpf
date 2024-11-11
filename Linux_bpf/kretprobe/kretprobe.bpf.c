#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
//#include "vmlinux.h"


// 针对不同架构定义 PT_REGS_RC 宏
#ifdef __x86_64__
    #define PT_REGS_RCT(ctx) ((ctx)->orig_rax)
#elif defined(__aarch64__)
    #define PT_REGS_RCT(ctx) ((ctx)->regs[0])
#else
    #error "Unsupported architecture"
#endif

SEC("kretprobe/__x64_sys_execve")
int ret_sys_execve(struct pt_regs* ctx) {
    int return_value;
    char name[16];

    bpf_get_current_comm(&name, sizeof name);
    return_value = PT_REGS_RCT(ctx);

    //bpf_trace_printk("process %s returned %d\n", name, return_value);
    //bpf_printk()
    bpf_trace_printk(name, sizeof name);
    bpf_trace_printk("%d", return_value, sizeof return_value);
    return 0;
}

char license[] SEC("license") = "GPL";