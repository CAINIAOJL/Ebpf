#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
//内核态的bpf程序
#define SEC(NAME) __attribute__((section(NAME), used))
//ecc ecli 解释器，不用clang 命令
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void* cxt) {
    char msg[] = "hello, BPF world!";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char _license[] SEC("license") = "GPL";