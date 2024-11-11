#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>

#define BPF_LOG_BUF_SIZE 65536

void bump_memlock_rlimit() {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    /* Set the soft and hard limits for RESOURCE to *RLIMITS.
   Only the super-user can increase hard limits.
   Return 0 if successful, -1 if not (and sets errno).  */
    setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char** argv) {
    struct bpf_object* obj;
    int prog_fd;

    //提升资源限制
    bump_memlock_rlimit();

    //挂载bpf程序
    obj = bpf_object__open_file("kprobe.bpf.o", NULL);
    if(libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed: %s\n", strerror(errno));
        return 1;
    }

    //加载bpf对象到内核
    if(bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed: %s\n", strerror(errno));
        return 1;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "do_sys_execve");
    if(!prog) {
        fprintf(stderr, "ERROR: finding BPF program failed: %s\n", strerror(errno));
        return 1;
    }

    prog_fd = bpf_program__fd(prog);

    //将bpf程序加到kprobe事件上
    //问题？
    if(bpf_program__attach_kprobe(prog, false, "sys_execve")) { //  __x64_sys_execve
        fprintf(stderr, "ERROR: attaching BPF program failed: %s\n", strerror(errno));
        return 1;
    }

    printf("BPF program loaded and attached. Tracing sys_execve... Press Ctrl+C to exit.\n");

    system("cat /sys/kernel/debug/tracing/trace_pipe");

    bpf_object__close(obj);
    return 0;
}