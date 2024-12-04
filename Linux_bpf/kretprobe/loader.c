#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <stdio.h>
#include <errno.h>


void bump_memlock_rlimit() {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char** argv) {
    struct bpf_program* skel;
    int prog_fd;

    //提升内存限制
    bump_memlock_rlimit();

    //加载bpf程序
    skel = bpf_program__open_file("kretprobe.bpf.o", NULL);

    if(libbpf_get_error(skel)) {
        fprintf(stderr, "ERROR: opening BPF skelect file failed: %s\n", strerror(errno));
        return 1;
    }

     // 加载 BPF 对象到内核
    if (bpf_skelect__load(skel)) {
        fprintf(stderr, "Error loading BPF program\n");
        bpf_skelect__close(skel);
        return 1;
    }

    // 查找并获取 BPF 程序的文件描述符
    struct bpf_program *prog = bpf_skelect__find_program_by_name(skel, "ret_sys_execve");
    if (!prog) {
        fprintf(stderr, "Cannot find program 'ret_sys_execve'\n");
        bpf_skelect__close(skel);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    // 将 BPF 程序附加到 kretprobe 事件
    //问题？
    if (bpf_program__attach_kprobe(prog, true, "sys_execve")) { //__x64_sys_execve
        fprintf(stderr, "Error attaching BPF program to kretprobe\n");
        bpf_skelect__close(skel);
        return 1;
    }

    printf("BPF program loaded and attached. Tracing execve return values... Press Ctrl+C to exit.\n");

    // 读取 trace_pipe 中的输出
    system("cat /sys/kernel/debug/tracing/trace_pipe");

    // 清理
    bpf_skelect__close(skel);
    return 0;


}