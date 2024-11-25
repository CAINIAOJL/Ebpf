#ifndef COMMON_UN_H
#define COMMON_UN_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>

static volatile bool exiting = false;

void sig_handler(int sig) {
    exiting = true;
}

static bool handle_signals() {
    __sighandler_t sighandler = signal(SIGINT, sig_handler);
    if (sighandler == SIG_ERR) {
        printf("Failed to set signal handler: %s\n", strerror(errno));
        return false;
    }

    sighandler = signal(SIGTERM, sig_handler);
    if (sighandler == SIG_ERR) {
        printf("Failed to set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    vfprintf(stderr, format, args);
}

//总的来说，这个函数的作用是尝试将进程的内存锁定限制提升到无限制，如果操作失败则给出相应的错误提示。
static bool bump_memlock_rlimit() {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static bool set_up() {
    libbpf_set_print(libbpf_print_fn);

    if(!handle_signals()) {
        return false;
    }

    if(!bump_memlock_rlimit()) {
        return false;
    }
    return true;
}

#ifdef BAD_BPF_USE_TRACE_PIPE
static void read_trace_pipe(void) {
    int trace_fd;
    trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if(trace_fd == -1) {
        printf("Failed to open trace pipe: %s\n", strerror(errno));
        return;
    }

    while (!exiting)
    {
        static char buf[1024];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf));
        if(sz > 0) {
            buf[sz] = '\x00';
            puts(buf);
        }
    }
}
#endif

#endif