// filename: main.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_bpf.skel.h"

int main() {
    struct trace_bpf *skel;
    int err;

    // 加载并打开 BPF 程序
    skel = trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序
    err = trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        trace_bpf__destroy(skel);
        return 1;
    }

    // 定期读取系统调用计数
    while (1) {
        u32 key = 0;
        u64 value;

        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.syscall_count), &key, &value) == 0) {
            printf("Syscall count: %llu\n", value);
        } else {
            fprintf(stderr, "Failed to read BPF map\n");
        }

        sleep(1);
    }

    trace_bpf__destroy(skel);
    return 0;
}

//bpftool gen skeleton trace_bpf.o > trace_bpf.skel.h
//gcc -o main main.c -lbpf -lelf -lz
//sudo ./main
