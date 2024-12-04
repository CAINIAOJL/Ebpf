/*#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>

int main() {
    struct bpf_skelect *skel;
    int map_fd;
    int key = 0;
    u64 count;

    // 加载和验证 BPF 程序
    skel = bpf_skelect__open_file("trace.o", NULL);
    if (libbpf_get_error(skel)) {
        fprintf(stderr, "Failed to open BPF skelect\n");
        return 1;
    }
    
    if (bpf_skelect__load(skel)) {
        fprintf(stderr, "Failed to load BPF skelect\n");
        return 1;
    }

    // 获取 Map 的文件描述符
    map_fd = bpf_skelect__find_map_fd_by_name(skel, "syscall_count_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map\n");
        return 1;
    }

    printf("Monitoring system calls...\n");

    // 循环读取计数器值
    for (int i = 0; i < 10; i++) {
        sleep(1);
        bpf_map_lookup_elem(map_fd, &key, &count);
        printf("System call count: %llu\n", count);
    }

    bpf_skelect__close(skel);
    return 0;
}

//bpftool gen skeleton trace.o > trace.skel.h

//gcc -O2 -g -o user user.c -lbpf -lelf -lz
*/

#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "trace.skel.h"  // 引入生成的骨架头文件

int main() {
    struct trace *skel;
    int key = 0;
    __u64 count;

    // 打开并加载 BPF 骨架
    skel = trace__open_and_load();
    //skel = trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序
    if (trace__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        trace__destroy(skel);
        return 1;
    }

    printf("Monitoring system calls...\n");

    // 循环读取计数器值
    for (int i = 0; i < 10; i++) {
        sleep(1);
        bpf_map_lookup_elem(bpf_map__fd(skel->maps.syscall_count_map), &key, &count);
        printf("System call count: %llu\n", count);
    }

    // 清理骨架
    trace__destroy(skel);
    return 0;
}
