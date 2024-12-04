/*#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
//#include "bpf.h"

static const char* my_array = "/sys/fs/bpf/my_array";


int main(int argc,char** argv) {
    int key, value, fd, added, pinned;

    fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), 100, 0);
    if(fd < 0) {
        perror("bpf_create_map");
        return -1;
    }

    key = 1, value = 1234;
    added = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
    if(added < 0) {
        printf("Failed to add element to map: %d(%s)\n", added, strerror(errno));
        return -1;
    }
    pinned = bpf_skel_pin(fd, my_array);
    if(pinned < 0) {
        printf("Failed to pin map: %d(%s)\n", pinned, strerror(errno));
        return -1;
    }
    return 0;
}*/

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h> // 使用 libbpf 的用户态头文件

static const char* my_array = "/sys/fs/bpf/my_array"; // 改为标准 BPF 文件系统路径

int main(int argc, char** argv) {
    int key, value, fd, added, pinned;

    fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), 100, 0);
    if (fd < 0) {
        perror("bpf_create_map");
        return -1;
    }

    key = 1;
    value = 1234;
    added = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
    if (added < 0) {
        printf("Failed to add element to map: %d(%s)\n", added, strerror(errno));
        return -1;
    }

    pinned = bpf_skel_pin(fd, my_array);
    if (pinned < 0) {
        printf("Failed to pin map: %d(%s)\n", pinned, strerror(errno));
        return -1;
    }

    printf("Map created and pinned successfully.\n");
    return 0;
}
