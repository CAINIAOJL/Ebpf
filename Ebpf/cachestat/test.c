#include <stdio.h>

void get_meminfo(long *cached, long *buffer) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if(fp == NULL) {
        perror("fopen");
        *cached = *buffer = 0;
        return;
    }
    char line[256];
    while(fgets(line, sizeof(line), fp)) {
        if(strncmp(line, "Cached:", 7) == 0) {
            sscanf(line, "Cached: %ld", cached);
        } else if(strncmp(line, "Buffers:", 8) == 0) { 
            sscanf(line, "Buffers: %ld", buffer);
        }
    }
    fclose(fp);
}

int main() {
    long cached, buffer;
    get_meminfo(&cached, &buffer);
    printf("Cached: %ld\n", cached);
    printf("Buffers: %ld\n", buffer);
    return 0;
}