#include "vmlinux.h"
#include <stdio.h>

int main(void) {
    printf("sizeof(struct iphdr) : %ld\n", sizeof(struct iphdr));
    printf("sizeof(struct etnhdr) : %ld\n", sizeof(struct ethhdr));
    printf("sizeof(struct tcphdr) : %ld\n", sizeof(struct tcphdr));
    return 0;
}