
#!/bin/bash
clang -O2 -g -target bpf -c pidhide.bpf.c -o pidhide_my.o
bpftool gen skeleton pidhide_my.o > pidhide.skel.h
gcc -O2 -g -o pidhide_my pidhide.c -lbpf -lelf -lz