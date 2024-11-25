
#!/bin/bash
clang -O2 -g -target bpf -c pidhide.bpf.c -o pidhide.o
bpftool gen skeleton pidhide.o > pidhide.skel.h
gcc -O2 -g -o pidhide pidhide.c -lbpf -lelf -lz