#!/bin/bash
#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#clang -O2 -g -target bpf -c (-D__TARGET_ARCH_X86_64) xxxx.c -o xxxx.o
#bpftool gen skeleton xxxx.o > xxxx.skel.h
#gcc -O2 -g -o xxxx xxx.c -lbpf -lelf -lz


bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c sockfilter.bpf.c -o sockfilter.o
bpftool gen skeleton sockfilter.o > sockfilter.skel.h
gcc -O2 -g -o sockfilter sockfilter.c -lbpf -lelf -lz