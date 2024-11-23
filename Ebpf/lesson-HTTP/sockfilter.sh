#!/bin/bash
#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#clang -O2 -g -target bpf -c (-D__TARGET_ARCH_X86_64) xxxx.c -o xxxx.o
#bpftool gen skeleton xxxx.o > xxxx.skel.h
#gcc -O2 -g -o xxxx xxx.c -lbpf -lelf -lz


bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c sockfilter.bpf.c -o sockfilter.o
bpftool gen skeleton sockfilter.o > sockfilter.skel.h
gcc -O2 -g -o sockfilter sockfilter.c -lbpf -lelf -lz

#连接头文件，
#cd /usr/include
#sudo ln -s /usr/include/x86_64-linux-gnu/asm asm
#ls -l asm
#lrwxrwxrwx 1 root root XX Oct  X XX:XX asm -> /usr/include/x86_64-linux-gnu/asm
#cd /usr/include
#sudo rm asm
#ls -l | grep asm