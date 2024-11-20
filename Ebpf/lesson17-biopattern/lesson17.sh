#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

#clang -O2 -g -target bpf -c (-D__TARGET_ARCH_X86_64) xxxx.c -o xxxx.o
clang -O2 -g -target bpf -c biopattern.bpf.c -o biopattern.o
bpftool gen skeleton biopattern.o > biopattern.skel.h
gcc -O2 -g -o biopattern biopattern.c -lbpf -lelf -lz