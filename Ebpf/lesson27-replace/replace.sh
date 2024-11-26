bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c replace.bpf.c -o replace.o
bpftool gen skeleton replace.o > replace.skel.h
gcc -O2 -g -o replace replace.c -lbpf -lelf -lz