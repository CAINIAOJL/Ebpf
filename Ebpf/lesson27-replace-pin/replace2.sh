#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c replace2.bpf.c -o replace2.o
bpftool gen skeleton replace2.o > replace2.skel.h
gcc -O2 -g -o replace2 replace2.c -lbpf -lelf -lz