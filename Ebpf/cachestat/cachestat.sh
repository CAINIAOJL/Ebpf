bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c cachestat.bpf.c -o cachestat.o
bpftool gen skeleton cachestat.o > cachestat.skel.h
gcc -O2 -g -o cachestat cachestat.c -lbpf -lelf -lz