#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c tcptrace.bpf.c -o tcptrace.o
bpftool gen skeleton tcptrace.o > tcptrace.skel.h
gcc -O2 -g -o tcptrace tcptrace.c -lbpf -lelf -lz