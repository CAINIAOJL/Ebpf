bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c slabratetop.bpf.c -o slabratetop.o
bpftool gen skeleton slabratetop.o > slabratetop.skel.h
gcc -O2 -g -o slabratetop slabrateto.c -lbpf -lelf -lz