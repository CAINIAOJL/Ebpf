#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c xdp-tcpdump.bpf.c -o xdp-tcpdump.o
bpftool gen skeleton xdp-tcpdump.o > xdp_tcpdump.skel.h
gcc -O2 -g -o xdp-tcpdump xdp-tcpdump.c -lbpf -lelf -lz