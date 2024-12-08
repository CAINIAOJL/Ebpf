bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c slabratetop.bpf.c -o slabratetop.o
echo "slabratetop.o generated successfully"
bpftool gen skeleton slabratetop.o > slabratetop.skel.h
echo "slabratetop.skel.h generated successfully"
gcc -O2 -g -o slabratetop slabratetop.c -lbpf -lelf -lz
echo "slabratetop generated successfully"