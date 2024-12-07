#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c tcptop.bpf.c -o tcptop.o
echo "tcptop.o generated"
bpftool gen skeleton tcptop.o > tcptop.skel.h
echo "tcptop skeleton generated"
gcc -O2 -g -o tcptop tcptop.c -lbpf -lelf -lz
echo "tcptop executable generated"
