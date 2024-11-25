#sudo ls /sys/kernel/debug/tracing/events/
#sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format

#bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c sudoadd.bpf.c -o sudoadd.o
bpftool gen skeleton sudoadd.o > sudoadd.skel.h
gcc -O2 -g -o sudoadd sudoadd.c -lbpf -lelf -lz
