clang -O2 -g -target bpf -c funclate.bpf.c -o funclate.o
bpftool gen skeleton funclate.o > funclate.skel.h
gcc -O2 -g -o funclate funclate.c -lbpf -lelf -lz