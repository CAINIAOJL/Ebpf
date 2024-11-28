clang -O2 -g -target bpf -c sslsniff.bpf.c -o sslsniff.o
bpftool gen skeleton sslsniff.o > sslsniff.skel.h
gcc -O2 -g -o sslsniff sslsniff.c -lbpf -lelf -lz