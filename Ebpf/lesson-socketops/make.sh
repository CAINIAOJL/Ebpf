
clang -O2 -g -target bpf -c bpf_redirect.bpf.c -o bpf_redirect.bpf.o
clang -O2 -g -target bpf -c bpf_contrack.bpf.c -o bpf_contrack.bpf.o