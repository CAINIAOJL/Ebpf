sudo insmod hello.ko
dmesg | tail

#[ 1234.5678] Hello, world!
#[ 1234.5679] bpf_kfunc_example: 模块加载成功