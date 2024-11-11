# !/bin/bash
#注意，bpf程序使用ecc开源工具进行编译加载

#bpf程序，内核态
cd
./ecc /home/jianglei/Ebpf/Linux_bpf/kprobe/kprobe.bpf.c
sudo ./ecli /home/jianglei/Ebpf/Linux_bpf/kprobe/package.json #已经完成了用户态的功能，可以直接运行，无需再写loader.c

#用户态
gcc -o loader loader.c -lelf -lbpf
./loader