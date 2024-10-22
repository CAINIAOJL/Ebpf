cd
./ecc Ebpf/Ebpf/lesson2/k_probe_unlink.c
sudo ./ecli run Ebpf/Ebpf/lesson2/package.json
touch test1
rm test1
touch test2
rm test2

#在另一个窗口下输入以下命令
#sudo cat /sys/kernel/debug/tracing/trace_pipe
