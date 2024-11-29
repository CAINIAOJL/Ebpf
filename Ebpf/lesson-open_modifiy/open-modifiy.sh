cd
./ecc /home/jianglei/Ebpf/Ebpf/lesson-open_modifiy/open-modifiy.bpf.c /home/jianglei/Ebpf/Ebpf/lesson-open_modifiy/open-modifiy.h
sudo ./ecli /home/jianglei/Ebpf/Ebpf/lesson-open_modifiy/package.json --rewrite --target_pid=$(pidof vicvim)

#Pidof 是一个命令行工具，用于查找正在运行程序的进程 ID（PID）。当你需要确定一个或多个特定程序的 PID 时，这个命令非常有用。例如，你可能需要结束一个无响应的进程或者监控特定程序的运行状态。
