/*#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include "goroutine.h"

#include <vmlinux.h>

#define GOID_OFFSET 0x98;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/./go-server-http/main:runtime.casgstatus")
int uprobe_runtime_casgstatus(struct pt_regs* ctx) {
    int newval = ctx->cx;
    void* gp = ctx->ax;
    struct goroutine_execute_data* data;
    u64 goid;
    if (bpf_probe_read_user(&goid, sizeof(goid), gp + GOID_OFFSET) == 0) {
        //预留空间
        data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);                     
        if(data) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            data->pid = pid_tgid;
            data->tgid = pid_tgid >> 32;
            data->goid = goid;
            data->status = newval;
            bpf_ringbuf_submit(data, 0);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";*/

#include <vmlinux.h>
#include "goroutine.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define GOID_OFFSET 0x98

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/./go-server-http/main:runtime.casgstatus")
int uprobe_runtime_casgstatus(struct pt_regs *ctx) {
  int newval = ctx->cx;
  void *gp = (void*)ctx->ax;
  struct goroutine_execute_data *data;
  u64 goid;
  if (bpf_probe_read_user(&goid, sizeof(goid), gp + GOID_OFFSET) == 0) {
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (data) {
      u64 pid_tgid = bpf_get_current_pid_tgid();
      data->pid = pid_tgid;
      data->tgid = pid_tgid >> 32;
      data->goid = goid;
      data->status = newval;
      bpf_ringbuf_submit(data, 0);
    }
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";