#define __TARGET_ARCH_x86
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "funclate.h"
#include "bits.bpf.h"

const volatile pid_t target_tgid = 0;
const volatile int units = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

__u32 hist[MAX_SLOTS] = {};

static void entry(void) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32; //问题
    u32 pid = pid_tgid;  //问题
    u64 nsec;

    if(target_tgid && target_tgid != tgid) {
        return;
    }
    nsec = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &nsec, BPF_ANY);
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe) {
    entry();
    return 0;
}

static void exit(void) {
    u64 *ts;
    u64 nsec = bpf_ktime_get_ns();
    u64 id =bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 slot, delta;

    ts = bpf_map_lookup_elem(&start, &pid);
    if(ts == 0) {
        return;
    }

    delta = nsec - *ts;

    switch(units) {
        case USEC:
            delta /= 1000;
            break;

        case MSEC:
            delta /= 1000000;
            break;
    }

    slot = log2l(delta);
    if(slot >= MAX_SLOTS) {
        slot = MAX_SLOTS - 1;
    }

    __sync_fetch_and_add(&hist[slot], 1);
}

SEC("kprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe) {
    exit();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";



// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
/*#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

const volatile pid_t targ_tgid = 0;
const volatile int units = 0;

/* key: pid.  value: start time */
/*struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");

__u32 hist[MAX_SLOTS] = {};

static void entry(void)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;
	u64 nsec;

	if (targ_tgid && targ_tgid != tgid)
		return;
	nsec = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{
	entry();
	return 0;
}

static void exit(void)
{
	u64 *start;
	u64 nsec = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	u64 slot, delta;

	start = bpf_map_lookup_elem(&starts, &pid);
	if (!start)
		return;

	delta = nsec - *start;

	switch (units) {
	case USEC:
		delta /= 1000;
		break;
	case MSEC:
		delta /= 1000000;
		break;
	}

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist[slot], 1);
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
	exit();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

*/