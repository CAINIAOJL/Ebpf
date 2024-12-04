#include "tcpconnlat.h"
/*
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "tcpconnlat.skel.h"

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

static volatile sig_atomic_t exiting = 0;

static struct env {
    __u64 min_us;
    pid_t pid;
    bool timestamp;
    bool lport;
    bool verbose;
} env;

const char* argp_program_version = "tcpconnlat 0.1";
const char* argp_program_bug_address = 
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_program_doc[] = 
    "\n Trace TCP connects and show connection latency.\n"
    "\n"
    "USAGE: tcpconnlat [--help] [-t] [-p PID] [-L]\n"
    "\n"
    "EXAMPLES:\n"
    "   tcpconnlat           #summarize on-cpu time as a histogram\n"
    "   tcpconnlat 1         # trace connection latency slower than 1 ms\n"
    "   tcpconnlat 0.1       # trace connection latency slower than 100 us \n"
    "\n"
    "   tcpconnlat -t        # 1s summaries, milliseconds, and timestamps\n"
    "   tcpconnlat -p 185    # trace PID 185 only\n"
    "   tcpconnlat -L        # include LPORT while printing output\n";

static const struct argp_option opts[] = {
    {"timestamp", 't', NULL, 0, "Include timestamp on output"},
    {"pid", 'p', "PID", 0, "Trace this PID only"},
    {"lport", 'L', NULL, 0, "Include LPORT on output"},
    {"Verbose", 'v', NULL, 0, "Verbose debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "show the full help"},
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    static int pos_args;

    switch (key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case 'v':
            env.verbose = true;
            break;
        case 'p':
            errno = 0;
            env.pid = strtol(arg, NULL, 10);
            if(errno) {
                fprintf(stderr, "invalid PID: %s\n", arg);
                argp_usage(state);
            }
            break;
        case 't':
            env.timestamp = true;
            break;
        case 'L':
            env.lport = true;
            break;
        case ARGP_KEY_ARG:
            if(pos_args++) {
                fprintf(stderr, "unrecognized argument: %s\n", arg);
                argp_usage(state);
            }
            errno = 0;
            env.min_us = strtod(arg, NULL) * 1000;
            if(errno || env.min_us <= 0) {
                fprintf(stderr, "invalid delay (in us): %s\n", arg);
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if(level == LIBBPF_DEBUG && !env.verbose) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

static void sig_int(int signo) {
    exiting = 1;
}

// data ->event->tcp_connect_v4_event
void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    const struct event* e = data;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    union 
    {
        struct in_addr addr4;
        struct in6_addr addr6;
    }s, d;
    static __u64 start_ts;

    if(env.timestamp) {
        if(start_ts == 0) {
            start_ts = e->ts_us;
        }
        printf("%-9.3f ", (e->ts_us - start_ts) / 1000000.0);
    }
    if(e->af == AF_INET) {
        s.x4.s_addr = e->saddr_v4;
        d.x4.s_addr = e->daddr_v4;
    } else if(e->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "broken event: event->af = %d", e->af);
        return;
    }

    if(env.lport) {
        printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", e->tgid,
               e->comm, e->af == AF_INET ? 4 : 6, 
               inet_ntop(e->af, &s, src, sizeof(src)), e->lport,
               inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
               e->delta_us / 1000.0);
    } else {
        printf("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f\n", e->tgid, e->comm,
               e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &s, src, sizeof(src)),
               inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
               e->delta_us / 1000.0);
    }
}

void handle_lost_event(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on cpu #%d\n", lost_cnt, cpu);
}


static bool fentry_try_attach(int id) {
    int prog_fd, attach_fd;
    char error[4096];
    struct bpf_insn insns[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };

    LIBBPF_OPTS(bpf_prog_load_opts, opts, .expected_attach_type = BPF_TRACE_FENTRY, .attach_btf_id = id, .log_buf = error, .log_size = sizeof(error),);

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns, sizeof(insns) / sizeof(struct bpf_insn), &opts);
    //prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns, sizeof(insns) / sizeof(struct bpf_insn), &opts);

    if(prog_fd < 0) {
        return false;
    }

    attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
    if(attach_fd >= 0) {
        close(attach_fd);
    }

    close(prog_fd);
    return attach_fd >= 0;
}

static bool fentry_can_attach(const char* name, const char* mod) {
    struct btf* btf, *vmlinux_btf, *module_btf = NULL;
    int err, id;

    vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(vmlinux_btf);
    if(err) {
        return false;
    }

    btf = vmlinux_btf;

    if(mod) {
        module_btf = btf__load_module_btf(mod, vmlinux_btf);
        err = libbpf_get_error(module_btf);
        if(!err) {
            btf = module_btf;
        }
    }

    id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

    btf__free(vmlinux_btf);
    btf__free(module_btf);

    return id > 0 && fentry_try_attach(id);
}

int main(int argc, char** argv) {
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };

    struct perf_buffer* pb = NULL;
    struct tcpconnlat_bpf* skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);

    if(err) {
        return err;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = tcpconnlat_bpf__open();
    if(!skel) {
        fprintf(stderr, "failed to open BPF skelect\n");
        return 1;
    }

    skel->rodata->targ_min_us = env.min_us;
    skel->rodata->targ_pid = env.pid;

    if(fentry_can_attach("tcp_v4_connect", NULL)) {
        bpf_program__set_attach_target(skel->progs.fentry_tcp_v4_connect, 0, "tcp_v4_connect");
        bpf_program__set_attach_target(skel->progs.fentry_tcp_v6_connect, 0, "tcp_v6_connect");
        bpf_program__set_attach_target(skel->progs.fentry_tcp_rcv_state_process, 0, "tcp_rcv_state_process");
        
        bpf_program__set_autoload(skel->progs.tcp_v4_connect, false);
        bpf_program__set_autoload(skel->progs.tcp_v6_connect, false);
        bpf_program__set_autoload(skel->progs.tcp_rcv_state_process, false);
    } else {
        bpf_program__set_autoload(skel->progs.fentry_tcp_v4_connect, false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_v6_connect, false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_rcv_state_process,false);
    }

    err = tcpconnlat_bpf__load(skel);
    if(err) {
        fprintf(stderr, "failed to load BPF skelect: %d\n", err);
        goto cleanup;
    }

    err = tcpconnlat_bpf__attach(skel);
    if(err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES, handle_event, handle_lost_event, NULL, NULL);

    if(!pb) {
        fprintf(stderr, "failed to create perf buffer\n");
        goto cleanup;
    }

    if(env.timestamp) {
        printf("%-9s ",  ("TIME(s)"));
    }
    if(env.lport) {
        printf("%-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n", "PID", "COMM",
               "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)");
    } else {
        printf("%-6s %-12s %-2s %-16s %-16s %-5s %s\n", "PID", "COMM",
               "IP", "SADDR", "DADDR", "DPORT", "LAT(ms)");
    }

    if(signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    while(!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if(err < 0 && err != -EINTR) {
            fprintf(stderr, "error polling perf buffer: %d\n", err);
            goto cleanup;
        }
        err = 0;
    }

cleanup:
    perf_buffer__free(pb);
    tcpconnlat_bpf__destroy(skel);

    return err != 0;
}
*/


// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on tcpconnlat(8) from BCC by Brendan Gregg.
// 11-Jul-2020   Wenbo Zhang   Created this.
#include "tcpconnlat.h"
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "tcpconnlat.skel.h"

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

static volatile sig_atomic_t exiting = 0;

static struct env {
    __u64 min_us;
    pid_t pid;
    bool timestamp;
    bool lport;
    bool verbose;
} env;

const char* argp_program_version = "tcpconnlat 0.1";
const char* argp_program_bug_address =
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "\nTrace TCP connects and show connection latency.\n"
    "\n"
    "USAGE: tcpconnlat [--help] [-t] [-p PID] [-L]\n"
    "\n"
    "EXAMPLES:\n"
    "    tcpconnlat              # summarize on-CPU time as a histogram\n"
    "    tcpconnlat 1            # trace connection latency slower than 1 ms\n"
    "    tcpconnlat 0.1          # trace connection latency slower than 100 "
    "us\n"
    "    tcpconnlat -t           # 1s summaries, milliseconds, and timestamps\n"
    "    tcpconnlat -p 185       # trace PID 185 only\n"
    "    tcpconnlat -L           # include LPORT while printing outputs\n";

static const struct argp_option opts[] = {
    {"timestamp", 't', NULL, 0, "Include timestamp on output"},
    {"pid", 'p', "PID", 0, "Trace this PID only"},
    {"lport", 'L', NULL, 0, "Include LPORT on output"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    static int pos_args;

    switch (key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case 'v':
            env.verbose = true;
            break;
        case 'p':
            errno = 0;
            env.pid = strtol(arg, NULL, 10);
            if (errno) {
                fprintf(stderr, "invalid PID: %s\n", arg);
                argp_usage(state);
            }
            break;
        case 't':
            env.timestamp = true;
            break;
        case 'L':
            env.lport = true;
            break;
        case ARGP_KEY_ARG:
            if (pos_args++) {
                fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
                argp_usage(state);
            }
            errno = 0;
            env.min_us = strtod(arg, NULL) * 1000;
            if (errno || env.min_us <= 0) {
                fprintf(stderr, "Invalid delay (in us): %s\n", arg);
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_int(int signo) {
    exiting = 1;
}

void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    const struct event* e = data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    union {
        struct in_addr x4;
        struct in6_addr x6;
    } s, d;
    static __u64 start_ts;

    if (env.timestamp) {
        if (start_ts == 0)
            start_ts = e->ts_us;
        printf("%-9.3f ", (e->ts_us - start_ts) / 1000000.0);
    }
    if (e->af == AF_INET) {
        s.x4.s_addr = e->saddr_v4;
        d.x4.s_addr = e->daddr_v4;
    } else if (e->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "broken event: event->af=%d", e->af);
        return;
    }

    if (env.lport) {
        printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", e->tgid,
               e->comm, e->af == AF_INET ? 4 : 6,
               inet_ntop(e->af, &s, src, sizeof(src)), e->lport,
               inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
               e->delta_us / 1000.0);
    } else {
        printf("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f\n", e->tgid, e->comm,
               e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &s, src, sizeof(src)),
               inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
               e->delta_us / 1000.0);
    }
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}
static bool fentry_try_attach(int id) {
    int prog_fd, attach_fd;
    char error[4096];
    struct bpf_insn insns[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
                .expected_attach_type = BPF_TRACE_FENTRY, .attach_btf_id = id,
                .log_buf = error, .log_size = sizeof(error), );

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
                            sizeof(insns) / sizeof(struct bpf_insn), &opts);
    if (prog_fd < 0)
        return false;

    attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
    if (attach_fd >= 0)
        close(attach_fd);

    close(prog_fd);
    return attach_fd >= 0;
}
static bool fentry_can_attach(const char* name, const char* mod) {
    struct btf *btf, *vmlinux_btf, *module_btf = NULL;
    int err, id;

    vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(vmlinux_btf);
    if (err)
        return false;

    btf = vmlinux_btf;

    if (mod) {
        module_btf = btf__load_module_btf(mod, vmlinux_btf);
        err = libbpf_get_error(module_btf);
        if (!err)
            btf = module_btf;
    }

    id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

    btf__free(module_btf);
    btf__free(vmlinux_btf);
    return id > 0 && fentry_try_attach(id);
}

int main(int argc, char** argv) {
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct perf_buffer* pb = NULL;
    struct tcpconnlat* skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = tcpconnlat__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skelect\n");
        return 1;
    }

    /* initialize global data (filtering options) */
    skel->rodata->targ_min_us = env.min_us;
    skel->rodata->targ_tgid = env.pid;

    if (fentry_can_attach("tcp_v4_connect", NULL)) {
        //bpf_program__set_attach_target(skel->progs.fentry_tcp_v4_connect, 0,
        //                               "tcp_v4_connect");
        //bpf_program__set_attach_target(skel->progs.fentry_tcp_v6_connect, 0,
        //                               "tcp_v6_connect");
        //bpf_program__set_attach_target(skel->progs.fentry_tcp_rcv_state_process,
        //                               0, "tcp_rcv_state_process");
        //bpf_program__set_autoload(skel->progs.tcp_v4_connect, false);
        //bpf_program__set_autoload(skel->progs.tcp_v6_connect, false);
        //bpf_program__set_autoload(skel->progs.tcp_rcv_state_process, false);
    } else {
        bpf_program__set_autoload(skel->progs.fentry_tcp_v4_connect, false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_v6_connect, false);
        bpf_program__set_autoload(skel->progs.fentry_tcp_rcv_state_process,
                                  false);
    }

    err = tcpconnlat__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skelect: %d\n", err);
        goto cleanup;
    }

    err = tcpconnlat__attach(skel);
    if (err) {
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "failed to open perf buffer: %d\n", errno);
        goto cleanup;
    }

    /* print header */
    if (env.timestamp)
        printf("%-9s ", ("TIME(s)"));
    if (env.lport) {
        printf("%-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n", "PID", "COMM",
               "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)");
    } else {
        printf("%-6s %-12s %-2s %-16s %-16s %-5s %s\n", "PID", "COMM", "IP",
               "SADDR", "DADDR", "DPORT", "LAT(ms)");
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    /* main: poll */
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        /* reset err to return 0 if exiting */
        err = 0;
    }

cleanup:
    perf_buffer__free(pb);
    tcpconnlat__destroy(skel);

    return err != 0;
}